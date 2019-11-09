/*
Written by Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>

The MIT License (MIT)

Copyright (c) 2019 Ole Fredrik Skudvik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	certutil "k8s.io/client-go/util/cert"
	csr "k8s.io/client-go/util/certificate/csr"
)

// CertificateData contains a private key
// and a certificate.
type CertificateData struct {
	Name              string    `json:"name"`
	PrivateKey        string    `json:"key"`
	PrivateKeyBase64  string    `json:"key.b64"`
	Certificate       string    `json:"cert"`
	CertificateBase64 string    `json:"cert.b64"`
	CA                string    `json:"ca.crt"`
	CABase64          string    `json:"ca.crt.b64"`
	Groups            []string  `json:"groups"`
	IssueDate         time.Time `json:issuedDate`
	ExpireDate        time.Time `json:expireDate`
}

// Manager object.
type Manager struct {
	kubeClient *kubernetes.Clientset
	namespace  string
	caCertData string
}

// newPrivateKey generates a new RSA private key.
// @param bitSize Bit size of the key to generate.
func newPrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// privateKeyToPem take sin a rsa.PrivateKey and returns a PEM encoded certificate
// as a byte array.
// @param privateKey rsa.PrivateKey to encode.
func privateKeyToPem(privateKey *rsa.PrivateKey) []byte {
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	return privateKeyPem
}

// generateSecretName normalizes username and returns a Kubernetes valid secret name
// based of it. Will replace all non-valid characters in username with a hyphen.
// @param username Username to normalize
func generateSecretName(username string) (string, error) {
	var secretName string
	rex, err := regexp.Compile("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*")

	if err != nil {
		return "", fmt.Errorf("failed to compile regex: %v", err)
	}

	var numReplace int
	for _, c := range []byte(strings.ToLower(username)) {
		if rex.Match([]byte{c}) {
			secretName = secretName + string(c)
		} else {
			numReplace++
			secretName = secretName + "-"
		}
	}

	if len(secretName)-numReplace == 0 {
		return "", fmt.Errorf("username '%s' is invalid as it does not contain any alphanumeric characters", username)
	}

	secretName = secretName + "-x509"

	return secretName, nil
}

// NewManager creates a new certificate manager.
// @param kubeClient Pointer to kubernetes Clientset.
// @param namespace Which namespace the secret is located in.
func NewManager(kubeClient *kubernetes.Clientset, namespace string, caCertData string) *Manager {
	return &Manager{
		kubeClient: kubeClient,
		namespace:  namespace,
		caCertData: caCertData,
	}
}

// StoreCertificate saves a CertificateData structrue as a Kubernetes secret.
// @param certData CertificateData structure to store.
func (mgr *Manager) StoreCertificate(certData *CertificateData) (string, error) {
	secretName, err := generateSecretName(certData.Name)

	if err != nil {
		return "", fmt.Errorf("failed to get secretname for '%s': %v", certData.Name, err)
	}

	data, err := json.Marshal(certData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal certificate data: %v", err)
	}

	secretData := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   mgr.namespace,
			Name:        secretName,
			Annotations: map[string]string{},
		},
		Data: map[string][]byte{
			"data": data,
		},
	}

	_, err = mgr.kubeClient.CoreV1().Secrets(mgr.namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		_, err = mgr.kubeClient.CoreV1().Secrets(mgr.namespace).Create(secretData)
	} else {
		_, err = mgr.kubeClient.CoreV1().Secrets(mgr.namespace).Update(secretData)
	}

	if err != nil {
		return "", fmt.Errorf("could not store certificate for user '%s': %v", certData.Name, err)
	}

	return secretName, nil
}

// GetStoredCertificate fetches a certificate stored by StoreCertificate.
// @param username Name of user.
func (mgr *Manager) GetStoredCertificate(username string) (*CertificateData, error) {
	secretName, err := generateSecretName(username)

	if err != nil {
		return nil, fmt.Errorf("failed to get secretname for '%s': %v", username, err)
	}

	secret, err := mgr.kubeClient.CoreV1().Secrets(mgr.namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get secret '%s' for user '%s': %s", secretName, username, err)
	}

	if _, ok := secret.Data["data"]; !ok {
		return nil, fmt.Errorf("no data field found in secret %s", secretName)
	}

	var certData CertificateData
	err = json.Unmarshal(secret.Data["data"], &certData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret %s: %v", secretName, err)
	}

	return &certData, nil
}

// DeleteCertificate deletes a Kubernetes secret/certificate.
// @param certData Certificate do delete.
func (mgr *Manager) DeleteCertificate(certData *CertificateData) error {
	secretName, err := generateSecretName(certData.Name)

	if err != nil {
		return fmt.Errorf("failed to get secretname for '%s': %v", certData.Name, err)
	}

	return mgr.kubeClient.CoreV1().Secrets(mgr.namespace).Delete(secretName, &metav1.DeleteOptions{})
}

// NewCertificate makes a certificate signing request to the Kubernetes server and returns a certificate and privatekey contained in
// a CertificateData struct on success.
// This does not store the certificate for later use, you have to call StoreCertificate on the returned certificate to do that.
// @param username Username to include in this certificate.
// @param groups Groups to include in this certificate.
func (mgr *Manager) NewCertificate(username string, groups []string) (*CertificateData, error) {
	client := mgr.kubeClient.CertificatesV1beta1().CertificateSigningRequests()

	subject := &pkix.Name{
		Organization: groups,
		CommonName:   username,
	}

	privateKey, err := newPrivateKey(2048)

	if err != nil {
		return nil, fmt.Errorf("failed to create private key for '%s': %v", username, err)
	}

	csrData, err := certutil.MakeCSR(privateKey, subject, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate request: %v", err)
	}

	usages := []certificates.KeyUsage{
		certificates.UsageDigitalSignature,
		certificates.UsageKeyEncipherment,
		certificates.UsageClientAuth,
	}

	req, err := csr.RequestCertificate(client, csrData, username, usages, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to request certificate: %v", err)
	}

	req.Status.Conditions = append(req.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:    certificates.CertificateApproved,
		Reason:  "AutoApproved",
		Message: "Approved",
	})

	_, err = client.UpdateApproval(req)

	if err != nil {
		return nil, fmt.Errorf("unable to approve certificate signing request: %v", err)
	}

	crt, err := csr.WaitForCertificate(client, req, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("timed out waiting for certificate: %v", err)
	}

	// Delete the CSR.
	client.Delete(username, &metav1.DeleteOptions{})

	privateKeyPem := privateKeyToPem(privateKey)

	cert := &CertificateData{
		Name:              username,
		PrivateKey:        string(privateKeyPem),
		Certificate:       string(crt),
		PrivateKeyBase64:  base64.StdEncoding.EncodeToString(privateKeyPem),
		CertificateBase64: base64.StdEncoding.EncodeToString(crt),
		CA:                mgr.caCertData,
		CABase64:          base64.StdEncoding.EncodeToString([]byte(mgr.caCertData)),
		Groups:            groups,
	}

	x509Cert, err := mgr.VerifyCertificate(cert, &username, &groups)

	if err != nil {
		return nil, fmt.Errorf("failed to validate certificate that was issued: %s", err.Error())
	}

	cert.IssueDate = x509Cert.NotBefore
	cert.ExpireDate = x509Cert.NotAfter

	return cert, nil
}

// VerifyCertificate verifies a certificate.
// @param certData CertificateData to validate.
// @param expectedUsername Expected common name in the certificate.
// @param expectedGroups	 Expected organizations included in the certificate.
func (mgr *Manager) VerifyCertificate(certData *CertificateData, expectedUsername *string, expectedGroups *[]string) (*x509.Certificate, error) {
	if certData == nil {
		return nil, fmt.Errorf("certificateData cannot be nil")
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(certData.Certificate))

	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate for '%s'", certData.Name)
	}

	block, _ := pem.Decode([]byte(certData.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM for '%s'", certData.Name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate for '%s': %s", certData.Name, err.Error())
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("failed to verify certificate for '%s': %s", certData.Name, err.Error())
	}

	if expectedUsername != nil && cert.Subject.CommonName != *expectedUsername {
		return nil, fmt.Errorf("certificate did not have expected username: %s != %s", cert.Subject.CommonName, *expectedUsername)
	}

	if expectedGroups != nil {
		var missingGroups []string

		for _, expectGroup := range *expectedGroups {
			found := false

			for _, certGroup := range cert.Subject.Organization {
				if certGroup == expectGroup {
					found = true
				}
			}

			if !found {
				missingGroups = append(missingGroups, expectGroup)
			}
		}

		if len(missingGroups) > 0 {
			return nil, fmt.Errorf("certificate is missing the following expected groups %s", strings.Join(missingGroups, ","))
		}
	}

	return cert, nil
}
