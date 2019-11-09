package certgen

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeClient *kubernetes.Clientset
var certManager *Manager

func newKubernetesClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	if os.Getenv("KUBECONFIG") != "" {
		config, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			return nil, err
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func TestGenerateSecretName(t *testing.T) {
	secret, err := generateSecretName("testuser@mydomain.com")
	assert.NilError(t, err)
	assert.Equal(t, secret, "testuser-mydomain-com-x509")
}

func TestNewPrivateKey(t *testing.T) {
	privKey, err := newPrivateKey(2048)
	assert.NilError(t, err)
	assert.Assert(t, privKey != nil)

	pem := privateKeyToPem(privKey)

	assert.Assert(t, is.Contains(string(pem), "RSA PRIVATE KEY"))
}

func TestCertificateManager(t *testing.T) {
	assert.Assert(t, 1 == 1)

	testUser := "testuser@mydomain.com"

	testGroups := []string{
		"group1",
		"group2",
		"group3",
	}

	cert, err := certManager.NewCertificate(testUser, testGroups)
	assert.NilError(t, err)
	assert.Equal(t, cert.Name, testUser)
	assert.DeepEqual(t, cert.Groups, testGroups)

	// StoreCertificate
	secretName, err := certManager.StoreCertificate(cert)
	assert.NilError(t, err)

	expectedSecretName, _ := generateSecretName(cert.Name)
	assert.Equal(t, secretName, expectedSecretName)

	// GetStoredCertificate
	storedCert, err := certManager.GetStoredCertificate(testUser)
	assert.NilError(t, err)
	assert.Equal(t, storedCert.Name, testUser)
	assert.DeepEqual(t, storedCert.Groups, testGroups)

	_, err = certManager.GetStoredCertificate("asdf@asdf.com")
	assert.ErrorContains(t, err, "could not get secret")

	// VerifyCertificate
	_, err = certManager.VerifyCertificate(storedCert, nil, nil)
	assert.NilError(t, err)

	_, err = certManager.VerifyCertificate(storedCert, &testUser, &testGroups)
	assert.NilError(t, err)

	tUser2 := "someother@user.com"
	_, err = certManager.VerifyCertificate(storedCert, &tUser2, &testGroups)
	assert.ErrorContains(t, err, "certificate did not have expected username")

	tgroups2 := append(testGroups, "group4")
	_, err = certManager.VerifyCertificate(storedCert, &testUser, &tgroups2)
	assert.ErrorContains(t, err, "certificate is missing the following expected groups group4")

	// DeleteCertificate
	err = certManager.DeleteCertificate(storedCert)
	assert.NilError(t, err)

	err = certManager.DeleteCertificate(storedCert)
	assert.Assert(t, err != nil)

	// GetStoredCertificate after delete
	storedCert, err = certManager.GetStoredCertificate(testUser)
	assert.Assert(t, err != nil)
	assert.Assert(t, storedCert == nil)
}

func TestMain(m *testing.M) {
	kubeClient, err := newKubernetesClient()

	if err != nil {
		fmt.Printf("test error: could not create kubernetes client: %v\n", err)
		os.Exit(1)
	}

	caFile := os.Getenv("CA_CERT_FILE")
	if caFile == "" {
		caFile = "/var/snap/microk8s/current/certs/ca.crt"
	}

	caData, err := ioutil.ReadFile(caFile)
	if err != nil {
		fmt.Printf("Failed to open CA certificate '%s': %s\n", caFile, err.Error())
		os.Exit(1)
	}

	certManager = NewManager(kubeClient, "default", string(caData))

	m.Run()
}
