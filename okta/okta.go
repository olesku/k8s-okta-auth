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

package okta

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"encoding/base64"
	"encoding/xml"

	saml2 "github.com/russellhaering/gosaml2"
	saml2types "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// ServiceProvider Represents an SAML2 service provider
type ServiceProvider struct {
	idpMetadata *saml2types.EntityDescriptor
	saml2sp     *saml2.SAMLServiceProvider
}

// UserInfo holds the user data contained in a assertion.
type UserInfo struct {
	NameID string
	Groups []string
}

func getAssertionAttr(assertionValues saml2.Values, key string) ([]string, error) {
	val, ok := assertionValues[key]
	if !ok {
		return nil, fmt.Errorf("getAssertionAttr: attribute '%s' not found in SAML response", key)
	}

	if len(val.Values) < 1 {
		return nil, fmt.Errorf("getAssertionAttr: attribute '%s' has no values", key)
	}

	var values []string
	for _, v := range val.Values {
		values = append(values, v.Value)
	}

	return values, nil
}

func getUserInfo(assertionInfo *saml2.AssertionInfo) (*UserInfo, error) {
	groups, err := getAssertionAttr(assertionInfo.Values, "groups")
	if err != nil {
		groups = []string{}
	}

	if assertionInfo.NameID == "" {
		return nil, fmt.Errorf("getUserInfo: NameID is empty")
	}

	user := UserInfo{
		NameID: assertionInfo.NameID,
		Groups: groups,
	}

	return &user, nil
}

func fetchMetaData(url string) (*saml2types.EntityDescriptor, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	metadata := &saml2types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// NewServiceProvider creates a new instance of ServiceProvider
func NewServiceProvider(acsURL, metadataURL string) (*ServiceProvider, error) {
	metadata, err := fetchMetaData(metadataURL)

	if err != nil {
		return nil, fmt.Errorf("error fetching metadata from IDP: %v", err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return nil, fmt.Errorf("metadata certificate(%d) cannot be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, fmt.Errorf("error parsing idp cerificate")
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		AssertionConsumerServiceURL: acsURL,
		SignAuthnRequests:           false,
		AudienceURI:                 acsURL,
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  nil,
	}

	return &ServiceProvider{
		idpMetadata: metadata,
		saml2sp:     sp,
	}, nil
}

// GetIdentityProviderSSOURL returns the IDP SSO URL.
func (sp *ServiceProvider) GetIdentityProviderSSOURL() string {
	return sp.saml2sp.IdentityProviderSSOURL
}

// ValidateSAMLAssertion validates a SAML2 assertion request.
func (sp *ServiceProvider) ValidateSAMLAssertion(encodedResponse string) (*UserInfo, error) {
	assertionInfo, err := sp.saml2sp.RetrieveAssertionInfo(encodedResponse)

	if err != nil {
		return nil, fmt.Errorf("assertion error: %s", err.Error())
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return nil, fmt.Errorf("invalid time")
	}

	if assertionInfo.WarningInfo.NotInAudience {
		return nil, fmt.Errorf("not in audience")
	}

	userinfo, err := getUserInfo(assertionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo")
	}

	return userinfo, nil
}
