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

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/olesku/k8s-okta-auth/certgen"
	"k8s.io/client-go/kubernetes"
)

const x509ClientCertIndexTemplate = ``

const x509ClientCertKubeconfigTemplate = ``

const x509ClientCertSetupScriptTemplate = ``

// X509ClientCertProvider AccountProvider implementation for service accounts.
type X509ClientCertProvider struct {
	kubeClient  *kubernetes.Clientset
	appConfig   *ApplicationConfig
	certManager *certgen.Manager
}

// NewX509ClientCertProvider Create a new X509ClientCertProvider.
func NewX509ClientCertProvider(appConfig *ApplicationConfig, kubeClient *kubernetes.Clientset) *X509ClientCertProvider {
	caData, err := ioutil.ReadFile(appConfig.CACertFile)
	if err != nil {
		log.Fatalf("Failed to open CA certificate '%s': %s\n", appConfig.CACertFile, err.Error())
	}

	return &X509ClientCertProvider{
		appConfig:   appConfig,
		kubeClient:  kubeClient,
		certManager: certgen.NewManager(kubeClient, appConfig.DefaultNameSpace, string(caData)),
	}
}

// Create a new x509 client certificate.
// @param username Username of service account. This will be run throug normalizeServiceAccountName().
// @param groups Required by interface, not used in this provider.
func (provider *X509ClientCertProvider) Create(username string, groups []string) (bool, error) {
	_, err := provider.certManager.NewCertificate(username, groups)

	if err != nil {
		return false, err
	}

	return true, nil
}

// Delete a client cert.
// @param username Username of client cert.
func (provider *X509ClientCertProvider) Delete(username string) (bool, error) {
	user, err := provider.certManager.GetStoredCertificate(username)

	if err != nil {
		return false, err
	}

	err = provider.certManager.DeleteCertificate(user)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Get a service client cert object from username.
func (provider *X509ClientCertProvider) Get(username string) (interface{}, error) {
	user, err := provider.certManager.GetStoredCertificate(username)

	if err != nil {
		return nil, err
	}

	return user, nil
}

// ValidateUser Check if service account is valid.
// @param username Username of client cert.
// @param groups Required by interface, not used in this provider.
func (provider *X509ClientCertProvider) ValidateUser(username string, groups []string) (bool, error) {
	user, err := provider.certManager.GetStoredCertificate(username)

	if err != nil {
		return false, err
	}

	_, err = provider.certManager.VerifyCertificate(user, &username, &groups)
	if err != nil {
		return false, err
	}

	return true, nil
}

// HandleRequest Handle HTTP request for config endpoints.
// @param ctx HTTP handler context.
// @param reqPath Requested URI.
func (provider *X509ClientCertProvider) HandleRequest(ctx *HandlerContext, reqPath string) {
	var pageTemplate string
	var buffer bytes.Buffer

	switch reqPath {
	case "/":
		pageTemplate = x509ClientCertIndexTemplate
		ctx.Resp.WriteHeader(http.StatusOK)

	case "/kubeconfig":
		ctx.Resp.Header().Set("Content-Type", "text/plain")
		ctx.Resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"kubeconfig_%s\"", strings.ReplaceAll(ctx.AppConfig.ClusterName, " ", "_")))
		ctx.Resp.WriteHeader(http.StatusOK)

		pageTemplate = x509ClientCertKubeconfigTemplate

	case "/setup_kubeconfig.sh":
		ctx.Resp.Header().Set("Content-Type", "text/plain")
		ctx.Resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"setup_kubeconfig_%s.sh\"", strings.ReplaceAll(ctx.AppConfig.ClusterName, " ", "_")))
		ctx.Resp.WriteHeader(http.StatusOK)

		pageTemplate = x509ClientCertSetupScriptTemplate
	default:
		showError(ctx.Resp, http.StatusBadRequest, "Invalid route")
		return
	}

	tpl, err := template.New(reqPath).Parse(pageTemplate)
	if err != nil {
		showError(ctx.Resp, http.StatusInternalServerError, err.Error())
		return
	}

	err = tpl.Execute(&buffer, &TemplateCtx{
		Account: ctx.UserAccount,
		Config:  ctx.AppConfig,
	})

	if err != nil {
		showError(ctx.Resp, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.Resp.Write(buffer.Bytes())
}
