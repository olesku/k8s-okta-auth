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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Index page template.
const saIndexTemplate = `<html>
<head>
	<title>Kubernetes configuration for {{ .Config.ClusterName }}</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u"
	 crossorigin="anonymous">
</head>
<body>
	<div class="container">
		<div class="page-header">
			<h3>Kubernetes configuration</h3>
		</div>

		<div class="panel panel-primary">
			<div class="panel-heading">
				<h3 class="panel-title">Configuration for {{ .Account.Name }} in cluster {{ .Config.ClusterName }}</h3>
			</div>
			<div class="panel-body">
				<p><a href="kubeconfig"><span class="glyphicon glyphicon-download"></span> Standalone kubeconfig file</a></p>
				<p><a href="setup_kubeconfig.sh"><span class="glyphicon glyphicon-download"></span> Script for adding to existing kubeconfig</a></p>
			</div>
		</div>
	</div>
</body>
</html>
`

// Kubeconfig template.
const saKubeConfigTemplate = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {{ .Account.TokenCABase64 }}
    server: {{ .Config.MasterURL }}
  name: {{ .Config.ClusterName }}
contexts:
- context:
    cluster: {{ .Config.ClusterName }}
    namespace: {{ .Config.DefaultNameSpace }}
    user: {{ .Account.Name }}
  name: {{ .Config.ClusterName }}
current-context: {{ .Config.ClusterName }}
users:
- name: {{ .Account.Name }}
  user:
    token: {{ .Account.Token }}
`

// Setup script template.
const saSetupScriptTemplate = `#!/bin/bash

export CA_FILE=$(mktemp) && \

echo '{{ .Account.TokenCA }}' > "${CA_FILE}" && \

kubectl config set-cluster {{ .Config.ClusterName }} --server='{{ .Config.MasterURL }}' --certificate-authority="${CA_FILE}" --embed-certs='true' && \
kubectl config set-cluster {{ .Config.ClusterName }} --server='{{ .Config.MasterURL }}' && \

kubectl config set-credentials {{ .Config.ClusterName }}-{{ .Account.Name }} --token='{{ .Account.Token }}' && \

kubectl config set-context {{ .Config.ClusterName }} --cluster='{{ .Config.ClusterName }}' --namespace='{{ .Config.DefaultNameSpace }}' --user='{{ .Config.ClusterName }}-{{ .Account.Name }}' && \

kubectl config use-context {{ .Config.ClusterName }}; \

rm -f "${CA_FILE}"
`

// ServiceAccount Holds service account data used to generate userconfig templates.
type ServiceAccount struct {
	Namespace         string
	Name              string
	TokenCA           string
	TokenCABase64     string
	Token             string
	CreationTimestamp metav1.Time
}

// ServiceAccountProvider AccountProvider implementation for service accounts.
type ServiceAccountProvider struct {
	kubeClient *kubernetes.Clientset
	appConfig  *ApplicationConfig
}

// NewServiceAccountProvider Create a new ServiceAccountProvider.
func NewServiceAccountProvider(appConfig *ApplicationConfig, kubeClient *kubernetes.Clientset) *ServiceAccountProvider {
	return &ServiceAccountProvider{
		appConfig:  appConfig,
		kubeClient: kubeClient,
	}
}

// normalizeServiceAccountName replace '@' with -.
func normalizeServiceAccountName(username string) string {
	return strings.Replace(username, "@", "-", -1)
}

// Create a new service account.
// @param username Username of service account. This will be run throug normalizeServiceAccountName().
// @param groups Required by interface, not used in this provider.
func (provider *ServiceAccountProvider) Create(username string, groups []string) (bool, error) {
	saName := normalizeServiceAccountName(username)

	_, err := provider.kubeClient.CoreV1().ServiceAccounts(provider.appConfig.DefaultNameSpace).Create(&v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: provider.appConfig.DefaultNameSpace,
		},
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

// Delete a service account.
// @param username Username of service account.
func (provider *ServiceAccountProvider) Delete(username string) (bool, error) {
	return true, nil
}

// Get a service ServiceAccount object from username.
func (provider *ServiceAccountProvider) Get(username string) (interface{}, error) {
	saName := normalizeServiceAccountName(username)

	sa, err := provider.kubeClient.CoreV1().ServiceAccounts(provider.appConfig.DefaultNameSpace).Get(saName, metav1.GetOptions{})

	if err != nil {
		return nil, err
	}

	if len(sa.Secrets) < 1 {
		return nil, fmt.Errorf("No secrets configured for serviceaccount '%s:%s'", provider.appConfig.DefaultNameSpace, saName)
	}

	secret, err := provider.kubeClient.CoreV1().Secrets(provider.appConfig.DefaultNameSpace).Get(sa.Secrets[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	ca, ok := secret.Data["ca.crt"]
	if !ok {
		return nil, fmt.Errorf("ca.crt not found in secret '%s'", secret.Name)
	}

	token, ok := secret.Data["token"]
	if !ok {
		return nil, fmt.Errorf("token not found in secret '%s'", secret.Name)
	}

	return &ServiceAccount{
		Namespace:         sa.Namespace,
		Name:              sa.Name,
		CreationTimestamp: sa.CreationTimestamp,
		TokenCA:           string(ca),
		TokenCABase64:     base64.StdEncoding.EncodeToString(ca), // CA is base64 encoded.
		Token:             string(token),                         // Token is not.
	}, nil
}

// ValidateUser Check if service account is valid.
// @param username Username of service account. This will be run throug normalizeServiceAccountName().
// @param groups Required by interface, not used in this provider.
func (provider *ServiceAccountProvider) ValidateUser(username string, groups []string) (bool, error) {
	saName := normalizeServiceAccountName(username)

	_, err := provider.kubeClient.CoreV1().ServiceAccounts(provider.appConfig.DefaultNameSpace).Get(saName, metav1.GetOptions{})

	if err != nil {
		return false, err
	}

	return true, nil
}

// HandleRequest Handle HTTP request for config endpoints.
// @param ctx HTTP handler context.
// @param reqPath Requested URI.
func (provider *ServiceAccountProvider) HandleRequest(ctx *HandlerContext, reqPath string) {
	var pageTemplate string
	var buffer bytes.Buffer

	switch reqPath {
	case "/":
		pageTemplate = saIndexTemplate
		ctx.Resp.WriteHeader(http.StatusOK)

	case "/kubeconfig":
		ctx.Resp.Header().Set("Content-Type", "text/plain")
		ctx.Resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"kubeconfig_%s\"", strings.ReplaceAll(ctx.AppConfig.ClusterName, " ", "_")))
		ctx.Resp.WriteHeader(http.StatusOK)

		pageTemplate = saKubeConfigTemplate

	case "/setup_kubeconfig.sh":
		ctx.Resp.Header().Set("Content-Type", "text/plain")
		ctx.Resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"setup_kubeconfig_%s.sh\"", strings.ReplaceAll(ctx.AppConfig.ClusterName, " ", "_")))
		ctx.Resp.WriteHeader(http.StatusOK)

		pageTemplate = saSetupScriptTemplate
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
