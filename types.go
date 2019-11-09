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
	"net/http"
	"regexp"

	"github.com/alexedwards/scs"
	"github.com/olesku/k8s-okta-auth/okta"
)

// ApplicationConfig contains all required configuration.
type ApplicationConfig struct {
	ListenPort       int    `envconfig:"LISTEN_PORT" default:"8080" required:"true"`
	OktaMetadataURL  string `envconfig:"OKTA_METADATA_URL" required:"true"`
	SelfURL          string `envconfig:"SELF_URL" required:"true"`
	ClusterName      string `envconfig:"CLUSTER_NAME" required:"true"`
	MasterURL        string `envconfig:"MASTER_URL"`
	KubeConfig       string `envconfig:"KUBECONFIG" default:""`
	CACertFile       string `envconfig:"CA_CERT_FILE" default:"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"`
	DefaultNameSpace string `envconfig:"DEFAULT_NAMESPACE" default:"default"`
	SecretNameSpace  string `envconfig:"SECRET_NAMESPACE" default:"default"`
	IncludeGroups    bool   `envconfig:"INCLUDE_GROUPS" default:"true"`
	GroupFilter      string `envconfig:"GROUP_FILTER" default:"default"`

	CompiledGroupFilter *regexp.Regexp
	BaseURI             string
}

// AccountProvider Interface for account providers.
type AccountProvider interface {
	Create(username string, groups []string) (bool, error)
	Delete(username string) (bool, error)
	Get(username string) (interface{}, error)
	ValidateUser(username string, groups []string) (bool, error)

	HandleRequest(ctx *HandlerContext, reqPath string)
}

// TemplateCtx Template context.
type TemplateCtx struct {
	Account interface{}
	Config  *ApplicationConfig
}

// HandlerContext holds all parameters required in HTTP handlers.
type HandlerContext struct {
	AppConfig           *ApplicationConfig
	OktaServiceProvider *okta.ServiceProvider
	SessionManager      *scs.Manager
	AccountManager      AccountProvider
	UserAccount         interface{}
	Resp                http.ResponseWriter
	Req                 *http.Request
}
