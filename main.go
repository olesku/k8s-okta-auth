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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alexedwards/scs"
	"github.com/alexedwards/scs/stores/memstore"
	"github.com/kelseyhightower/envconfig"
	"github.com/olesku/k8s-okta-auth/okta"
)

// handleMain routes all requests to correct handler.
// @param ctx Request context.
func handlerMain(ctx *HandlerContext) http.Handler {
	fn := func(resp http.ResponseWriter, req *http.Request) {
		sess := ctx.SessionManager.Load(req)
		username, _ := sess.GetString("username")
		logUsername := username

		if logUsername == "" {
			logUsername = "anonymous"
		}

		log.Printf("%s (%s) %s %s", req.RemoteAddr, logUsername, req.Method, req.RequestURI)

		if req.RequestURI == ctx.AppConfig.BaseURI {
			http.Redirect(resp, req, ctx.AppConfig.BaseURI+"/", http.StatusFound)
			return
		}

		reqPath := strings.TrimPrefix(req.RequestURI, ctx.AppConfig.BaseURI)

		if !strings.HasPrefix(req.RequestURI, ctx.AppConfig.BaseURI) {
			showError(resp, http.StatusBadRequest, "Invalid route")
			return
		}

		hCtx := *ctx
		hCtx.Resp = resp
		hCtx.Req = req

		if reqPath == "/saml/acs" {
			if req.Method != "POST" {
				resp.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintln(resp, "Method not allowed.")
				return
			}

			acsHandler(&hCtx)
			return
		}

		if req.Method != "GET" {
			resp.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintln(resp, http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		if username == "" {
			http.Redirect(resp, req, ctx.OktaServiceProvider.GetIdentityProviderSSOURL(), http.StatusFound)
			return
		}

		userAccount, err := ctx.AccountManager.Get(username)
		if err != nil {
			showError(resp, http.StatusNotFound, "%s", err.Error())
			return
		}

		hCtx.UserAccount = userAccount
		ctx.AccountManager.HandleRequest(&hCtx, reqPath)
	}

	return ctx.SessionManager.Use(http.HandlerFunc(fn))
}

// acsHandler checks a SAML assertion requests and creates a session if it's valid.
// It will also create and store a new certificate for the user if it doesn't exist
// or if the existing one is invalid.
// @param ctx HandlerContext
func acsHandler(ctx *HandlerContext) {
	err := ctx.Req.ParseForm()

	if err != nil {
		showError(ctx.Resp, http.StatusBadRequest, "Could not parse form data: %s\n", err.Error())
		return
	}

	userInfo, err := ctx.OktaServiceProvider.ValidateSAMLAssertion(ctx.Req.FormValue("SAMLResponse"))
	if err != nil {
		showError(ctx.Resp, http.StatusForbidden, "Invalid SAML assertion: %s", err.Error())
		return
	}

	if userInfo.NameID == "" {
		showError(ctx.Resp, http.StatusForbidden, "No username found in SAML assertion.")
		return
	}

	sess := ctx.SessionManager.Load(ctx.Req)
	sess.Remove(ctx.Resp, "username")

	var groups []string
	if ctx.AppConfig.IncludeGroups {
		for _, group := range userInfo.Groups {
			if ctx.AppConfig.GroupFilter != "" && !ctx.AppConfig.CompiledGroupFilter.MatchString(group) {
				continue
			}

			groups = append(groups, group)
		}
	}

	// Create user if it doesn't exist.
	if _, err := ctx.AccountManager.Get(userInfo.NameID); err != nil {
		_, err = ctx.AccountManager.Create(userInfo.NameID, groups)
		if err != nil {
			showError(ctx.Resp, 500, "Failed to create user %s: %s", userInfo.NameID, err.Error())
			return
		}
	}

	// If user is invalid (missing groups, expired, etc) recreate it and validate once again.
	valid, err := ctx.AccountManager.ValidateUser(userInfo.NameID, groups)
	if !valid {
		log.Printf("Failed to validate user %s: %s. Attempting to recreate it.", userInfo.NameID, err.Error())
		ctx.AccountManager.Delete(userInfo.NameID)
		ctx.AccountManager.Create(userInfo.NameID, groups)

		valid, err = ctx.AccountManager.ValidateUser(userInfo.NameID, groups)

		if !valid {
			showError(ctx.Resp, 500, "Failed to validate user %s: %s", userInfo.NameID, err.Error())
			return
		}
	}

	log.Printf("Successfully validated user %s.", userInfo.NameID)

	sess.PutString(ctx.Resp, "username", userInfo.NameID)
	http.Redirect(ctx.Resp, ctx.Req, ctx.AppConfig.BaseURI+"/", http.StatusFound)
}

func main() {
	var appConfig ApplicationConfig
	err := envconfig.Process("", &appConfig)

	if err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		envconfig.Usage("", appConfig)
		os.Exit(1)
	}

	if appConfig.IncludeGroups {
		appConfig.CompiledGroupFilter = regexp.MustCompile(appConfig.GroupFilter)
	}

	selfURL, err := url.Parse(appConfig.SelfURL)
	if err != nil {
		fmt.Printf("Invalid SELF_URL '%s': %s\n", appConfig.SelfURL, err.Error())
		os.Exit(1)
	}

	kubeClient, err := newKubernetesClient(&appConfig)
	if err != nil {
		log.Fatalf("Error connecting to kubernetes: %v\n", err.Error())
	}

	appConfig.BaseURI = strings.TrimSuffix(selfURL.EscapedPath(), "/")
	acsURL := fmt.Sprintf("%s://%s%s/saml/acs", selfURL.Scheme, selfURL.Host, appConfig.BaseURI)

	oktaSp, err := okta.NewServiceProvider(acsURL, appConfig.OktaMetadataURL)
	if err != nil {
		log.Fatalf("failed to initialize okta service provider: %v\n", err)
	}

	accountManager := NewServiceAccountProvider(&appConfig, kubeClient)

	var sessionManager = scs.NewManager(memstore.New(0))
	sessionManager.Lifetime(5 * time.Minute)
	sessionManager.Persist(true)

	if selfURL.Scheme == "https" {
		sessionManager.Secure(true)
	}

	handlerCtx := &HandlerContext{
		AppConfig:           &appConfig,
		AccountManager:      accountManager,
		OktaServiceProvider: oktaSp,
		SessionManager:      sessionManager,
	}

	http.ListenAndServe(fmt.Sprintf(":%d", appConfig.ListenPort), handlerMain(handlerCtx))
}
