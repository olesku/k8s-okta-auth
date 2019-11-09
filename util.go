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
	"log"
	"net/http"
	"text/template"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const errorTemplate = `<html>
<head>
  <title>Error</title>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u"
   crossorigin="anonymous">
</head>
<body>
  <div class="container">
    <div class="page-header">
      <h3>Error</h3>
    </div>

    <div class="panel panel-primary">
      <div class="panel-heading">
        <h3 class="panel-title">Details</h3>
      </div>
      <div class="panel-body">
        {{ . }}
      </div>
    </div>
  </div>
</body>
</html>`

func newKubernetesClient(appConfig *ApplicationConfig) (*kubernetes.Clientset, error) {

	var config *rest.Config
	var err error

	if appConfig.KubeConfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", appConfig.KubeConfig)
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

func showError(rw http.ResponseWriter, statusCode int, format string, args ...interface{}) (int, error) {
	errorString := fmt.Sprintf(format, args...)

	var templateBuffer bytes.Buffer
	tpl, _ := template.New("error").Parse(errorTemplate)
	err := tpl.Execute(&templateBuffer, errorString)

	if err != nil {
		log.Printf("Error rendering error template: %s", err.Error())
		return fmt.Fprintf(rw, "<h1>Error</h1>\n<pre>%s</pre>\n", errorString)
	}

	rw.WriteHeader(statusCode)
	return rw.Write(templateBuffer.Bytes())
}
