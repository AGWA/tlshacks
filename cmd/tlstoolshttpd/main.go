// Copyright (C) 2023 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"flag"
	"strings"

	"src.agwa.name/go-listener/cert"
)

func parseCertString(str string) cert.GetCertificateFunc {
	if strings.HasPrefix(str, "/") {
		// assume it's a path to a certificate
		return cert.GetCertificateFromFile(str)
	} else {
		// assume it's a hostname
		return cert.GetCertificateAutomatically([]string{str})
	}
}

type config struct {
	cert   string
	listen string
}

func main() {
	var clientcertConfig, clienthelloConfig, clienthelloResumptionConfig config
	flag.StringVar(&clientcertConfig.cert, "clientcert-cert", "", "Hostname or certificate file for clientcert")
	flag.StringVar(&clientcertConfig.listen, "clientcert-listen", "", "Socket for clientcert to listen on")
	flag.StringVar(&clienthelloConfig.cert, "clienthello-cert", "", "Hostname or certificate file for clienthello")
	flag.StringVar(&clienthelloConfig.listen, "clienthello-listen", "", "Socket for clienthello to listen on")
	flag.StringVar(&clienthelloResumptionConfig.cert, "clienthello-resumption-cert", "", "Hostname or certificate file for clienthello with resumption")
	flag.StringVar(&clienthelloResumptionConfig.listen, "clienthello-resumption-listen", "", "Socket for clienthello with resumption to listen on")
	flag.Parse()

	if clientcertConfig.listen != "" {
		go runClientcert(clientcertConfig)
	}
	if clienthelloConfig.listen != "" {
		go runClienthello(clienthelloConfig, false)
	}
	if clienthelloResumptionConfig.listen != "" {
		go runClienthello(clienthelloResumptionConfig, true)
	}
	select {}
}
