// Copyright (C) 2022 Andrew Ayer
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
	"crypto/tls"
	"encoding/json"
	"golang.org/x/crypto/acme"
	"log"
	"net/http"
	"time"

	"src.agwa.name/go-listener"
	"src.agwa.name/tlshacks"
)

func handleClienthello(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	clientHello := req.Context().Value(tlshacks.ClientHelloKey).([]byte)
	info := tlshacks.UnmarshalClientHello(clientHello)

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ")
	encoder.Encode(info)
}

func runClienthello(config config, enableResumption bool) {
	streamListener, err := listener.Open(config.listen)
	if err != nil {
		log.Fatalf("error opening clienthello listener: %s", err)
	}
	defer streamListener.Close()

	tlsConfig := &tls.Config{
		NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
		SessionTicketsDisabled: !enableResumption,
		GetCertificate:         parseCertString(config.cert),
	}
	httpServer := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
		Handler:      http.HandlerFunc(handleClienthello),
		ConnContext:  tlshacks.ConnContext,
	}
	httpServer.SetKeepAlivesEnabled(false)

	tlsListener := tls.NewListener(tlshacks.NewListener(streamListener), tlsConfig)
	log.Fatal(httpServer.Serve(tlsListener))
}
