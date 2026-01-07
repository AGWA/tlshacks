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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/acme"
	"log"
	"net/http"
	"time"

	"src.agwa.name/go-listener"
)

func fingerprints(certs []*x509.Certificate) []string {
	f := make([]string, len(certs))
	for i, cert := range certs {
		fp := sha256.Sum256(cert.Raw)
		f[i] = hex.EncodeToString(fp[:])
	}
	return f
}

func handleClientcert(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	certs := req.TLS.PeerCertificates

	if verbose {
		log.Printf("clientcert: %v", fingerprints(certs))
	}

	w.Header().Set("Content-Type", "text/plain")
	for _, cert := range certs {
		fmt.Fprintf(w, "Subject = %s\n", cert.Subject.String())
		fmt.Fprintf(w, "Issuer = %s\n", cert.Issuer.String())
		fmt.Fprintf(w, "Certificate SHA-256 = %x\n", sha256.Sum256(cert.Raw))
		fmt.Fprintf(w, "Public Key SHA-256 = %x\n", sha256.Sum256(cert.RawSubjectPublicKeyInfo))
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
}

func runClientcert(config config) {
	streamListener, err := listener.Open(config.listen)
	if err != nil {
		log.Fatalf("error opening clientcert listener: %s", err)
	}
	defer streamListener.Close()

	tlsConfig := &tls.Config{
		NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
		SessionTicketsDisabled: true,
		ClientAuth:             tls.RequireAnyClientCert,
		GetCertificate:         parseCertString(config.cert),
	}
	httpServer := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
		Handler:      http.HandlerFunc(handleClientcert),
	}
	httpServer.SetKeepAlivesEnabled(false)

	tlsListener := tls.NewListener(streamListener, tlsConfig)
	log.Fatal(httpServer.Serve(tlsListener))
}
