package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
	"golang.org/x/crypto/acme"

	"src.agwa.name/go-listener"
	"src.agwa.name/go-listener/cert"
	"src.agwa.name/tlshacks"
)

func handler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	clientHello := req.Context().Value(tlshacks.ClientHelloKey).([]byte)
	info := tlshacks.UnmarshalClientHello(clientHello)

	log.Printf("%s %q %#v", req.RemoteAddr, req.Header.Get("User-Agent"), info)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func main() {
	var (
		hostname    = os.Args[1]
		listenerArg = os.Args[2]
	)

	tlsConfig := &tls.Config{
		GetCertificate: cert.GetCertificateAutomatically([]string{hostname}),
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
	}
	httpServer := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
		Handler:      http.HandlerFunc(handler),
		ConnContext:  tlshacks.ConnContext,
	}

	streamListener, err := listener.Open(listenerArg)
	if err != nil {
		log.Fatal(err)
	}
	defer streamListener.Close()

	tlsListener := tls.NewListener(tlshacks.NewListener(streamListener), tlsConfig)
	log.Fatal(httpServer.Serve(tlsListener))
}
