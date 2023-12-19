package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"tailscale.com/client/tailscale"
)

var client tailscale.LocalClient

var (
	allowedOrigins string
	address        string
	origins        []string
)

func init() {
	flag.StringVar(&allowedOrigins, "allowed-origins", "http://localhost:3000", "comma-separated list of allowed origins")
	flag.StringVar(&address, "address", "", "address to listen on")
}

func whoami(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	found := false
	for _, o := range origins {
		if o == origin {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.Header().Set("Vary", "Origin")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	whoami, err := client.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(whoami)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	address = ":" + port
	flag.Parse()
	origins = strings.Split(allowedOrigins, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	http.HandleFunc("/whoami", whoami)
	server := &http.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			GetCertificate: client.GetCertificate,
		},
	}

	status, err := client.Status(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Listening on", strings.TrimSuffix(status.Self.DNSName, ".")+address)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
