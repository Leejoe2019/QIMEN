package qimen

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHTTPProxyGETAndHTTPSCONNECT(t *testing.T) {
	upstreamHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/qimen" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "http-through-qimen")
	}))
	defer upstreamHTTP.Close()
	upstreamTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "https-through-qimen")
	}))
	defer upstreamTLS.Close()
	pair, roots := testCert(t)
	remoteAddr, socksAddr, httpAddr := pickAddr(t), pickAddr(t), pickAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{Listen: remoteAddr, UDPListen: "-", Token: "http-proxy-integration-token", TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}
	go func() { _ = server.Run(ctx) }()
	connectRetry(t, remoteAddr).Close()
	client := &Client{Listen: socksAddr, HTTPListen: httpAddr, Servers: []string{remoteAddr}, Token: "http-proxy-integration-token", TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ProbeInterval: time.Hour, DialTimeout: time.Second}
	go func() { _ = client.Run(ctx) }()
	proxyURL, err := url.Parse("http://" + httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	plain := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	var resp *http.Response
	for i := 0; i < 40; i++ {
		resp, err = plain.Get(upstreamHTTP.URL + "/qimen")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != "http-through-qimen" {
		t.Fatalf("plain response: %s %s", resp.Status, string(data))
	}
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(upstreamTLS.Certificate())
	httpsClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: tlsRoots}}}
	resp, err = httpsClient.Get(upstreamTLS.URL + "/secure")
	if err != nil {
		t.Fatalf("HTTPS CONNECT: %v", err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != "https-through-qimen" {
		t.Fatalf("TLS response: %s %s", resp.Status, string(data))
	}
}
