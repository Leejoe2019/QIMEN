package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Leejoe2019/QIMEN/internal/qimen"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	httpListen := flag.String("http-listen", "127.0.0.1:1081", "local HTTP proxy listen address (empty disables)")
	servers := flag.String("servers", "", "comma-separated QIMEN server host:port endpoints")
	ca := flag.String("ca", "", "trusted certificate CA/self-signed server cert PEM; default system roots")
	servername := flag.String("tls-server-name", "", "optional TLS certificate server name override")
	interval := flag.Duration("probe-interval", 15*time.Second, "path re-probe interval")
	timeout := flag.Duration("dial-timeout", 5*time.Second, "server dial/probe timeout")
	flag.Parse()
	if *servers == "" {
		log.Fatal("--servers is required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			log.Fatal("invalid CA PEM")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := &qimen.Client{Listen: *listen, HTTPListen: *httpListen, Servers: strings.Split(*servers, ","), Token: os.Getenv("QIMEN_TOKEN"), TLSConfig: &tls.Config{RootCAs: roots, ServerName: *servername, MinVersion: tls.VersionTLS13}, ProbeInterval: *interval, DialTimeout: *timeout}
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
