package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Leejoe2019/QIMEN/internal/qimen"
)

func main() {
	listen := flag.String("listen", ":8443", "TLS TCP listen address")
	udp := flag.String("udp-listen", "", "UDP probe address (default same as TCP, '-' disables)")
	cert := flag.String("tls-cert", "", "TLS certificate PEM")
	key := flag.String("tls-key", "", "TLS private key PEM")
	timeout := flag.Duration("dial-timeout", 10*time.Second, "destination dial timeout")
	flag.Parse()
	if *cert == "" || *key == "" {
		log.Fatal("--tls-cert and --tls-key required")
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &qimen.Server{Listen: *listen, UDPListen: *udp, Token: os.Getenv("QIMEN_TOKEN"), TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, DialTimeout: *timeout}
	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
