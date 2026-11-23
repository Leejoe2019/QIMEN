package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Leejoe2019/QIMEN/internal/qimen"
)

type config struct {
	Listen            string `json:"listen"`
	UDPListen         string `json:"udp_listen"`
	Token             string `json:"token"`
	TLSCertificatePEM string `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM  string `json:"tls_private_key_pem"`
	DialTimeout       string `json:"dial_timeout"`
}

func loadConfig(path string) (config, error) {
	var c config
	if path == "" {
		return c, fmt.Errorf("--config is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return c, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return c, fmt.Errorf("config must be a regular file with permissions 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("config JSON: %w", err)
	}
	if c.Token == "" || c.TLSCertificatePEM == "" || c.TLSPrivateKeyPEM == "" {
		return c, fmt.Errorf("missing token or TLS certificate/key")
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:18443"
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return c, fmt.Errorf("listen: %w", err)
	}
	if c.UDPListen == "" {
		c.UDPListen = "-"
	}
	if c.UDPListen != "-" {
		_, udpPort, err := net.SplitHostPort(c.UDPListen)
		if err != nil {
			return c, fmt.Errorf("udp_listen: %w", err)
		}
		if port != udpPort {
			return c, fmt.Errorf("TCP and UDP must use the same numeric port")
		}
	}
	return c, nil
}

func main() {
	configFile := flag.String("config", "", "path to the single JSON configuration file")
	flag.Parse()
	c, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(c.TLSCertificatePEM), []byte(c.TLSPrivateKeyPEM))
	if err != nil {
		log.Fatal("invalid embedded TLS certificate/key: ", err)
	}
	timeout := 10 * time.Second
	if strings.TrimSpace(c.DialTimeout) != "" {
		timeout, err = time.ParseDuration(c.DialTimeout)
		if err != nil || timeout <= 0 {
			log.Fatal("invalid dial_timeout")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &qimen.Server{Listen: c.Listen, UDPListen: c.UDPListen, Token: c.Token, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, DialTimeout: timeout}
	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
