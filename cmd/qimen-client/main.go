package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Leejoe2019/QIMEN/internal/qimen"
)

type config struct {
	Listen         string   `json:"listen"`
	HTTPListen     string   `json:"http_listen"`
	Servers        []string `json:"servers"`
	Token          string   `json:"token"`
	TLSCAPEM       string   `json:"tls_ca_pem"`
	TLSServerName  string   `json:"tls_server_name"`
	ProbeInterval  string   `json:"probe_interval"`
	DialTimeout    string   `json:"dial_timeout"`
	AsymUDPAddress string   `json:"asym_udp_address"`
}

func loadConfig(path string) (config, error) {
	var cfg config
	if path == "" {
		return cfg, errors.New("--config is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return cfg, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("config must be a regular file with permissions 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.Token == "" || len(cfg.Servers) == 0 || cfg.TLSCAPEM == "" {
		return cfg, errors.New("token, servers and tls_ca_pem are required")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.HTTPListen == "" {
		cfg.HTTPListen = "127.0.0.1:1081"
	}
	return cfg, nil
}
func main() {
	path := flag.String("config", "", "path to single JSON config file")
	asymProbe := flag.Bool("asym-probe", false, "probe UDP uplink and TCP downlink without relaying data")
	flag.Parse()
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM([]byte(cfg.TLSCAPEM)) {
		log.Fatal("invalid embedded CA PEM")
	}
	timeout := 12 * time.Second
	if cfg.DialTimeout != "" {
		timeout, err = time.ParseDuration(cfg.DialTimeout)
		if err != nil || timeout <= 0 {
			log.Fatal("invalid dial_timeout")
		}
	}
	interval := 30 * time.Second
	if cfg.ProbeInterval != "" {
		interval, err = time.ParseDuration(cfg.ProbeInterval)
		if err != nil || interval <= 0 {
			log.Fatal("invalid probe_interval")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := &qimen.Client{Listen: cfg.Listen, HTTPListen: cfg.HTTPListen, Servers: cfg.Servers, Token: cfg.Token, TLSConfig: &tls.Config{RootCAs: roots, ServerName: cfg.TLSServerName, MinVersion: tls.VersionTLS13}, ProbeInterval: interval, DialTimeout: timeout}
	if *asymProbe {
		udp := cfg.AsymUDPAddress
		if udp == "" {
			udp = cfg.Servers[0]
		}
		rtt, err := qimen.ProbeAsymmetric(ctx, c.Servers[0], udp, c.Token, c.TLSConfig, timeout)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("asymmetric UDP uplink/TCP downlink verified: %s", rtt)
		return
	}
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
