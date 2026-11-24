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
 "path/filepath"
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
		c.Listen = "0.0.0.0:43"
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

func migrateLegacy(path, dir string) error {
  if path=="" || dir=="" {return fmt.Errorf("--config and --migrate-legacy are required")}
  read := func(name string) (string,error) { b,e:=os.ReadFile(filepath.Join(dir,name));return string(b),e }
  token,e:=read("token");if e!=nil{return e}
  cert,e:=read("server.crt");if e!=nil{return e}
  key,e:=read("server.key");if e!=nil{return e}
  cfg:=config{Listen:"0.0.0.0:43", UDPListen:"0.0.0.0:43",Token:strings.TrimSpace(token),TLSCertificatePEM:cert,TLSPrivateKeyPEM:key,DialTimeout:"12s"}
  if _,e=tls.X509KeyPair([]byte(cert),[]byte(key));e!=nil{return fmt.Errorf("invalid local TLS pair: %w",e)}
  if cfg.Token==""{return fmt.Errorf("empty local token")}
  b,e:=json.MarshalIndent(cfg,"","  ");if e!=nil{return e}
  if _,e=os.Stat(path);e==nil{return fmt.Errorf("config exists, refusing overwrite")}
  f,e:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return e}
  defer f.Close()
  if _,e=f.Write(append(b,'\n'));e!=nil{return e}
  return f.Sync()
}

func main() {
	configFile := flag.String("config", "", "path to the single JSON configuration file")
 legacy := flag.String("migrate-legacy", "", "one-time on-device migration of legacy credentials; does not start server")
	flag.Parse()
 if *legacy!="" {if err:=migrateLegacy(*configFile,*legacy);err!=nil{log.Fatal(err)};log.Println("private config migrated");return}
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
