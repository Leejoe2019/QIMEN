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
 "path/filepath"
 "strings"
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
func migrateLegacy(path,dir string) error {
 if path==""||dir=="" {return errors.New("--config and --migrate-legacy required")}
 read:=func(n string)(string,error){b,e:=os.ReadFile(filepath.Join(dir,n));return string(b),e}
 token,e:=read("token");if e!=nil{return e}
 cert,e:=read("server.crt");if e!=nil{return e}
 cfg:=config{Listen:"127.0.0.1:1080",HTTPListen:"127.0.0.1:1081",Servers:[]string{"107.173.181.158:18443"},Token:strings.TrimSpace(token),TLSCAPEM:cert,DialTimeout:"12s",ProbeInterval:"30s",AsymUDPAddress:"107.173.181.158:18443"}
 if cfg.Token==""{return errors.New("empty token")}
 if ok:=x509.NewCertPool().AppendCertsFromPEM([]byte(cert));!ok{return errors.New("invalid CA")}
 b,e:=json.MarshalIndent(cfg,"","  ");if e!=nil{return e}
 if _,e=os.Stat(path);e==nil{return errors.New("config exists; refusing overwrite")}
 f,e:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return e}
 defer f.Close()
 if _,e=f.Write(append(b,'\n'));e!=nil{return e}
 return f.Sync()
}

func main() {
	path := flag.String("config", "", "path to single JSON config file")
 legacy := flag.String("migrate-legacy", "", "one-time on-device migration of legacy credentials; does not start client")
	asymProbe := flag.Bool("asym-probe", false, "probe UDP uplink and TCP downlink without relaying data")
 bench := flag.String("bench", "", "authenticated benchmark: tcp-up, tcp-down or udp-up")
 benchSize := flag.Int64("bench-size", 524288, "TCP test bytes")
 benchCount := flag.Int("bench-count", 5000, "UDP synthetic data packets")
 benchRate := flag.Float64("bench-rate", 20, "UDP target rate in Mbps")
 benchClientCC := flag.String("bench-client-cc", "", "Linux per-socket client congestion control")
 benchServerCC := flag.String("bench-server-cc", "", "Linux per-socket server congestion control")
 benchNagle := flag.Bool("bench-nagle", false, "enable Nagle on TCP benchmark connections")
	flag.Parse()
 if *legacy!="" {if err:=migrateLegacy(*path,*legacy);err!=nil{log.Fatal(err)};log.Println("private config migrated");return}
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
	if *bench!="" {
        if *bench=="udp-up" {
            result,e:=qimen.BenchmarkUDPUp(ctx,c.Servers[0],c.Token,c.TLSConfig,timeout,*benchCount,*benchRate)
            b,_:=json.Marshal(result);log.Printf("BENCH %s",b);if e!=nil{log.Fatal(e)};return
        }
        if *bench!="tcp-up" && *bench!="tcp-down" {log.Fatal("invalid --bench mode")}
        direction:= "up";if *bench=="tcp-down"{direction="down"}
        result,e:=qimen.BenchmarkTCP(ctx,c.Servers[0],c.Token,c.TLSConfig,timeout,direction,*benchSize,*benchClientCC,*benchServerCC,*benchNagle)
        b,_:=json.Marshal(result);log.Printf("BENCH %s",b);if e!=nil{log.Fatal(e)};return
    }
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
