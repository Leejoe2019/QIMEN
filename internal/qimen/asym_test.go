package qimen

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

func TestAsymmetricUDPUpTLSDown(t *testing.T) {
	pair, roots := testCert(t)
	tcpAddress, udpAddress := pickAddr(t), pickAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{Listen: tcpAddress, UDPListen: udpAddress, Token: "asym-test-secret", TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}
	go func() { _ = server.Run(ctx) }()
	connectRetry(t, tcpAddress).Close()
	result, err := ProbeAsymmetric(ctx, tcpAddress, udpAddress, "asym-test-secret", &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result <= 0 {
		t.Fatalf("invalid RTT: %v", result)
	}
}
