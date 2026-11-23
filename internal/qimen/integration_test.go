package qimen

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: key}, roots
}

func pickAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func connectRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cannot connect to %s", addr)
	return nil
}

func TestMessages(t *testing.T) {
	var b bytes.Buffer
	original := Message{Type: "connect", Target: "example.com:443", Token: "abc"}
	if err := WriteMessage(&b, original); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatalf("got %#v", got)
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{255, 255})); err == nil {
		t.Fatal("expected reject oversize")
	}
}

func TestProbeMAC(t *testing.T) {
	var nonce [8]byte
	copy(nonce[:], "random12")
	p := probePacket("QPR1", nonce, "secret")
	if _, ok := verifyProbe(p, "QPR1", "secret"); !ok {
		t.Fatal("valid probe rejected")
	}
	if _, ok := verifyProbe(p, "QPR1", "wrong"); ok {
		t.Fatal("wrong key accepted")
	}
	p[4] ^= 1
	if _, ok := verifyProbe(p, "QPR1", "secret"); ok {
		t.Fatal("tampered probe accepted")
	}
}

func TestSOCKSRelayAndUDPProbe(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var buf [1024]byte
				for {
					n, e := conn.Read(buf[:])
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	pair, roots := testCert(t)
	serverAddr := pickAddr(t)
	socksAddr := pickAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{Listen: serverAddr, UDPListen: serverAddr, Token: "strong-test-token", TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx) }()
	_ = connectRetry(t, serverAddr).Close()
	rtt, err := ProbeUDP(serverAddr, "strong-test-token", time.Second)
	if err != nil {
		t.Fatalf("UDP probe failed: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("invalid rtt %v", rtt)
	}
	if _, err := ProbeUDP(serverAddr, "wrong", 50*time.Millisecond); err == nil {
		t.Fatal("wrong token UDP probe accepted")
	}
	client := &Client{Listen: socksAddr, Servers: []string{serverAddr}, Token: "strong-test-token", TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ProbeInterval: time.Hour, DialTimeout: time.Second}
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()
	socks := connectRetry(t, socksAddr)
	defer socks.Close()
	_ = socks.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := socks.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := readFull(socks, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("SOCKS auth response %v", reply)
	}
	host, portStr, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := socks.Write(req); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err := readFull(socks, response); err != nil {
		t.Fatal(err)
	}
	if response[1] != 0 {
		t.Fatalf("SOCKS connect rejected: %v", response)
	}
	payload := []byte("qimen end-to-end relay")
	if _, err := socks.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := readFull(socks, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}
	cancel()
	socks.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not terminate")
	}
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not terminate")
	}
}

func readFull(c net.Conn, b []byte) (int, error) { return io.ReadFull(c, b) }
