package qimen

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// ProbeAsymmetric proves UDP client->server reachability with the reply on
// a separately authenticated TLS/TCP channel. It is a control-plane experiment,
// not a UDP user-data transport.
func ProbeAsymmetric(ctx context.Context, tcpAddress, udpAddress, token string, tlsConfig *tls.Config, timeout time.Duration) (time.Duration, error) {
	if token == "" || tlsConfig == nil {
		return 0, errors.New("missing authentication")
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", tcpAddress)
	if err != nil {
		return 0, fmt.Errorf("TLS control: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 2))
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	if err = WriteMessage(conn, Message{Type: "asym", Target: hex.EncodeToString(nonce[:]), Token: token}); err != nil {
		return 0, err
	}
	reply, err := ReadMessage(conn)
	if err != nil {
		return 0, err
	}
	if !reply.OK {
		return 0, fmt.Errorf("control rejected: %s", reply.Error)
	}
	udp, err := net.DialTimeout("udp", udpAddress, timeout)
	if err != nil {
		return 0, err
	}
	defer udp.Close()
	packet := probePacket("QAX1", nonce, token)
	start := time.Now()
	// Limited redundancy makes the test robust to one-way packet loss.
	for i := 0; i < 4; i++ {
		if _, err = udp.Write(packet); err != nil {
			return 0, err
		}
		if i < 3 {
			time.Sleep(90 * time.Millisecond)
		}
	}
	reply, err = ReadMessage(conn)
	if err != nil {
		return 0, err
	}
	if !reply.OK {
		return 0, fmt.Errorf("no UDP uplink confirmed: %s", reply.Error)
	}
	return time.Since(start), nil
}
