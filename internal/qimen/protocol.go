// Package qimen implements the initial authenticated transport and path probes.
package qimen

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const maxMessage = 4096

// Control messages are small length-prefixed JSON objects inside an authenticated TLS connection.
type Message struct {
	Type   string `json:"type,omitempty"`
	Target string `json:"target,omitempty"`
	Token  string `json:"token,omitempty"`
	OK     bool   `json:"ok,omitempty"`
	Error  string `json:"error,omitempty"`
}

func WriteMessage(w io.Writer, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return errors.New("control message too large")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(b)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func ReadMessage(r io.Reader) (Message, error) {
	var m Message
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return m, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > maxMessage {
		return m, errors.New("invalid control message size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return m, err
	}
	err := json.Unmarshal(b, &m)
	return m, err
}

const probeSize = 4 + 8 + sha256.Size

// A probe response has the same length as the request, avoiding amplification.
func probePacket(prefix string, nonce [8]byte, key string) []byte {
	p := make([]byte, probeSize)
	copy(p[:4], prefix)
	copy(p[4:12], nonce[:])
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(p[:12])
	copy(p[12:], mac.Sum(nil))
	return p
}

func verifyProbe(p []byte, prefix, key string) ([8]byte, bool) {
	var nonce [8]byte
	if len(p) != probeSize || string(p[:4]) != prefix {
		return nonce, false
	}
	copy(nonce[:], p[4:12])
	expected := probePacket(prefix, nonce, key)
	return nonce, hmac.Equal(p, expected)
}

// ProbeUDP measures whether authenticated UDP round trips are possible.
func ProbeUDP(address, key string, timeout time.Duration) (time.Duration, error) {
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	p := probePacket("QPR1", nonce, key)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := conn.Write(p); err != nil {
		return 0, err
	}
	buf := make([]byte, probeSize)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	got, valid := verifyProbe(buf[:n], "QPA1", key)
	if !valid || got != nonce {
		return 0, fmt.Errorf("invalid UDP probe response")
	}
	return time.Since(start), nil
}
