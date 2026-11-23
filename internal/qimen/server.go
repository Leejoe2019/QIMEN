package qimen

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Server struct {
	Listen       string
	UDPListen    string
	TLSConfig    *tls.Config
	Token        string
	DialTimeout  time.Duration
	Logger       *log.Logger
	asymSessions sync.Map
}

func (s *Server) logger() *log.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return log.Default()
}

// Run binds TCP and UDP independently. UDP probe support is optional.
func (s *Server) Run(ctx context.Context) error {
	if s.Token == "" || s.TLSConfig == nil {
		return errors.New("server requires token and TLS configuration")
	}
	if s.Listen == "" {
		s.Listen = ":8443"
	}
	tcp, err := tls.Listen("tcp", s.Listen, s.TLSConfig)
	if err != nil {
		return err
	}
	defer tcp.Close()
	go func() { <-ctx.Done(); tcp.Close() }()
	if s.UDPListen != "-" {
		uaddr := s.UDPListen
		if uaddr == "" {
			uaddr = s.Listen
		}
		udp, e := net.ListenPacket("udp", uaddr)
		if e != nil {
			tcp.Close()
			return fmt.Errorf("UDP bind %s: %w", uaddr, e)
		}
		defer udp.Close()
		go func() { <-ctx.Done(); udp.Close() }()
		go s.serveUDP(ctx, udp)
		s.logger().Printf("QIMEN UDP probes listening on %s", udp.LocalAddr())
	}
	s.logger().Printf("QIMEN TLS relay listening on %s", tcp.Addr())
	for {
		conn, e := tcp.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go s.ServeConn(conn)
	}
}

func (s *Server) authorized(token string) bool {
	a, b := sha256.Sum256([]byte(s.Token)), sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	msg, err := ReadMessage(conn)
	if err != nil {
		return
	}
	if !s.authorized(msg.Token) {
		_ = WriteMessage(conn, Message{Error: "authentication failed"})
		return
	}
	if msg.Type == "asym" {
		nonce, e := hex.DecodeString(msg.Target)
		if e != nil || len(nonce) != 8 {
			_ = WriteMessage(conn, Message{Error: "invalid nonce"})
			return
		}
		ch := make(chan struct{}, 1)
		s.asymSessions.Store(string(nonce), ch)
		defer s.asymSessions.Delete(string(nonce))
		if e := WriteMessage(conn, Message{OK: true}); e != nil {
			return
		}
		select {
		case <-ch:
			_ = WriteMessage(conn, Message{OK: true})
		case <-time.After(7 * time.Second):
			_ = WriteMessage(conn, Message{Error: "no authenticated UDP uplink"})
		}
		return
	}
	if msg.Type == "ping" {
		_ = WriteMessage(conn, Message{OK: true})
		return
	}
	if msg.Type != "connect" {
		_ = WriteMessage(conn, Message{Error: "unsupported request"})
		return
	}
	if _, _, err := net.SplitHostPort(msg.Target); err != nil {
		_ = WriteMessage(conn, Message{Error: "invalid destination"})
		return
	}
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	remote, err := net.DialTimeout("tcp", msg.Target, timeout)
	if err != nil {
		_ = WriteMessage(conn, Message{Error: "connect failed: " + err.Error()})
		return
	}
	defer remote.Close()
	if err := WriteMessage(conn, Message{OK: true}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	bridge(conn, remote)
}

// bridge implements full duplex and propagates half-close for TCP sockets.
func bridge(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.SetWriteDeadline(time.Now())
		}
	}
	go copyHalf(left, right)
	go copyHalf(right, left)
	wg.Wait()
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if nonce, valid := verifyProbe(buf[:n], "QAX1", s.Token); valid {
			if value, found := s.asymSessions.Load(string(nonce[:])); found {
				select {
				case value.(chan struct{}) <- struct{}{}:
				default:
				}
			}
			continue
		}
		nonce, ok := verifyProbe(buf[:n], "QPR1", s.Token)
		if !ok {
			continue
		}
		response := probePacket("QPA1", nonce, s.Token)
		_, _ = pc.WriteTo(response, addr)
	}
}
