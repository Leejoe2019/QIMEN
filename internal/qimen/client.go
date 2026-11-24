package qimen

import (
	"context"
	grpcgo "google.golang.org/grpc"
	"crypto/tls"
 "crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

type Client struct {
	Listen        string
	HTTPListen    string
	Servers       []string
	TLSConfig     *tls.Config
	Token         string
	ProbeInterval time.Duration
	DialTimeout   time.Duration
	Logger        *log.Logger
 TransportMode string
 HelloSplit string
 grpcMu sync.Mutex
 grpcConns map[string]*grpcgo.ClientConn
	mu            sync.RWMutex
	stats         map[string]PathStat
}

type PathStat struct {
	TCP                        time.Duration
 GRPC                       time.Duration
	UDP                        time.Duration
	TCPAvailable, UDPAvailable bool
 GRPCAvailable bool
	Checked                    time.Time
}

func (c *Client) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

func (c *Client) Run(ctx context.Context) error {
	if c.Token == "" || c.TLSConfig == nil || len(c.Servers) == 0 {
		return errors.New("client requires token, TLS, and at least one server")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:1080"
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = 15 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	c.mu.Lock()
	c.stats = make(map[string]PathStat)
	c.mu.Unlock()
	c.checkPaths(ctx)
	go func(){<-ctx.Done();c.closeGRPCConns()}()
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	go c.probeLoop(ctx)
	if c.HTTPListen != "" {
		go func() {
			if err := c.serveHTTP(ctx); err != nil && ctx.Err() == nil {
				c.logger().Printf("HTTP proxy error: %v", err)
			}
		}()
	}
	c.logger().Printf("QIMEN SOCKS5 listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go c.handleSOCKS(conn)
	}
}

func (c *Client) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(c.ProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkPaths(ctx)
		}
	}
}

func (c *Client) checkPaths(ctx context.Context) {
 c.mu.Lock()
 if c.stats==nil{c.stats=make(map[string]PathStat)}
 c.mu.Unlock()
	var wg sync.WaitGroup
	for _, srv := range c.Servers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			tcp, err := c.dialTunnel(ctx, srv, "ping", "")
			st := PathStat{Checked: time.Now()}
			if err == nil {
				st.TCPAvailable = true
				st.TCP = time.Since(tcp.start)
                tcp.conn.Close()
            }
            if c.TransportMode!="tcp" {
             began:=time.Now()
             if probe,e:=c.dialGRPCTunnel(ctx,srv,"PING");e==nil {
              st.GRPCAvailable=true
              st.GRPC=time.Since(began)
              probe.Close()
             }
            }
			udpTimeout := c.DialTimeout
			if udpTimeout > 1500*time.Millisecond {
				udpTimeout = 1500 * time.Millisecond
			}
			udp, uerr := ProbeUDP(srv, c.Token, udpTimeout)
			if uerr == nil {
				st.UDPAvailable = true
				st.UDP = udp
			}
			c.mu.Lock()
			c.stats[srv] = st
			c.mu.Unlock()
			c.logger().Printf("path %s TCP=%v/%s GRPC=%v/%s UDP=%v/%s", srv, st.TCPAvailable, st.TCP,st.GRPCAvailable,st.GRPC, st.UDPAvailable, st.UDP)
		}(srv)
	}
	wg.Wait()
}

type tunnel struct {
	conn  net.Conn
	start time.Time
}

func (c *Client) dialTunnel(ctx context.Context, server, typ, target string)(t tunnel,err error){
 mode:=c.HelloSplit
 if mode==""{mode="adaptive"}
 attempts:=[]string{"off"}
 if mode=="split1"||mode=="split5"{attempts=[]string{mode}}
 if mode=="adaptive"{attempts=[]string{"off","split5","split1"}}
 timeout:=c.DialTimeout
 if timeout<=0{timeout=6*time.Second}
 per:=timeout/time.Duration(len(attempts))
 if per<1500*time.Millisecond{per=1500*time.Millisecond}
 for _,candidate:=range attempts{
  if ctx.Err()!=nil{return t,ctx.Err()}
  tryCtx,cancel:=context.WithTimeout(ctx,per)
  began:=time.Now()
  conn,e:=dialTLSWithSplit(tryCtx,server,c.TLSConfig,per,candidate)
  cancel()
  if e!=nil{
   err=e
   var certErr *tls.CertificateVerificationError
   var unknownAuth x509.UnknownAuthorityError
   if errors.As(e,&certErr)||errors.As(e,&unknownAuth){return t,e}
   continue
  }
  _ = conn.SetDeadline(time.Now().Add(c.DialTimeout))
  e=WriteMessage(conn,Message{Type:typ,Target:target,Token:c.Token})
  var reply Message
  if e==nil{reply,e=ReadMessage(conn)}
  if e!=nil{_ = conn.Close();err=e;continue}
  if !reply.OK{_ = conn.Close();return t,fmt.Errorf("server: %s",reply.Error)}
  _ = conn.SetDeadline(time.Time{})
  return tunnel{conn:conn,start:began},nil
 }
 return t,err
}

func (c *Client) rankedServers() []string {
	a := append([]string(nil), c.Servers...)
	c.mu.RLock()
	defer c.mu.RUnlock()
	sort.SliceStable(a, func(i, j int) bool {
		x, y := c.stats[a[i]], c.stats[a[j]]
		if x.TCPAvailable != y.TCPAvailable {
			return x.TCPAvailable
		}
		if !x.TCPAvailable {
			return false
		}
		return x.TCP < y.TCP
	})
	return a
}

// handleSOCKS implements SOCKS5 CONNECT, intentionally without local client authentication.
// Bind Listen to loopback unless protected by an external access-control layer.
func (c *Client) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0 {
			hasNoAuth = true
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 {
		socksReply(conn, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return
		}
		if n[0] == 0 {
			socksReply(conn, 8)
			return
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(conn, 8)
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:])))
	var remote net.Conn
	for _, server := range c.rankedServers() {
		ctx, cancel := context.WithTimeout(context.Background(), c.DialTimeout)
		remoteConn, err := c.openTunnel(ctx, server, target)
        cancel()
        if err == nil {
            remote = remoteConn
			break
		}
		c.logger().Printf("tunnel %s failed: %v", server, err)
	}
	if remote == nil {
		socksReply(conn, 5)
		return
	}
	defer remote.Close()
	if err := socksReply(conn, 0); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	bridge(conn, remote)
}

func socksReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
