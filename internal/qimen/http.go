package qimen

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func (c *Client) establish(ctx context.Context, target string) (net.Conn, error) {
	var last error
	for _, server := range c.rankedServers() {
		tryCtx, cancel := context.WithTimeout(ctx, c.DialTimeout)
		tun, err := c.dialTunnel(tryCtx, server, "connect", target)
		cancel()
		if err == nil {
			return tun.conn, nil
		}
		last = err
		c.logger().Printf("HTTP tunnel %s: %v", server, err)
	}
	if last == nil {
		last = errors.New("no upstream server")
	}
	return nil, last
}

func (c *Client) serveHTTP(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.HTTPListen)
	if err != nil {
		return err
	}
	defer ln.Close()
	server := &http.Server{Handler: http.HandlerFunc(c.handleHTTP), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(closeCtx)
	}()
	c.logger().Printf("QIMEN HTTP proxy listening on %s", ln.Addr())
	err = server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (c *Client) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		target := r.Host
		if _, _, err := net.SplitHostPort(target); err != nil {
			target = net.JoinHostPort(target, "443")
		}
		remote, err := c.establish(r.Context(), target)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			remote.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		local, rw, err := hj.Hijack()
		if err != nil {
			remote.Close()
			return
		}
		defer local.Close()
		defer remote.Close()
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := rw.Flush(); err != nil {
			return
		}
		// Buffered bytes must not be dropped when the client pipelines data after CONNECT.
		if rw.Reader.Buffered() != 0 {
			_, _ = io.CopyN(remote, rw, int64(rw.Reader.Buffered()))
		}
		bridge(local, remote)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "absolute http URL required", http.StatusBadRequest)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	stripHopHeaders(outReq.Header)
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return c.establish(ctx, address)
		},
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	stripHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func stripHopHeaders(h http.Header) {
	for _, token := range strings.Split(h.Get("Connection"), ",") {
		if k := strings.TrimSpace(token); k != "" {
			h.Del(k)
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}
