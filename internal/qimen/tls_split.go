package qimen

import (
 "context"
 "crypto/tls"
 "errors"
 "io"
 "net"
 "sync"
 "time"
)

// helloSplitConn changes only the write boundaries of the first TLS
// ClientHello. It does not forge TCP sequence numbers or modify TLS bytes,
// and it is not a substitute for ECH or REALITY.
type helloSplitConn struct {
 net.Conn
 cutoff int
 mu sync.Mutex
 tried bool
 splitDone bool
}
func (w *helloSplitConn) Write(b []byte)(int,error){
 w.mu.Lock()
 split:=!w.tried && w.cutoff>0 && len(b)>w.cutoff && len(b)>6 && b[0]==22 && b[5]==1
 if split {w.tried=true;w.splitDone=true}
 w.mu.Unlock()
 if !split{return w.Conn.Write(b)}
 first,err:=w.Conn.Write(b[:w.cutoff])
 if err!=nil{return first,err}
 if first!=w.cutoff{return first,io.ErrShortWrite}
 second,err:=w.Conn.Write(b[w.cutoff:])
 return first+second,err
}

func dialTLSWithSplit(ctx context.Context,server string,config *tls.Config,timeout time.Duration,mode string)(net.Conn,error){
 raw,err:=(&net.Dialer{Timeout:timeout}).DialContext(ctx,"tcp",server)
 if err!=nil{return nil,err}
 if tcp,ok:=raw.(*net.TCPConn);ok{_ = tcp.SetNoDelay(true)}
 name,_,err:=net.SplitHostPort(server)
 if err!=nil{raw.Close();return nil,err}
 cfg:=config.Clone()
 if cfg.ServerName==""{cfg.ServerName=name}
 split:=0
 switch mode {
 case "","off":
 case "split1":split=1
 case "split5":split=5
 default:raw.Close();return nil,errors.New("unknown ClientHello split mode")
 }
 var conn net.Conn=raw
 if split>0 {conn=&helloSplitConn{Conn:raw,cutoff:split}}
 tlsConn:=tls.Client(conn,cfg)
 if err:=tlsConn.HandshakeContext(ctx);err!=nil{tlsConn.Close();return nil,err}
 return tlsConn,nil
}
