package qimen

import (
 "context"
 "crypto/tls"
 "strings"
 "testing"
 "time"
)

// Stable builds intentionally reject the experimental transport rather than
// starting a QUIC listener. The TCP and gRPC integration tests remain enabled.
func TestStableRejectsAsymmetricQUIC(t *testing.T) {
 pair, roots := testCert(t)
 address := pickAddr(t)
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 s := &Server{Listen:address, UDPListen:address, Token:"test-stable", TLSConfig:&tls.Config{Certificates:[]tls.Certificate{pair}, MinVersion:tls.VersionTLS13}}
 done := make(chan error,1)
 go func(){done<-s.Run(ctx)}()
 connectRetry(t,address).Close()
 c := &Client{TLSConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13}, Token:"test-stable", DialTimeout:2*time.Second, Uplink:"quic-udp", Downlink:"tls-tcp", AsymFallback:true}
 if conn,err:=c.openTunnel(ctx,address,"127.0.0.1:1");err==nil{
  conn.Close()
  t.Fatal("experimental client transport accepted")
 }
 for i:=0;i<3;i++{
  conn,err:=tls.Dial("tcp",address,c.TLSConfig)
  if err!=nil{t.Fatal(err)}
  _=conn.SetDeadline(time.Now().Add(2*time.Second))
  if err=WriteMessage(conn,Message{Type:"asym_quic",Token:c.Token});err!=nil{conn.Close();t.Fatal(err)}
  reply,err:=ReadMessage(conn)
  conn.Close()
  if err!=nil || reply.OK || !strings.Contains(reply.Error,"disabled"){t.Fatalf("unexpected response: %+v %v",reply,err)}
 }
 cancel()
 select{case e:=<-done:if e!=nil{t.Fatal(e)};case <-time.After(3*time.Second):t.Fatal("server shutdown timed out")}
}
