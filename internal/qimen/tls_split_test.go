package qimen

import (
 "context"
 "crypto/tls"
 "net"
 "testing"
 "time"
)

func TestTLSHelloSplitModesPreserveTLS13(t *testing.T){
 cert,roots:=testCert(t)
 for _,cutoff:=range []int{1,5}{
  left,right:=net.Pipe()
  done:=make(chan error,1)
  go func(){
   defer right.Close()
   server:=tls.Server(right,&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13})
   done<-server.Handshake()
  }()
  ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second)
  wire:=&helloSplitConn{Conn:left,cutoff:cutoff}
  client:=tls.Client(wire,&tls.Config{RootCAs:roots,ServerName:"127.0.0.1",MinVersion:tls.VersionTLS13})
  err:=client.HandshakeContext(ctx)
  if err!=nil{t.Fatalf("split at %d: %v",cutoff,err)}
  if !wire.splitDone{t.Fatalf("split %d was not applied",cutoff)}
  _ = client.Close()
  select{case e:=<-done:if e!=nil{t.Fatal(e)};case <-time.After(time.Second):t.Fatal("server stuck")}
  cancel()
 }
}
