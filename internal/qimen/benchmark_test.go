package qimen

import (
 "context"
 "crypto/tls"
 "testing"
 "time"
)

func TestIntegratedBenchmarksOnePort(t *testing.T) {
 pair,roots:=testCert(t)
 address:=pickAddr(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 server:=&Server{Listen:address,UDPListen:address,Token:"bench-test-only",TLSConfig:&tls.Config{Certificates:[]tls.Certificate{pair},MinVersion:tls.VersionTLS13}}
 done:=make(chan error,1)
 go func(){done<-server.Run(ctx)}()
 connectRetry(t,address).Close()
 tc:=&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13}
 for _,direction:=range []string{"up","down"}{
  res,err:=BenchmarkTCP(ctx,address,"bench-test-only",tc,2*time.Second,direction,16384,"","",false)
  if err!=nil{t.Fatalf("%s failed: %v",direction,err)}
  if res.Received!=16384 || res.GoodputMbps<=0 {t.Fatalf("unexpected %s result %#v",direction,res)}
 }
 udp,err:=BenchmarkUDPUp(ctx,address,"bench-test-only",tc,2*time.Second,100,4)
 if err!=nil{t.Fatal(err)}
 if udp.Received!=100*1200 || udp.LossPercent!=0 {t.Fatalf("UDP loss in loopback: %#v",udp)}
 cancel()
 select {case err:=<-done:if err!=nil{t.Fatal(err)};case <-time.After(2*time.Second):t.Fatal("server did not close")}
}
