package qimen

import (
 "context"
 "crypto/tls"
 "testing"
 "time"
)

func TestOnePortHTTP3AndGRPC(t *testing.T){
 pair,roots:=testCert(t)
 address:=pickAddr(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 s:=&Server{Listen:address,UDPListen:address,Token:"multi-proto-test",TLSConfig:&tls.Config{Certificates:[]tls.Certificate{pair},MinVersion:tls.VersionTLS13}}
 done:=make(chan error,1)
 go func(){done<-s.Run(ctx)}()
 connectRetry(t,address).Close()
 tc:=&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13}
 for _,fn:=range []struct{name string;run func(context.Context,string,string,*tls.Config,time.Duration,int)(BenchResult,error)}{
  {"gRPC",BenchmarkGRPC},{"HTTP3",BenchmarkHTTP3},
 }{
  res,err:=fn.run(ctx,address,"multi-proto-test",tc,4*time.Second,512)
  if err!=nil{t.Fatalf("%s: %v",fn.name,err)}
  if res.Received!=512{t.Fatalf("%s returned %d",fn.name,res.Received)}
 }
 cancel()
 select {case err:=<-done:if err!=nil{t.Fatal(err)};case <-time.After(2*time.Second):t.Fatal("server failed to shutdown")}
}
