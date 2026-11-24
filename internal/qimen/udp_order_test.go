package qimen

import (
 "context"
 "crypto/tls"
 "testing"
 "time"
)

func TestOutOfOrderAuthenticatedUDPFragments(t *testing.T){
 cert,roots:=testCert(t)
 endpoint:=pickAddr(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 server:=&Server{Listen:endpoint,UDPListen:endpoint,Token:"udp-order-test",TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13}}
 go func(){_ = server.Run(ctx)}()
 connectRetry(t,endpoint).Close()
 result,err:=BenchmarkUDPUpWithOrder(ctx,endpoint,"udp-order-test",&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13},3*time.Second,101,3.2,"reverse8")
 if err!=nil{t.Fatal(err)}
 if result.Received!=101*udpBenchmarkSize || result.LossPercent!=0{t.Fatalf("unexpected result: %#v",result)}
}
