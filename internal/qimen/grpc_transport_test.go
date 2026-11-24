package qimen

import (
 "bytes"
 "context"
 "crypto/tls"
 "io"
 "net"
 "testing"
 "time"
)

func TestLiveGRPCBidirectionalTCPRelay(t *testing.T){
 echo,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer echo.Close()
 go func(){for {
  socket,e:=echo.Accept();if e!=nil{return}
  go func(){defer socket.Close();_,_=io.Copy(socket,socket)}()
 }}()
 cert,roots:=testCert(t)
 endpoint:=pickAddr(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 server:=&Server{Listen:endpoint,UDPListen:endpoint,Token:"grpc-tunnel-secret",TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13},DialTimeout:time.Second}
 go func(){_ = server.Run(ctx)}()
 connectRetry(t,endpoint).Close()
 client:=&Client{Servers:[]string{endpoint},Token:"grpc-tunnel-secret",TLSConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13},DialTimeout:3*time.Second,TransportMode:"grpc"}
 for _,mode:=range []string{"grpc","auto"}{
  client.TransportMode=mode
  client.checkPaths(ctx)
  tun,e:=client.openTunnel(ctx,endpoint,echo.Addr().String())
  if e!=nil{t.Fatal(e)}
  _ = tun.SetDeadline(time.Now().Add(3*time.Second))
  payload:=[]byte("grpc streaming payload")
  if _,e=tun.Write(payload);e!=nil{t.Fatal(e)}
  got:=make([]byte,len(payload))
  if _,e=io.ReadFull(tun,got);e!=nil{t.Fatal(e)}
  if !bytes.Equal(payload,got){t.Fatalf("%s: mismatch",mode)}
  tun.Close()
 }
 client.closeGRPCConns()
}
