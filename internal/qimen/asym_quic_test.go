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

func TestAsymmetricQUICRelay(t *testing.T){
 echo,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer echo.Close()
 go func(){c,e:=echo.Accept();if e==nil{defer c.Close();_,_=io.Copy(c,c)}}()
 pair,roots:=testCert(t);address:=pickAddr(t)
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 s:=&Server{Listen:address,UDPListen:address,Token:"test-split-quic",TLSConfig:&tls.Config{Certificates:[]tls.Certificate{pair},MinVersion:tls.VersionTLS13}}
 done:=make(chan error,1);go func(){done<-s.Run(ctx)}()
 connectRetry(t,address).Close()
 c:=&Client{TLSConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS13},Token:"test-split-quic",DialTimeout:10*time.Second,Uplink:"quic-udp",Downlink:"tls-tcp",UDPCopies:2}
 dialCtx,stop:=context.WithTimeout(ctx,10*time.Second);defer stop()
 conn,err:=c.openTunnel(dialCtx,address,echo.Addr().String());if err!=nil{t.Fatal(err)}
 defer conn.Close()
 if _,ok:=conn.(*asymQUICStream);!ok{t.Fatal("did not use asymmetric QUIC")}
 _=conn.SetDeadline(time.Now().Add(8*time.Second))
 data:=bytes.Repeat([]byte("split-quic-data"),4096)
 written:=make(chan error,1)
 go func(){_,e:=conn.Write(data);written<-e}()
 got:=make([]byte,len(data));if _,err=io.ReadFull(conn,got);err!=nil{t.Fatal(err)}
 if err:=<-written;err!=nil{t.Fatal(err)}
 if !bytes.Equal(data,got){t.Fatal("echo corrupted")}
 conn.Close()
 cancel()
 select{case e:=<-done:if e!=nil{t.Fatal(e)};case <-time.After(3*time.Second):t.Fatal("server shutdown timed out")}
}
