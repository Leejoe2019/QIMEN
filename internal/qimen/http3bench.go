package qimen

import (
 "bytes"
 "context"
 "crypto/tls"
 "fmt"
 "io"
 "net"
 "net/http"
 "time"

 "github.com/quic-go/quic-go/http3"
)

func (s *Server) serveHTTP3(ctx context.Context, pc net.PacketConn){
 server:=&http3.Server{TLSConfig:s.TLSConfig.Clone(),Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="POST"||r.URL.Path!="/bench/echo" || !s.authorized(r.Header.Get("X-Qimen-Token")){
   http.Error(w,"unauthorized benchmark",http.StatusForbidden);return
  }
  body,err:=io.ReadAll(io.LimitReader(r.Body,2<<20))
  if err!=nil || len(body)>1<<20 {http.Error(w,"request too large",413);return}
  w.Header().Set("Content-Type","application/octet-stream")
  _,_=w.Write(body)
 })}
 go func(){<-ctx.Done();_ = server.Close()}()
 if err:=server.Serve(pc);err!=nil && ctx.Err()==nil{s.logger().Printf("http3 stopped: %v",err)}
}
func BenchmarkHTTP3(ctx context.Context,address,token string,tc *tls.Config, timeout time.Duration,size int)(BenchResult,error){
 result:=BenchResult{Protocol:"HTTP/3 over QUIC/UDP",Direction:"echo",Sent:int64(size)}
 if size<1||size>1<<20{return result,fmt.Errorf("HTTP3 size out of range")}
 tr:=&http3.Transport{TLSClientConfig:tc.Clone()}
 defer tr.Close()
 client:=&http.Client{Transport:tr,Timeout:timeout}
 data:=bytes.Repeat([]byte("h"),size)
 req,err:=http.NewRequestWithContext(ctx,"POST","https://"+address+"/bench/echo",bytes.NewReader(data))
 if err!=nil{return result,err}
 req.Header.Set("X-Qimen-Token",token)
 begin:=time.Now()
 resp,err:=client.Do(req)
 if err!=nil{return result,err}
 defer resp.Body.Close()
 if resp.StatusCode!=200{return result,fmt.Errorf("HTTP3 response HTTP %d",resp.StatusCode)}
 got,err:=io.ReadAll(io.LimitReader(resp.Body,int64(size+1)))
 if err!=nil{return result,err}
 if !bytes.Equal(got,data){return result,fmt.Errorf("HTTP3 data mismatch")}
 result.Received=int64(len(got))
 result.TransferMS=float64(time.Since(begin).Microseconds())/1000
 result.GoodputMbps=float64(result.Received*8)/result.TransferMS/1000
 return result,nil
}
