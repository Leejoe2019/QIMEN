package qimen

import (
 "bytes"
 "context"
 "crypto/tls"
 "fmt"
 "net"
 "net/http"
 "strings"
 "time"

 "golang.org/x/net/http2"
 grpcgo "google.golang.org/grpc"
 "google.golang.org/grpc/credentials"
 "google.golang.org/grpc/metadata"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

type echoBenchmarkService interface {
 Echo(context.Context,*wrapperspb.BytesValue)(*wrapperspb.BytesValue,error)
}
type echoBenchmarkServer struct{}
func (echoBenchmarkServer)Echo(_ context.Context,request *wrapperspb.BytesValue)(*wrapperspb.BytesValue,error){
 if len(request.Value)>1<<20{return nil,fmt.Errorf("echo too large")}
 return request,nil
}

func (s *Server) serveGRPCConn(conn net.Conn){
 service:=grpcgo.NewServer(grpcgo.MaxRecvMsgSize(2<<20))
 service.RegisterService(&grpcgo.ServiceDesc{
  ServiceName:"qimen.Bench",HandlerType:(*echoBenchmarkService)(nil),
  Methods:[]grpcgo.MethodDesc{{MethodName:"Echo",Handler:func(impl interface{},ctx context.Context,decode func(interface{})error,interceptor grpcgo.UnaryServerInterceptor)(interface{},error){
   input:=new(wrapperspb.BytesValue)
   if err:=decode(input);err!=nil{return nil,err}
   if interceptor==nil{return impl.(echoBenchmarkService).Echo(ctx,input)}
   info:=&grpcgo.UnaryServerInfo{Server:impl,FullMethod:"/qimen.Bench/Echo"}
   handle:=func(ctx context.Context,value interface{})(interface{},error){return impl.(echoBenchmarkService).Echo(ctx,value.(*wrapperspb.BytesValue))}
   return interceptor(ctx,input,info,handle)
  }}},
 },echoBenchmarkServer{})
 handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  auth:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ")
  if r.Method!="POST" || r.URL.Path!="/qimen.Bench/Echo" || !s.authorized(auth){
   http.Error(w,"unauthorized gRPC benchmark",http.StatusForbidden);return
  }
  service.ServeHTTP(w,r)
 })
 (&http2.Server{}).ServeConn(conn,&http2.ServeConnOpts{Handler:handler})
 service.Stop()
}

func BenchmarkGRPC(ctx context.Context,address,token string,tc *tls.Config,timeout time.Duration,size int)(BenchResult,error){
 result:=BenchResult{Protocol:"gRPC/HTTP2/TLS/TCP",Direction:"echo",Sent:int64(size)}
 if size<1||size>1<<20{return result,fmt.Errorf("gRPC size out of range")}
 conf:=tc.Clone();conf.NextProtos=[]string{"h2"}
 dialCtx,cancel:=context.WithTimeout(ctx,timeout);defer cancel()
 start:=time.Now()
 conn,err:=grpcgo.DialContext(dialCtx,address,grpcgo.WithTransportCredentials(credentials.NewTLS(conf)),grpcgo.WithBlock(),
   grpcgo.WithDefaultCallOptions(grpcgo.MaxCallRecvMsgSize(2<<20)))
 if err!=nil{return result,err}
 defer conn.Close()
 result.SetupMS=float64(time.Since(start).Microseconds())/1000
 echoCtx,cancelEcho:=context.WithTimeout(ctx,timeout);defer cancelEcho()
 echoCtx=metadata.AppendToOutgoingContext(echoCtx,"authorization","Bearer "+token)
 payload:=bytes.Repeat([]byte("g"),size)
 input:=&wrapperspb.BytesValue{Value:payload}
 output:=new(wrapperspb.BytesValue)
 begin:=time.Now()
 if err:=conn.Invoke(echoCtx,"/qimen.Bench/Echo",input,output);err!=nil{return result,err}
 result.TransferMS=float64(time.Since(begin).Microseconds())/1000
 if !bytes.Equal(output.Value,payload){return result,fmt.Errorf("gRPC response mismatch")}
 result.Received=int64(len(output.Value))
 result.GoodputMbps=float64(result.Received*8)/result.TransferMS/1000
 return result,nil
}
