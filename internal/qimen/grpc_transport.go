package qimen

import (
 "context"
 "errors"
 "io"
 "net"
 "sync"
 "time"

 grpcgo "google.golang.org/grpc"
 "google.golang.org/grpc/connectivity"
 "google.golang.org/grpc/credentials"
 "google.golang.org/grpc/metadata"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

var tunnelStreamDescription=&grpcgo.StreamDesc{StreamName:"Pipe",ClientStreams:true,ServerStreams:true}

func (c *Client) closeGRPCConns(){
 c.grpcMu.Lock()
 defer c.grpcMu.Unlock()
 for _,cc:=range c.grpcConns{_ = cc.Close()}
 c.grpcConns=nil
}
func (c *Client) grpcConnection(ctx context.Context,server string)(*grpcgo.ClientConn,error){
 c.grpcMu.Lock()
 if c.grpcConns!=nil{
  if cc:=c.grpcConns[server];cc!=nil&&cc.GetState()!=connectivity.Shutdown {
   c.grpcMu.Unlock();return cc,nil
  }
 }
 c.grpcMu.Unlock()
 tc:=c.TLSConfig.Clone()
 tc.NextProtos=[]string{"h2"}
 timeout:=c.DialTimeout
 if timeout<=0{timeout=5*time.Second}
 dialCtx,cancel:=context.WithTimeout(ctx,timeout)
 defer cancel()
 cc,err:=grpcgo.DialContext(dialCtx,server,
   grpcgo.WithTransportCredentials(credentials.NewTLS(tc)),
   grpcgo.WithBlock(),
   grpcgo.WithDefaultCallOptions(grpcgo.MaxCallRecvMsgSize(1<<20),grpcgo.MaxCallSendMsgSize(1<<20)))
 if err!=nil{return nil,err}
 c.grpcMu.Lock()
 if c.grpcConns==nil{c.grpcConns=make(map[string]*grpcgo.ClientConn)}
 if existing:=c.grpcConns[server];existing!=nil && existing.GetState()!=connectivity.Shutdown {
  c.grpcMu.Unlock();cc.Close();return existing,nil
 }
 c.grpcConns[server]=cc
 c.grpcMu.Unlock()
 return cc,nil
}

type grpcTunnelConn struct {
 stream grpcgo.ClientStream
 cancel context.CancelFunc
 readMu sync.Mutex
 pending []byte
 closeOnce sync.Once
}
func (g *grpcTunnelConn) Read(p []byte)(int,error){
 g.readMu.Lock();defer g.readMu.Unlock()
 if len(p)==0{return 0,nil}
 for len(g.pending)==0{
  message:=new(wrapperspb.BytesValue)
  if err:=g.stream.RecvMsg(message);err!=nil{return 0,err}
  g.pending=message.Value
 }
 n:=copy(p,g.pending)
 g.pending=g.pending[n:]
 return n,nil
}
func (g *grpcTunnelConn) Write(p []byte)(int,error){
 written:=0
 for written<len(p){
  end:=written+16*1024
  if end>len(p){end=len(p)}
  part:=append([]byte(nil),p[written:end]...)
  if err:=g.stream.SendMsg(&wrapperspb.BytesValue{Value:part});err!=nil{return written,err}
  written=end
 }
 return written,nil
}
func (g *grpcTunnelConn) CloseWrite()error{return g.stream.CloseSend()}
func (g *grpcTunnelConn) Close()error{
 g.closeOnce.Do(func(){g.cancel()})
 return nil
}
func (g *grpcTunnelConn) LocalAddr()net.Addr{return grpcDummyAddr("qimen-local")}
func (g *grpcTunnelConn) RemoteAddr()net.Addr{return grpcDummyAddr("qimen-grpc")}
func (g *grpcTunnelConn) SetDeadline(time.Time)error{return nil}
func (g *grpcTunnelConn) SetReadDeadline(time.Time)error{return nil}
func (g *grpcTunnelConn) SetWriteDeadline(time.Time)error{return nil}
type grpcDummyAddr string
func (a grpcDummyAddr)Network()string{return "grpc"}
func (a grpcDummyAddr)String()string{return string(a)}

func (c *Client) dialGRPCTunnel(ctx context.Context,server,target string)(net.Conn,error){
 cc,err:=c.grpcConnection(ctx,server)
 if err!=nil{return nil,err}
 streamCtx,cancel:=context.WithCancel(context.Background())
 streamCtx=metadata.AppendToOutgoingContext(streamCtx,"authorization","Bearer "+c.Token)
 // Bound initial handshake without closing the long-lived stream once accepted.
 timeout:=c.DialTimeout
 if timeout<=0{timeout=5*time.Second}
 timer:=time.AfterFunc(timeout,cancel)
 stream,err:=cc.NewStream(streamCtx,tunnelStreamDescription,"/qimen.Tunnel/Pipe")
 if err!=nil {timer.Stop();cancel();return nil,err}
 err=stream.SendMsg(&wrapperspb.BytesValue{Value:[]byte(target)})
 if err!=nil{timer.Stop();cancel();return nil,err}
 reply:=new(wrapperspb.BytesValue)
 err=stream.RecvMsg(reply)
 timer.Stop()
 if err!=nil{cancel();return nil,err}
 if string(reply.Value)!="OK"{cancel();return nil,errors.New("gRPC relay rejected target")}
 if target=="PING"{_ = stream.CloseSend()}
 return &grpcTunnelConn{stream:stream,cancel:cancel},nil
}

func (c *Client) openTunnel(ctx context.Context,server,target string)(net.Conn,error){
 mode:=c.TransportMode
 if mode==""{mode="auto"}
 grpcFirst:=mode=="grpc"
 if mode=="auto"{
  c.mu.RLock()
  stat:=c.stats[server]
  c.mu.RUnlock()
  grpcFirst=stat.GRPCAvailable && (!stat.TCPAvailable||stat.GRPC<stat.TCP)
 }
 methods:=[]string{"tcp","grpc"}
 if mode=="tcp"{methods=[]string{"tcp"}
 }else if mode=="grpc"{methods=[]string{"grpc"}
 }else if grpcFirst{methods=[]string{"grpc","tcp"}}
 var last error
 for _,method:=range methods{
  if method=="grpc" {
   conn,e:=c.dialGRPCTunnel(ctx,server,target)
   if e==nil{return conn,nil}
   last=e
   c.logger().Printf("gRPC tunnel failed: %v",e)
  }else{
   tun,e:=c.dialTunnel(ctx,server,"connect",target)
   if e==nil{return tun.conn,nil}
   last=e
  }
 }
 if last==nil{last=io.EOF}
 return nil,last
}

var _ net.Conn=(*grpcTunnelConn)(nil)
