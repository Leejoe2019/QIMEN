package qimen

import (
 "context"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "sync"
 "time"

 quic "github.com/quic-go/quic-go"
)

const asymQUICHeader = 32
const asymQUICMaxPacket = 1500
const asymQUICALPN = "qimen-asym-quic-v1"

// This is a QUIC transport over a split packet path, NOT Hysteria2, HTTP/3
// or REALITY wire compatibility. An authenticated outer TLS connection carries
// return datagrams. Actual QUIC Initial and subsequent packets travel in
// authenticated UDP envelopes on the forward path. QUIC handles loss recovery.
type asymQUICPacketConn struct {
 tcp net.Conn
 udp *net.UDPConn // client only
 local,peer net.Addr
 id [12]byte
 key []byte
 copies int
 rx chan []byte
 done chan struct{}
 once sync.Once
 mu sync.Mutex
 wake chan struct{}
 rd time.Time
 writeMu sync.Mutex
}

func newAsymQUICPacketConn(tcp net.Conn,udp *net.UDPConn,local,peer net.Addr,id [12]byte,key []byte,copies int)*asymQUICPacketConn{
 if copies<1||copies>3{copies=1}
 return &asymQUICPacketConn{tcp:tcp,udp:udp,local:local,peer:peer,id:id,key:key,copies:copies,rx:make(chan []byte,512),done:make(chan struct{}),wake:make(chan struct{})}
}
func (p *asymQUICPacketConn) offer(b []byte){
 data:=append([]byte(nil),b...)
 select{case <-p.done:return;default:}
 select{case p.rx<-data:case <-p.done:default:} // QUIC retransmits on receive queue pressure
}
func (p *asymQUICPacketConn) Close()error{
 p.once.Do(func(){close(p.done);_ = p.tcp.Close();if p.udp!=nil{_ = p.udp.Close()}})
 return nil
}
func (p *asymQUICPacketConn) LocalAddr()net.Addr{return p.local}
func (p *asymQUICPacketConn) SetDeadline(t time.Time)error{
 if err:=p.SetReadDeadline(t);err!=nil{return err};return p.SetWriteDeadline(t)
}
func (p *asymQUICPacketConn) SetReadDeadline(t time.Time)error{
 p.mu.Lock();defer p.mu.Unlock()
 p.rd=t;close(p.wake);p.wake=make(chan struct{});return nil
}
func (p *asymQUICPacketConn) SetWriteDeadline(t time.Time)error{
 if p.udp!=nil{return p.udp.SetWriteDeadline(t)}
 return p.tcp.SetWriteDeadline(t)
}
func (p *asymQUICPacketConn) ReadFrom(b []byte)(int,net.Addr,error){
 for{
  p.mu.Lock();rd,wake:=p.rd,p.wake;p.mu.Unlock()
  var timer *time.Timer
  var timeout <-chan time.Time
  if !rd.IsZero(){
   if !rd.After(time.Now()){return 0,nil,os.ErrDeadlineExceeded}
   timer=time.NewTimer(time.Until(rd));timeout=timer.C
  }
  select{
  case <-p.done:if timer!=nil{timer.Stop()};return 0,nil,net.ErrClosed
  case <-wake:if timer!=nil{timer.Stop()};continue
  case <-timeout:return 0,nil,os.ErrDeadlineExceeded
  case data:=<-p.rx:if timer!=nil{timer.Stop()};return copy(b,data),p.peer,nil
  }
 }
}
func asymQUICMAC(key,header,payload []byte)[]byte{
 h:=hmac.New(sha256.New,key);h.Write(header);h.Write(payload);return h.Sum(nil)[:16]
}
func (p *asymQUICPacketConn) WriteTo(b []byte,_ net.Addr)(int,error){
 if len(b)==0||len(b)>asymQUICMaxPacket{return 0,errors.New("invalid QUIC packet size")}
 select{case <-p.done:return 0,net.ErrClosed;default:}
 p.writeMu.Lock();defer p.writeMu.Unlock()
 if p.udp!=nil{
  frame:=make([]byte,asymQUICHeader+len(b))
  copy(frame[:4],"QAQ1");copy(frame[4:16],p.id[:]);copy(frame[32:],b)
  copy(frame[16:32],asymQUICMAC(p.key,frame[:16],b))
  for i:=0;i<p.copies;i++{if _,err:=p.udp.Write(frame);err!=nil{return 0,err}}
  return len(b),nil
 }
 frame:=make([]byte,2+len(b))
 binary.BigEndian.PutUint16(frame[:2],uint16(len(b)));copy(frame[2:],b)
 n,err:=p.tcp.Write(frame)
 if err!=nil{return 0,err}
 if n!=len(frame){return 0,io.ErrShortWrite}
 return len(b),nil
}
func (p *asymQUICPacketConn) readReturn(){
 defer p.Close()
 for{
  var h [2]byte
  if _,err:=io.ReadFull(p.tcp,h[:]);err!=nil{return}
  size:=int(binary.BigEndian.Uint16(h[:]))
  if size<1||size>asymQUICMaxPacket{return}
  packet:=make([]byte,size)
  if _,err:=io.ReadFull(p.tcp,packet);err!=nil{return}
  p.offer(packet)
 }
}
func (s *Server) receiveAsymQUIC(packet []byte){
 if len(packet)<=asymQUICHeader||len(packet)>asymQUICHeader+asymQUICMaxPacket{return}
 session,ok:=s.asymQUICSessions.Load(string(packet[4:16]));if !ok{return}
 pc:=session.(*asymQUICPacketConn)
 if !hmac.Equal(packet[16:32],asymQUICMAC(pc.key,packet[:16],packet[32:])){return}
 pc.offer(packet[32:])
}
func asymQUICKey(conn net.Conn,id [12]byte)([]byte,error){
 tc,ok:=conn.(*tls.Conn);if !ok{return nil,errors.New("TLS required")}
 st:=tc.ConnectionState()
 return st.ExportKeyingMaterial("EXPORTER-QIMEN-asymmetric-quic-v1",id[:],32)
}
func asymQUICSettings()*quic.Config{
 return &quic.Config{HandshakeIdleTimeout:8*time.Second,MaxIdleTimeout:90*time.Second,
 KeepAlivePeriod:20*time.Second,MaxIncomingStreams:1,MaxIncomingUniStreams:-1,
 InitialPacketSize:1200,DisablePathMTUDiscovery:true}
}
func (s *Server) serveAsymQUIC(conn net.Conn){
 if s.UDPListen=="-"||s.asymQUICSlots==nil{_ = WriteMessage(conn,Message{Error:"asymmetric QUIC disabled"});return}
 select{case s.asymQUICSlots<-struct{}{}:defer func(){<-s.asymQUICSlots}();default:_=WriteMessage(conn,Message{Error:"asymmetric QUIC busy"});return}
 var id [12]byte
 if _,err:=rand.Read(id[:]);err!=nil{return}
 key,err:=asymQUICKey(conn,id);if err!=nil{return}
 addr:=s.UDPListen;if addr==""{addr=s.Listen}
 local,err:=net.ResolveUDPAddr("udp",addr);if err!=nil{return}
 peer,err:=net.ResolveUDPAddr("udp",conn.RemoteAddr().String());if err!=nil{return}
 pc:=newAsymQUICPacketConn(conn,nil,local,peer,id,key,1)
 defer pc.Close()
 s.asymQUICSessions.Store(string(id[:]),pc);defer s.asymQUICSessions.Delete(string(id[:]))
 tc:=s.TLSConfig.Clone();tc.NextProtos=[]string{asymQUICALPN}
 listener,err:=quic.Listen(pc,tc,asymQUICSettings());if err!=nil{_ = WriteMessage(conn,Message{Error:"QUIC listener failed"});return}
 defer listener.Close()
 if err:=WriteMessage(conn,Message{OK:true,Target:hex.EncodeToString(id[:])});err!=nil{return}
 _ = conn.SetDeadline(time.Time{})
 go func(){_,_=io.Copy(io.Discard,conn);pc.Close()}()
 ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second);defer cancel()
 q,err:=listener.Accept(ctx);if err!=nil{return}
 defer q.CloseWithError(0,"")
 stream,err:=q.AcceptStream(ctx);if err!=nil{return}
 _=stream.SetDeadline(time.Now().Add(12*time.Second))
 msg,err:=ReadMessage(stream);if err!=nil||msg.Type!="connect"{return}
 if _,_,err:=net.SplitHostPort(msg.Target);err!=nil{_ = WriteMessage(stream,Message{Error:"invalid destination"});return}
 timeout:=s.DialTimeout;if timeout<=0{timeout=10*time.Second}
 remote,err:=net.DialTimeout("tcp",msg.Target,timeout)
 if err!=nil{_ = WriteMessage(stream,Message{Error:"connect failed: "+err.Error()});return}
 defer remote.Close()
 if err:=WriteMessage(stream,Message{OK:true});err!=nil{return}
 _=stream.SetDeadline(time.Time{})
 bridge(&asymQUICStream{Stream:stream,q:q,pc:pc},remote)
}

type asymQUICStream struct{
 quic.Stream
 q quic.Connection
 pc *asymQUICPacketConn
 once sync.Once
}
func (s *asymQUICStream) LocalAddr()net.Addr{return s.pc.LocalAddr()}
func (s *asymQUICStream) RemoteAddr()net.Addr{return s.pc.peer}
func (s *asymQUICStream) CloseWrite()error{return s.Stream.Close()}
func (s *asymQUICStream) Close()error{
 s.once.Do(func(){_ = s.Stream.Close();s.Stream.CancelRead(0);_ = s.q.CloseWithError(0,"");_ = s.pc.Close()})
 return nil
}
func (c *Client) dialAsymQUIC(ctx context.Context,server,target string)(net.Conn,error){
 timeout:=c.DialTimeout;if timeout<=0{timeout=12*time.Second}
 outer,err:=dialTLSWithSplit(ctx,server,c.TLSConfig,timeout,"off");if err!=nil{return nil,err}
 success:=false;defer func(){if !success{_ = outer.Close()}}()
 _=outer.SetDeadline(time.Now().Add(timeout))
 if err:=WriteMessage(outer,Message{Type:"asym_quic",Token:c.Token});err!=nil{return nil,err}
 reply,err:=ReadMessage(outer);if err!=nil{return nil,err}
 if !reply.OK{return nil,fmt.Errorf("asymmetric QUIC rejected: %s",reply.Error)}
 raw,err:=hex.DecodeString(reply.Target);if err!=nil||len(raw)!=12{return nil,errors.New("invalid session identifier")}
 var id [12]byte;copy(id[:],raw)
 key,err:=asymQUICKey(outer,id);if err!=nil{return nil,err}
 addr,err:=net.ResolveUDPAddr("udp",server);if err!=nil{return nil,err}
 udp,err:=net.DialUDP("udp",nil,addr);if err!=nil{return nil,err}
 pc:=newAsymQUICPacketConn(outer,udp,udp.LocalAddr(),addr,id,key,c.UDPCopies)
 defer func(){if !success{pc.Close()}}()
 _=outer.SetDeadline(time.Time{});go pc.readReturn()
 tc:=c.TLSConfig.Clone();tc.NextProtos=[]string{asymQUICALPN}
 if tc.ServerName==""{tc.ServerName,_,err=net.SplitHostPort(server);if err!=nil{return nil,err}}
 q,err:=quic.Dial(ctx,pc,addr,tc,asymQUICSettings());if err!=nil{return nil,err}
 defer func(){if !success{_ = q.CloseWithError(0,"")}}()
 stream,err:=q.OpenStreamSync(ctx);if err!=nil{return nil,err}
 if dl,ok:=ctx.Deadline();ok{_=stream.SetDeadline(dl)}else{_=stream.SetDeadline(time.Now().Add(timeout))}
 if err:=WriteMessage(stream,Message{Type:"connect",Target:target});err!=nil{return nil,err}
 reply,err=ReadMessage(stream);if err!=nil{return nil,err}
 if !reply.OK{return nil,fmt.Errorf("server: %s",reply.Error)}
 _=stream.SetDeadline(time.Time{})
 success=true
 return &asymQUICStream{Stream:stream,q:q,pc:pc},nil
}

var _ net.PacketConn=(*asymQUICPacketConn)(nil)
var _ net.Conn=(*asymQUICStream)(nil)
