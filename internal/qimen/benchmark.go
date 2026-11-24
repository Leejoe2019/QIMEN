package qimen

import (
 "context"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "encoding/binary"
 "encoding/hex"
 "fmt"
 "io"
 "net"
 "sync"
 "time"
)

const udpBenchmarkSize = 1200
const udpBenchmarkPayloadEnd = udpBenchmarkSize - sha256.Size
const maxBenchBytes = 32 << 20
const maxBenchPackets = 100000

type udpBenchSession struct {
 mu sync.Mutex
 count uint32
 received map[uint32]struct{}
}

type BenchResult struct {
 Protocol string `json:"protocol"`
 Direction string `json:"direction"`
 CC string `json:"cc,omitempty"`
 Nagle bool `json:"nagle"`
 Sent int64 `json:"sent"`
 Received int64 `json:"received"`
 SetupMS float64 `json:"setup_ms"`
 TransferMS float64 `json:"transfer_ms"`
 GoodputMbps float64 `json:"goodput_mbps"`
 LossPercent float64 `json:"loss_percent,omitempty"`
}

func (s *Server) serveBenchmark(conn net.Conn, m Message) bool {
 switch m.Type {
 case "bench_up", "bench_down":
  _ = conn.SetDeadline(time.Now().Add(90*time.Second))
  if m.Size <= 0 || m.Size > maxBenchBytes { _ = WriteMessage(conn, Message{Error:"invalid benchmark size"});return true }
  if m.CC != "" && m.CC != "cubic" && m.CC != "reno" && m.CC != "brutal" {
   _ = WriteMessage(conn, Message{Error:"unapproved TCP congestion control"});return true
  }
  if err:=setTCPOptions(conn,m.CC,m.Nagle);err!=nil{_ = WriteMessage(conn,Message{Error:err.Error()});return true}
  if err:=WriteMessage(conn,Message{OK:true});err!=nil{return true}
  if m.Type=="bench_up" {
   if _,err:=io.CopyN(io.Discard,conn,m.Size);err!=nil{return true}
   _ = WriteMessage(conn,Message{OK:true})
  } else {
   _,_ = io.CopyN(conn,zeroSource{},m.Size)
  }
  return true
 case "bench_udp":
  _ = conn.SetDeadline(time.Now().Add(35*time.Second))
  nonce,err:=hex.DecodeString(m.Target)
  if err!=nil || len(nonce)!=8 || m.Count<=0 || m.Count>maxBenchPackets {
   _ = WriteMessage(conn,Message{Error:"invalid UDP benchmark parameters"});return true
  }
  key:=string(nonce)
  state:=&udpBenchSession{count:uint32(m.Count),received:make(map[uint32]struct{})}
  s.udpBenchSessions.Store(key,state)
  defer s.udpBenchSessions.Delete(key)
  if err:=WriteMessage(conn,Message{OK:true});err!=nil{return true}
  done,err:=ReadMessage(conn)
  if err!=nil || done.Type!="bench_end"{return true}
  state.mu.Lock()
  n:=len(state.received)
  state.mu.Unlock()
  _ = WriteMessage(conn,Message{OK:true,Count:n})
  return true
 default:
  return false
 }
}

type zeroSource struct{}
func (zeroSource) Read(b []byte)(int,error){clear(b);return len(b),nil}

func (s *Server) receiveBenchUDP(buf []byte) {
 if len(buf)!=udpBenchmarkSize || string(buf[:4])!="QUB1"{return}
 raw,ok:=s.udpBenchSessions.Load(string(buf[4:12]));if !ok{return}
 mac:=hmac.New(sha256.New,[]byte(s.Token));_,_=mac.Write(buf[:udpBenchmarkPayloadEnd])
 if !hmac.Equal(buf[udpBenchmarkPayloadEnd:],mac.Sum(nil)){return}
 n:=binary.BigEndian.Uint32(buf[12:16])
 state:=raw.(*udpBenchSession)
 if n>=state.count{return}
 state.mu.Lock();state.received[n]=struct{}{};state.mu.Unlock()
}

func dialBenchTLS(ctx context.Context, address string, conf *tls.Config, timeout time.Duration) (net.Conn,error) {
 return (&tls.Dialer{NetDialer:&net.Dialer{Timeout:timeout},Config:conf}).DialContext(ctx,"tcp",address)
}

func BenchmarkTCP(ctx context.Context, address,token string, tlsConf *tls.Config, timeout time.Duration, direction string, size int64, localCC, serverCC string, nagle bool)(BenchResult,error) {
 res:=BenchResult{Protocol:"TLS/TCP",Direction:direction,CC:localCC+"/"+serverCC,Nagle:nagle,Sent:size}
 if direction!="up" && direction!="down"{return res,fmt.Errorf("unsupported direction")}
 start:=time.Now()
 conn,err:=dialBenchTLS(ctx,address,tlsConf,timeout);if err!=nil{return res,err}
 defer conn.Close()
 res.SetupMS=float64(time.Since(start).Microseconds())/1000
 if err:=setTCPOptions(conn,localCC,nagle);err!=nil{return res,err}
 _ = conn.SetDeadline(time.Now().Add(90*time.Second))
 typ:="bench_"+direction
 if err=WriteMessage(conn,Message{Type:typ,Token:token,Size:size,CC:serverCC,Nagle:nagle});err!=nil{return res,err}
 ack,err:=ReadMessage(conn)
 if err!=nil{return res,err}
 if !ack.OK{return res,fmt.Errorf("benchmark rejected: %s",ack.Error)}
 began:=time.Now()
 if direction=="up"{
  _,err=io.CopyN(conn,zeroSource{},size)
  if err==nil {
   var confirm Message
   confirm,err=ReadMessage(conn)
   if err==nil && !confirm.OK{err=fmt.Errorf("upload not confirmed: %s",confirm.Error)}
  }
 }else{_,err=io.CopyN(io.Discard,conn,size)}
 res.TransferMS=float64(time.Since(began).Microseconds())/1000
 if err==nil {res.Received=size;res.GoodputMbps=float64(size*8)/res.TransferMS/1000}
 return res,err
}

func BenchmarkUDPUp(ctx context.Context, address,token string,tlsConf *tls.Config,timeout time.Duration,count int,rateMbps float64)(BenchResult,error){
 return BenchmarkUDPUpWithOrder(ctx,address,token,tlsConf,timeout,count,rateMbps,"normal")
}
func BenchmarkUDPUpWithOrder(ctx context.Context, address,token string,tlsConf *tls.Config,timeout time.Duration,count int,rateMbps float64,order string)(BenchResult,error){
 if order!="normal" && order!="reverse8" {return BenchResult{},fmt.Errorf("invalid benchmark order")}

 res:=BenchResult{Protocol:"QUB1/HMAC/UDP + TCP-feedback ("+order+")",Direction:"up",Sent:int64(count*udpBenchmarkSize)}
 if count<=0||count>maxBenchPackets||rateMbps<=0||rateMbps>500{return res,fmt.Errorf("invalid rate or packet count")}
 began:=time.Now()
 conn,err:=dialBenchTLS(ctx,address,tlsConf,timeout);if err!=nil{return res,err}
 defer conn.Close()
 res.SetupMS=float64(time.Since(began).Microseconds())/1000
 _=conn.SetDeadline(time.Now().Add(35*time.Second))
 var nonce [8]byte
 if _,err=rand.Read(nonce[:]);err!=nil{return res,err}
 if err=WriteMessage(conn,Message{Type:"bench_udp",Target:hex.EncodeToString(nonce[:]),Token:token,Count:count});err!=nil{return res,err}
 ack,err:=ReadMessage(conn)
 if err!=nil{return res,err}
 if !ack.OK{return res,fmt.Errorf("UDP benchmark rejected: %s",ack.Error)}
 udp,err:=net.DialTimeout("udp",address,timeout);if err!=nil{return res,err}
 defer udp.Close()
 packet:=make([]byte,udpBenchmarkSize)
 copy(packet[:4],"QUB1")
 copy(packet[4:12],nonce[:])
 interval:=time.Duration(float64(udpBenchmarkSize*8)/rateMbps*1000)
 transferStart:=time.Now()
 for i:=0;i<count;i++{
  if err=ctx.Err();err!=nil{return res,err}
  wait:=transferStart.Add(time.Duration(i)*interval).Sub(time.Now())
  if wait>0{time.Sleep(wait)}
  seq:=i
  if order=="reverse8"{
   base:=(i/8)*8
   width:=8
   if count-base<width {width=count-base}
   seq=base+(width-1)-(i-base)
  }
  binary.BigEndian.PutUint32(packet[12:16],uint32(seq))
  h:=hmac.New(sha256.New,[]byte(token));_,_=h.Write(packet[:udpBenchmarkPayloadEnd]);copy(packet[udpBenchmarkPayloadEnd:],h.Sum(nil))
  if _,err=udp.Write(packet);err!=nil{return res,err}
 }
 res.TransferMS=float64(time.Since(transferStart).Microseconds())/1000
 time.Sleep(350*time.Millisecond)
 if err=WriteMessage(conn,Message{Type:"bench_end",Token:token});err!=nil{return res,err}
 ack,err=ReadMessage(conn);if err!=nil{return res,err}
 if !ack.OK{return res,fmt.Errorf("UDP bench feedback: %s",ack.Error)}
 res.Received=int64(ack.Count*udpBenchmarkSize)
 res.LossPercent=float64(count-ack.Count)*100/float64(count)
 if res.TransferMS>0{res.GoodputMbps=float64(res.Received*8)/res.TransferMS/1000}
 return res,nil
}
