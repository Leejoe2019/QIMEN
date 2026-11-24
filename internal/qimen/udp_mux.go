package qimen

import (
 "context"
 "net"
 "time"
)

type quicDatagram struct {
 data []byte
 addr net.Addr
}

// quicPacketConn receives only packets not claimed by QIMEN's own HMAC probe
// protocols. Both transports use a single underlying UDP listener/port.
type quicPacketConn struct {
 net.PacketConn
 ctx context.Context
 packets chan quicDatagram
}

func newQUICPacketConn(ctx context.Context, pc net.PacketConn)*quicPacketConn{
 return &quicPacketConn{PacketConn:pc,ctx:ctx,packets:make(chan quicDatagram,512)}
}
func (m *quicPacketConn) offer(b []byte, addr net.Addr){
 cloned:=append([]byte(nil),b...)
 select {case m.packets<-quicDatagram{data:cloned,addr:addr}:default:}
}
func (m *quicPacketConn) ReadFrom(b []byte)(int,net.Addr,error){
 select {
 case <-m.ctx.Done():return 0,nil,net.ErrClosed
 case p:=<-m.packets:return copy(b,p.data),p.addr,nil
 }
}
func (m *quicPacketConn) Close()error{return nil}
func (m *quicPacketConn) SetDeadline(time.Time)error{return nil}
func (m *quicPacketConn) SetReadDeadline(time.Time)error{return nil}
func (m *quicPacketConn) SetWriteDeadline(time.Time)error{return nil}
