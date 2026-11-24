//go:build !linux
package qimen
import ("crypto/tls";"fmt";"net")
func setTCPOptions(conn net.Conn,cc string,nagle bool)error{
 if t,ok:=conn.(*tls.Conn);ok{conn=t.NetConn()}
 if tcp,ok:=conn.(*net.TCPConn);ok{_ = tcp.SetNoDelay(!nagle)}
 if cc!="" {return fmt.Errorf("TCP congestion control selection only implemented on Linux")}
 return nil
}
