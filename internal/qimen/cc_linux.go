//go:build linux
package qimen
import (
 "crypto/tls"
 "fmt"
 "net"
 "syscall"
)
func setTCPOptions(conn net.Conn, cc string, nagle bool) error {
 if t,ok:=conn.(*tls.Conn);ok {conn=t.NetConn()}
 tcp,ok:=conn.(*net.TCPConn);if !ok {return fmt.Errorf("not TCP")}
 if err:=tcp.SetNoDelay(!nagle);err!=nil{return err}
 if cc==""{return nil}
 r,err:=tcp.SyscallConn();if err!=nil{return err}
 var setErr error
 err=r.Control(func(fd uintptr){setErr=syscall.SetsockoptString(int(fd),syscall.IPPROTO_TCP,syscall.TCP_CONGESTION,cc)})
 if err!=nil{return err}
 return setErr
}
