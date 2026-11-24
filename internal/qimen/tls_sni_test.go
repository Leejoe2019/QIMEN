package qimen

import (
 "bytes"
 "crypto/tls"
 "encoding/binary"
 "io"
 "net"
 "testing"
)

func clientHelloRecord(t *testing.T,name string) []byte {
 t.Helper()
 local,peer:=net.Pipe()
 defer local.Close()
 defer peer.Close()
 done:=make(chan struct{})
 go func(){defer close(done); _ = tls.Client(local,&tls.Config{ServerName:name,MinVersion:tls.VersionTLS13}).Handshake()}()
 header:=make([]byte,5)
 if _,err:=io.ReadFull(peer,header);err!=nil{t.Fatal(err)}
 if header[0]!=22{t.Fatal("expected TLS handshake record")}
 n:=int(binary.BigEndian.Uint16(header[3:5]))
 if n<16||n>16384{t.Fatalf("unexpected record size %d",n)}
 record:=make([]byte,n)
 if _,err:=io.ReadFull(peer,record);err!=nil{t.Fatal(err)}
 peer.Close()
 <-done
 return record
}

// Using an IP SAN and an IP server name omits SNI while keeping ordinary
// certificate verification. This is NOT Encrypted Client Hello (ECH).
func TestNoPlainSNIWithIPAddress(t *testing.T){
 ipHello:=clientHelloRecord(t,"127.0.0.1")
 if bytes.Contains(ipHello,[]byte("127.0.0.1")){t.Fatal("IP literal unexpectedly present in ClientHello")}
 dnsHello:=clientHelloRecord(t,"qimen.example")
 if !bytes.Contains(dnsHello,[]byte("qimen.example")){t.Fatal("test control: expected DNS SNI not present")}
}
