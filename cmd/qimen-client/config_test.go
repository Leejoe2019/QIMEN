package main

import (
 "os"
 "path/filepath"
 "testing"
)
func TestConfigAcceptsOrdinaryFilePermissions(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"qimen.json")
 if err:=os.WriteFile(path,[]byte(`{"servers":["example.com:43"],"token":"test-only","tls_ca_pem":"test-placeholder"}`),0644);err!=nil{t.Fatal(err)}
 if _,err:=loadConfig(path);err!=nil{t.Fatal(err)}
}
