package main

import (
 "os"
 "path/filepath"
 "testing"
)
func TestConfigAcceptsOrdinaryFilePermissions(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"qimen.json")
 if err:=os.WriteFile(path,[]byte(`{"listen":":43","token":"test-only","tls_certificate_pem":"test-placeholder","tls_private_key_pem":"test-placeholder"}`),0644);err!=nil{t.Fatal(err)}
 if _,err:=loadConfig(path);err!=nil{t.Fatal(err)}
}
