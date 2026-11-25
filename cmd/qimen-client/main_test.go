package main

import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)

func TestStableListenerConfig(t *testing.T){
 for _,tc:=range []struct{name,http,want,mode,up,down string; reject bool}{
  {"default","","127.0.0.1:1081","tcp","auto","auto",false},
  {"disabled","-","","grpc","auto","auto",false},
  {"reject split","-","","auto","quic-udp","tls-tcp",true},
 }{
  t.Run(tc.name,func(t *testing.T){
   path:=filepath.Join(t.TempDir(),"config.json")
   b,err:=json.Marshal(config{Token:"test",Servers:[]string{"127.0.0.1:43"},TLSCAPEM:"test",HTTPListen:tc.http,TransportMode:tc.mode,Uplink:tc.up,Downlink:tc.down})
   if err!=nil{t.Fatal(err)}
   if err=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
   cfg,err:=loadConfig(path)
   if tc.reject{if err==nil{t.Fatal("expected rejection")};return}
   if err!=nil{t.Fatal(err)}
   if cfg.Listen!="127.0.0.1:1080" || cfg.HTTPListen!=tc.want || cfg.TransportMode!=tc.mode{t.Fatalf("unexpected listener or transport settings: %s %s %s",cfg.Listen,cfg.HTTPListen,cfg.TransportMode)}
  })
 }
}
