go mod tidy

go build -o gtp-init


.\gtp-init 
  -local 0.0.0.0:0 
  -remote 10.10.10.20:2123 
  -node-ip 10.10.10.11 
  -imsi 001010123456789 
  -msisdn 919999999999 
  -apn internet 
  -pdn ipv4 
  -rat 6 
  -ebi 5 
  -echo 10s 
  -timeout 5s

[root@localhost go-gtp_sim]# ./gtp-init  -local 172.16.10.174:2123 -remote 172.16.10.170:2123 -node-ip 172.16.10.174 -imsi 001010123456789 -msisdn 919999999999 -apn internet -pdn ipv4 -rat 6 -ebi 5 -echo 10s  -timeout 5s
2026/01/08 17:10:34 S5/S8 SGW initiator up: local=172.16.10.174:2123 remote=172.16.10.170:2123 node-ip=172.16.10.174
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x48 pc=0x540015]

goroutine 1 [running]:
github.com/wmnsk/go-gtp/gtpv2.(*Conn).WriteTo(...)
	/root/go/pkg/mod/github.com/wmnsk/go-gtp@v0.8.12/gtpv2/conn.go:228
main.sendCreateSession(0xc0000862a0, {0x5ec428, 0xc0000a0c30}, {{0x7ffcddf501e4, 0x12}, {0x7ffcddf501ff, 0x12}, {0xc0000980ac, 0x4, 0x4}, ...}, ...)
	/root/go-gtp_sim/main.go:205 +0x375
main.main()
	/root/go-gtp_sim/main.go:144 +0x977
[root@localhost go-gtp_sim]# 


