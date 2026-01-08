go mod tidy
go build -o gtp-init


.\gtp-init `
  -local 0.0.0.0:0 `
  -remote 10.10.10.20:2123 `
  -node-ip 10.10.10.11 `
  -imsi 001010123456789 `
  -msisdn 919999999999 `
  -apn internet `
  -pdn ipv4 `
  -rat 6 `
  -ebi 5 `
  -echo 10s `
  -timeout 5s
