package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	gtp "github.com/wmnsk/go-gtp"
	gtpv2 "github.com/wmnsk/go-gtp/gtpv2"
	gtpv2ie "github.com/wmnsk/go-gtp/gtpv2/ie"
	gtpv2msg "github.com/wmnsk/go-gtp/gtpv2/message"
)

type cfg struct {
	local   string
	remote  string
	nodeIP  net.IP
	imsi    string
	msisdn  string
	apn     string
	pdnType string // ipv4|ipv6|ipv4v6
	ratType uint8
	ebi     uint8

	echoEvery time.Duration
	timeout   time.Duration
}

func main() {
	var c cfg
	var ratU, ebiU uint

	nodeIP := flag.String("node-ip", "127.0.0.1", "SGW IP to put inside F-TEID (IPv4)")
	flag.StringVar(&c.local, "local", "0.0.0.0:2123", "local bind ip:port")
	flag.StringVar(&c.remote, "remote", "", "PGW ip:port (e.g. 172.16.10.170:2123)")
	flag.StringVar(&c.imsi, "imsi", "001010123456789", "IMSI")
	flag.StringVar(&c.msisdn, "msisdn", "919999999999", "MSISDN (optional)")
	flag.StringVar(&c.apn, "apn", "internet", "APN")
	flag.StringVar(&c.pdnType, "pdn", "ipv4", "pdn: ipv4|ipv6|ipv4v6")
	flag.UintVar(&ratU, "rat", 6, "RAT-Type (e.g. 6=EUTRAN)")
	flag.UintVar(&ebiU, "ebi", 5, "EPS Bearer ID (default bearer usually 5)")
	flag.DurationVar(&c.echoEvery, "echo", 10*time.Second, "send Echo Request every duration")
	flag.DurationVar(&c.timeout, "timeout", 5*time.Second, "wait timeout for CSRsp")
	flag.Parse()

	if c.remote == "" {
		log.Fatalf("missing -remote")
	}
	if ratU > 255 || ebiU > 255 {
		log.Fatalf("rat/ebi must be <=255")
	}
	c.ratType = uint8(ratU)
	c.ebi = uint8(ebiU)

	c.nodeIP = net.ParseIP(*nodeIP).To4()
	if c.nodeIP == nil {
		log.Fatalf("invalid -node-ip %q (must be IPv4)", *nodeIP)
	}

	laddr, err := net.ResolveUDPAddr("udp", c.local)
	if err != nil {
		log.Fatalf("resolve local: %v", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", c.remote)
	if err != nil {
		log.Fatalf("resolve remote: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	log.Printf("S5/S8 SGW initiator up: local=%s remote=%s node-ip=%s", udpConn.LocalAddr(), raddr, c.nodeIP)

	// Channel to deliver CSRsp back to sender (match by seq).
	csRspCh := make(chan *gtpv2msg.CreateSessionResponse, 8)

	// RX loop: respond EchoReq, forward CSRsp to channel, log others.
	go rxLoop(udpConn, csRspCh)

	// Periodic Echo Requests
	go func() {
		t := time.NewTicker(c.echoEvery)
		defer t.Stop()
		for range t.C {
			seq := uint32(time.Now().UnixNano() & 0x00ffffff)

			req := gtpv2msg.NewEchoRequest(0, gtpv2ie.NewRecovery(1))
			req.SetSequenceNumber(seq)

			b, err := gtp.Marshal(req)
			if err != nil {
				log.Printf("echo req marshal err: %v", err)
				continue
			}
			_, _ = udpConn.WriteToUDP(b, raddr)
			log.Printf("tx EchoReq seq=%d -> %s", seq, raddr.String())
		}
	}()

	// Trigger Create Session
	if err := sendCreateSession(udpConn, raddr, c, csRspCh); err != nil {
		log.Fatalf("CreateSession failed: %v", err)
	}

	select {} // keep alive
}

func rxLoop(udpConn *net.UDPConn, csRspCh chan<- *gtpv2msg.CreateSessionResponse) {
	buf := make([]byte, 8192)
	for {
		n, peer, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("rx err: %v", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Parse any GTP message
		m, err := gtp.Parse(pkt)
		if err != nil {
			continue
		}

		v2m, ok := m.(gtpv2msg.Message)
		if !ok {
			continue
		}

		switch v2m.MessageType() {
		case gtpv2msg.MsgTypeEchoRequest:
			er := v2m.(*gtpv2msg.EchoRequest)
			resp := gtpv2msg.NewEchoResponse(0, gtpv2ie.NewRecovery(1))
			resp.SetSequenceNumber(er.Sequence())
			b, err := gtp.Marshal(resp)
			if err == nil {
				_, _ = udpConn.WriteToUDP(b, peer)
			}
			log.Printf("rx EchoReq from %s -> EchoResp (seq=%d)", peer.String(), er.Sequence())

		case gtpv2msg.MsgTypeEchoResponse:
			log.Printf("rx EchoResp from %s seq=%d", peer.String(), v2m.Sequence())

		case gtpv2msg.MsgTypeCreateSessionResponse:
			resp := v2m.(*gtpv2msg.CreateSessionResponse)
			select {
			case csRspCh <- resp:
			default:
			}
			log.Printf("rx CSRsp from %s teid=0x%08x seq=%d", peer.String(), resp.TEID(), resp.Sequence())

		default:
			log.Printf("rx msgType=%d from %s teid=0x%08x seq=%d", v2m.MessageType(), peer.String(), v2m.TEID(), v2m.Sequence())
		}
	}
}

func sendCreateSession(udpConn *net.UDPConn, raddr *net.UDPAddr, c cfg, csRspCh <-chan *gtpv2msg.CreateSessionResponse) error {
	seq := uint32(time.Now().UnixNano() & 0x00ffffff)

	// Sender F-TEID for CP (S5/S8 SGW GTP-C)
	localCTeid := randUint32()
	senderFTEID := gtpv2ie.NewFullyQualifiedTEID(
		gtpv2.IFTypeS5S8SGWGTPC,
		localCTeid,
		c.nodeIP.String(), // v4
		"",                // v6
	)
	senderFTEID.SetInstance(0)

	// PDN Type
	var pdnVal uint8
	switch strings.ToLower(c.pdnType) {
	case "ipv6":
		pdnVal = 2
	case "ipv4v6":
		pdnVal = 3
	default:
		pdnVal = 1
	}

	// Bearer Context (to be created) — instance 0
	bearerQoS := gtpv2ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)
	bearerCtx := gtpv2ie.NewBearerContext(
		gtpv2ie.NewEPSBearerID(c.ebi),
		bearerQoS,
	)
	bearerCtx.SetInstance(0)

	ies := []*gtpv2ie.IE{
		gtpv2ie.NewIMSI(c.imsi),
		gtpv2ie.NewAccessPointName(c.apn),
		gtpv2ie.NewRATType(c.ratType),
		gtpv2ie.NewPDNType(pdnVal),
		senderFTEID,
		bearerCtx,
	}
	if c.msisdn != "" {
		ies = append(ies, gtpv2ie.NewMSISDN(c.msisdn))
	}

	// Your version requires (teid, seq, ies...)
	req := gtpv2msg.NewCreateSessionRequest(0, seq, ies...)

	b, err := gtp.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal csr: %w", err)
	}

	if _, err := udpConn.WriteToUDP(b, raddr); err != nil {
		return fmt.Errorf("send csr: %w", err)
	}
	log.Printf("tx CSR seq=%d localCTeid=0x%08x -> %s", seq, localCTeid, raddr.String())

	// Wait for matching CSRsp
	deadline := time.NewTimer(c.timeout)
	defer deadline.Stop()

	for {
		select {
		case resp := <-csRspCh:
			if resp.Sequence() != seq {
				// ignore unrelated responses
				continue
			}
			log.Printf("CSR succeeded seq=%d (resp teid=0x%08x). Next: DeleteSession / ModifyBearer.", seq, resp.TEID())
			return nil
		case <-deadline.C:
			return fmt.Errorf("timeout waiting CSRsp (seq=%d)", seq)
		}
	}
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		return 1
	}
	return v
}
