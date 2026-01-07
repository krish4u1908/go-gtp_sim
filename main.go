package main

import (
	"context"
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
	flag.StringVar(&c.local, "local", "0.0.0.0:0", "local bind ip:port (0=ephemeral)")
	flag.StringVar(&c.remote, "remote", "", "PGW ip:port (e.g. 10.10.10.20:2123)")
	flag.StringVar(&c.imsi, "imsi", "001010123456789", "IMSI")
	flag.StringVar(&c.msisdn, "msisdn", "919999999999", "MSISDN (optional)")
	flag.StringVar(&c.apn, "apn", "internet", "APN")
	flag.StringVar(&c.pdnType, "pdn", "ipv4", "pdn: ipv4|ipv6|ipv4v6")
	flag.UintVar(&ratU, "rat", 6, "RAT-Type (e.g. 6=EUTRAN)")
	flag.UintVar(&ebiU, "ebi", 5, "EPS Bearer ID (default bearer usually 5)")
	flag.DurationVar(&c.echoEvery, "echo", 10*time.Second, "send Echo Request every duration")
	flag.DurationVar(&c.timeout, "timeout", 3*time.Second, "wait timeout for CSRsp")
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

	// S5/S8 SGW GTP-C interface conn
	conn := gtpv2.NewConn(laddr, gtpv2.IFTypeS5S8SGWGTPC, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to receive CSRsp for our seq
	csRspCh := make(chan *gtpv2msg.CreateSessionResponse, 1)

	// Handle Echo Request -> Echo Response
	conn.AddHandler(gtpv2msg.MsgTypeEchoRequest, func(cn *gtpv2.Conn, sender net.Addr, msg gtpv2msg.Message) error {
		er := msg.(*gtpv2msg.EchoRequest)

		// NewEchoResponse(teid, ies...)  (NO seq param in this go-gtp version)
		resp := gtpv2msg.NewEchoResponse(0, gtpv2ie.NewRecovery(1))
		resp.SetSequenceNumber(er.Sequence())

		b, err := gtp.Marshal(resp)
		if err != nil {
			log.Printf("echo resp marshal err: %v", err)
			return nil
		}
		_, _ = cn.WriteTo(b, sender)
		log.Printf("rx EchoReq from %s -> EchoResp (seq=%d)", sender.String(), er.Sequence())
		return nil
	})

	// Capture Create Session Response
	conn.AddHandler(gtpv2msg.MsgTypeCreateSessionResponse, func(cn *gtpv2.Conn, sender net.Addr, msg gtpv2msg.Message) error {
		resp := msg.(*gtpv2msg.CreateSessionResponse)
		select {
		case csRspCh <- resp:
		default:
		}
		log.Printf("rx CSRsp from %s teid=0x%08x seq=%d", sender.String(), resp.TEID(), resp.Sequence())
		return nil
	})

	// Start RX loop
	go func() {
		if err := conn.ListenAndServe(ctx); err != nil {
			log.Printf("ListenAndServe stopped: %v", err)
		}
	}()

	log.Printf("S5/S8 SGW initiator up: local=%s remote=%s node-ip=%s", laddr, raddr, c.nodeIP)

	// Periodic Echo Requests (keepalive)
	go func() {
		t := time.NewTicker(c.echoEvery)
		defer t.Stop()
		for range t.C {
			seq := uint32(time.Now().UnixNano() & 0x00ffffff)

			// NewEchoRequest(teid, ies...)  (NO seq param)
			req := gtpv2msg.NewEchoRequest(0, gtpv2ie.NewRecovery(1))
			req.SetSequenceNumber(seq)

			b, err := gtp.Marshal(req)
			if err != nil {
				log.Printf("echo req marshal err: %v", err)
				continue
			}
			_, _ = conn.WriteTo(b, raddr)
			log.Printf("tx EchoReq seq=%d -> %s", seq, raddr.String())
		}
	}()

	// Trigger one Create Session Request
	if err := sendCreateSession(conn, raddr, c, csRspCh); err != nil {
		log.Fatalf("CreateSession failed: %v", err)
	}

	select {} // keep alive
}
func sendCreateSession(conn *gtpv2.Conn, raddr net.Addr, c cfg, csRspCh <-chan *gtpv2msg.CreateSessionResponse) error {
	seq := uint32(time.Now().UnixNano() & 0x00ffffff)

	// Sender F-TEID for CP (S5/S8 SGW GTP-C)
	localCTeid := randUint32()

	// Your go-gtp expects IPv4/IPv6 as strings here
	senderFTEID := gtpv2ie.NewFullyQualifiedTEID(
		gtpv2.IFTypeS5S8SGWGTPC,
		localCTeid,
		c.nodeIP.String(), // v4 string
		"",                // v6 string
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

	// Minimal bearer context: EBI + BearerQoS (tune for your PGW expectations)
	bearerQoS := gtpv2ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)

	bearerCtx := gtpv2ie.NewBearerContext(
		gtpv2ie.NewEPSBearerID(c.ebi),
		bearerQoS,
	)
	bearerCtx.SetInstance(0) // "to be created"

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

	// In your version: NewCreateSessionRequest(teid, seq, ies...)
	req := gtpv2msg.NewCreateSessionRequest(0, seq, ies...)

	b, err := gtp.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal csr: %w", err)
	}

	if _, err := conn.WriteTo(b, raddr); err != nil {
		return fmt.Errorf("send csr: %w", err)
	}
	log.Printf("tx CSR seq=%d localCTeid=0x%08x -> %s", seq, localCTeid, raddr.String())

	// Wait for CSRsp (best-effort)
	select {
	case resp := <-csRspCh:
		if resp.Sequence() != seq {
			log.Printf("got CSRsp but seq mismatch: want=%d got=%d", seq, resp.Sequence())
			return nil
		}
		log.Printf("CSR succeeded (seq=%d). Extend next: Delete Session / Modify Bearer.", seq)
		return nil
	case <-time.After(c.timeout):
		return fmt.Errorf("timeout waiting CSRsp (seq=%d)", seq)
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
