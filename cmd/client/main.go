// Command client connects a Windows machine to the VPN server over TLS:
// creates a wintun adapter, routes traffic through the tunnel.
// Requires administrator privileges.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"personalvpn/internal/config"
	"personalvpn/internal/protocol"
	"personalvpn/internal/tun"
)

// defaultGateway finds the current default IPv4 route (before we change anything).
func defaultGateway() (winipcfg.LUID, netip.Addr, error) {
	rows, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(windows.AF_INET))
	if err != nil {
		return 0, netip.Addr{}, err
	}
	best := uint32(^uint32(0))
	var gw netip.Addr
	var luid winipcfg.LUID
	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		next := row.NextHop.Addr()
		if !next.IsValid() || !next.Is4() {
			continue
		}
		metric := row.Metric
		if metric < best {
			best = metric
			gw = next
			luid = row.InterfaceLUID
		}
	}
	if !gw.IsValid() {
		return 0, netip.Addr{}, fmt.Errorf("no default IPv4 route found")
	}
	return luid, gw, nil
}

// dialTLS connects to the server with a Chrome-like TLS fingerprint
// and verifies the pinned certificate fingerprint.
func dialTLS(cfg config.ClientConfig) (net.Conn, error) {
	wantFP := strings.ToLower(strings.ReplaceAll(cfg.CertFingerprint, ":", ""))
	tlsCfg := &utls.Config{
		InsecureSkipVerify: true, // we verify the fingerprint manually below
		ServerName:         cfg.SNI,
		MinVersion:         utls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != wantFP {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		},
	}
	rawConn, err := net.DialTimeout("tcp", cfg.ServerAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	conn := utls.UClient(rawConn, tlsCfg, utls.HelloChrome_Auto)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	// Auth frame right after the handshake.
	if err := protocol.WritePacket(conn, []byte(cfg.Token)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// runEcho is a diagnostic: send a frame every 2s and wait for the echo.
// No TUN, no admin rights needed. Usage: client -echo -config client.json
func runEcho(cfg config.ClientConfig) {
	cfg.Token = "echo:" + cfg.Token
	conn, err := dialTLS(cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	log.Printf("echo: connected, testing 60s")
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i)
	}
	for i := 0; i < 30; i++ {
		start := time.Now()
		if err := protocol.WritePacket(conn, payload); err != nil {
			log.Fatalf("echo: write failed at %ds: %v", i*2, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, protocol.MaxPacketSize)
		n, err := protocol.ReadPacket(conn, buf)
		if err != nil {
			log.Fatalf("echo: read failed at %ds: %v", i*2, err)
		}
		log.Printf("echo: %ds OK (%d bytes, rtt %v)", i*2, n, time.Since(start).Round(time.Millisecond))
		time.Sleep(2 * time.Second)
	}
	log.Printf("echo: PASSED, connection stable for 60s")
}

func main() {
	configPath := flag.String("config", "client.json", "path to config file")
	echo := flag.Bool("echo", false, "diagnostic echo mode (no tunnel)")
	flag.Parse()

	var cfg config.ClientConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		log.Fatal(err)
	}

	if *echo {
		runEcho(cfg)
		return
	}

	serverIP, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		log.Fatalf("bad server_addr: %v", err)
	}

	conn, err := dialTLS(cfg)
	if err != nil {
		log.Fatalf("connect to %s: %v", cfg.ServerAddr, err)
	}
	log.Printf("connected to %s (TLS 1.3, cert pinned)", cfg.ServerAddr)

	dev, err := tun.Create(cfg.TunName)
	if err != nil {
		log.Fatalf("create tun (need admin): %v", err)
	}
	luid := winipcfg.LUID(dev.Adapter.LUID())

	// Address and DNS on the tunnel interface.
	tunPrefix, err := netip.ParsePrefix(cfg.TunIP)
	if err != nil {
		log.Fatalf("bad tun_ip: %v", err)
	}
	if err := luid.SetIPAddresses([]netip.Prefix{tunPrefix}); err != nil {
		log.Fatalf("set ip: %v", err)
	}
	dns := []netip.Addr{netip.MustParseAddr(cfg.DNS)}
	if err := luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), dns, nil); err != nil {
		log.Printf("set dns: %v", err)
	}

	// Route the server itself via the physical gateway, so the tunnel
	// connection doesn't loop into itself.
	physLUID, gw, err := defaultGateway()
	if err != nil {
		log.Fatalf("find gateway: %v", err)
	}
	log.Printf("physical gateway: %s", gw)
	serverRoute := netip.PrefixFrom(netip.MustParseAddr(serverIP), 32)
	if err := physLUID.AddRoute(serverRoute, gw, 1); err != nil {
		log.Printf("add server route: %v", err)
	}

	// 0.0.0.0/1 + 128.0.0.0/1 override the default route without deleting it.
	tunGW := netip.MustParseAddr(cfg.TunGateway)
	for _, p := range []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 1),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{128, 0, 0, 0}), 1),
	} {
		if err := luid.AddRoute(p, tunGW, 0); err != nil {
			log.Printf("add route %s: %v", p, err)
		}
	}
	log.Printf("tunnel is up: %s via %s", cfg.TunIP, cfg.TunGateway)

	cleanup := func() {
		_ = physLUID.DeleteRoute(serverRoute, gw)
		dev.Close() // closing the adapter removes its routes
		log.Printf("tunnel is down")
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cleanup()
		os.Exit(0)
	}()

	errc := make(chan error, 2)
	var tunRx, tunTx, connRx, connTx atomic.Uint64

	// Periodic stats for debugging.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			log.Printf("stats: tun_rx=%d conn_tx=%d conn_rx=%d tun_tx=%d",
				tunRx.Load(), connTx.Load(), connRx.Load(), tunTx.Load())
		}
	}()

	// TUN -> server
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				errc <- fmt.Errorf("read tun: %w", err)
				return
			}
			tunRx.Add(1)
			if err := protocol.WritePacket(conn, buf[:n]); err != nil {
				errc <- fmt.Errorf("write conn: %w", err)
				return
			}
			connTx.Add(1)
		}
	}()

	// server -> TUN
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := protocol.ReadPacket(conn, buf)
			if err != nil {
				errc <- fmt.Errorf("read conn: %w", err)
				return
			}
			connRx.Add(1)
			if err := dev.WritePacket(buf[:n]); err != nil {
				errc <- fmt.Errorf("write tun: %w", err)
				return
			}
			tunTx.Add(1)
		}
	}()

	err = <-errc
	log.Printf("connection lost: %v", err)
	cleanup()
}
