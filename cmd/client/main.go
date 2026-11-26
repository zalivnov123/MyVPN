// Command client connects a Windows machine to the VPN server over SSH:
// creates a wintun adapter, routes traffic through the tunnel.
// Requires administrator privileges. Reconnects automatically on failure.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"personalvpn/internal/config"
	"personalvpn/internal/protocol"
	"personalvpn/internal/tun"
)

var stats struct {
	tunRx, tunTx, connRx, connTx atomic.Uint64
}

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

// dialVPN connects to the server over SSH (camouflage: DPI lets SSH through)
// and opens a forwarded channel to the VPN listener on the server's localhost.
func dialVPN(cfg config.ClientConfig) (net.Conn, error) {
	keyPath := cfg.SSHKeyFile
	if !filepath.IsAbs(keyPath) {
		// Relative path: resolve against the executable's directory,
		// so a portable folder works on any machine without edits.
		if exe, err := os.Executable(); err == nil {
			keyPath = filepath.Join(filepath.Dir(exe), keyPath)
		}
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}
	hostKey, err := base64.StdEncoding.DecodeString(cfg.SSHHostKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode ssh_host_key: %w", err)
	}
	pubKey, err := ssh.ParsePublicKey(hostKey)
	if err != nil {
		return nil, fmt.Errorf("parse ssh_host_key: %w", err)
	}
	sshCfg := &ssh.ClientConfig{
		User:              cfg.SSHUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(pubKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
	}
	addrs := cfg.SSHAddrs
	if len(addrs) == 0 {
		addrs = []string{cfg.SSHAddr}
	}
	var sshConn *ssh.Client
	var lastErr error
	for _, addr := range addrs {
		sshConn, lastErr = ssh.Dial("tcp", addr, sshCfg)
		if lastErr == nil {
			break
		}
		log.Printf("dial %s: %v (trying next)", addr, lastErr)
	}
	if sshConn == nil {
		return nil, fmt.Errorf("all ssh addresses failed, last: %w", lastErr)
	}
	conn, err := sshConn.Dial("tcp", cfg.VPNAddr)
	if err != nil {
		sshConn.Close()
		return nil, fmt.Errorf("ssh forward to %s: %w", cfg.VPNAddr, err)
	}
	// Auth frame right after connecting.
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
	conn, err := dialVPN(cfg)
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

// pump moves packets between the tunnel and one connection until it breaks.
func pump(conn net.Conn, dev *tun.Device, tunCh <-chan []byte) error {
	errc := make(chan error, 2)
	done := make(chan struct{})
	defer close(done)

	// conn -> TUN (replies from the internet)
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := protocol.ReadPacket(conn, buf)
			if err != nil {
				errc <- fmt.Errorf("read conn: %w", err)
				return
			}
			stats.connRx.Add(1)
			if err := dev.WritePacket(buf[:n]); err != nil {
				errc <- fmt.Errorf("write tun: %w", err)
				return
			}
			stats.tunTx.Add(1)
		}
	}()

	// TUN -> conn (packets from this machine to the internet)
	go func() {
		for {
			select {
			case <-done:
				return
			case pkt := <-tunCh:
				if err := protocol.WritePacket(conn, pkt); err != nil {
					errc <- fmt.Errorf("write conn: %w", err)
					return
				}
				stats.connTx.Add(1)
			}
		}
	}()

	return <-errc
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

	host, _, err := net.SplitHostPort(cfg.SSHAddr)
	if err != nil {
		log.Fatalf("bad ssh_addr: %v", err)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(addrs) == 0 {
		log.Fatalf("resolve %s: %v", host, err)
	}
	serverIP := addrs[0].IP.String()

	// Download/refresh the RU zone list while the network is still direct
	// (before we touch DNS and routes).
	var ruPrefixes []netip.Prefix
	if cfg.BypassRU {
		ruPrefixes = loadRUPrefixesSafe()
	}
	if len(cfg.BypassDomains) > 0 {
		ruPrefixes = append(ruPrefixes, resolveBypassDomains(cfg.BypassDomains)...)
	}

	// connectOnce dials and reads the assigned tunnel IP. No system state
	// (routes, adapters) is touched here.
	connectOnce := func() (net.Conn, string, error) {
		conn, err := dialVPN(cfg)
		if err != nil {
			return nil, "", err
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		abuf := make([]byte, 64)
		an, err := protocol.ReadPacket(conn, abuf)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return nil, "", fmt.Errorf("ip assignment: %w", err)
		}
		assigned := cfg.TunIP
		if rest, ok := strings.CutPrefix(string(abuf[:an]), "ip:"); ok {
			assigned = rest
		}
		return conn, assigned, nil
	}

	// IMPORTANT: establish the first connection BEFORE touching any routes,
	// otherwise an unreachable server would kill the whole internet.
	var conn net.Conn
	var assigned string
	for {
		conn, assigned, err = connectOnce()
		if err == nil {
			break
		}
		log.Printf("connect: %v (retry in 5s)", err)
		time.Sleep(5 * time.Second)
	}
	log.Printf("connected to %s (SSH transport)", cfg.SSHAddr)

	dev, err := tun.Create(cfg.TunName)
	if err != nil {
		log.Fatalf("create tun (need admin): %v", err)
	}
	luid := winipcfg.LUID(dev.Adapter.LUID())

	setTunIP := func(cidr string) error {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		return luid.SetIPAddresses([]netip.Prefix{prefix})
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

	// Russian sites that block VPN traffic go directly via the physical gateway.
	if len(ruPrefixes) > 0 {
		applyRURoutes(physLUID, gw, ruPrefixes)
	}

	if err := setTunIP(assigned); err != nil {
		log.Fatalf("set ip: %v", err)
	}
	curIP := assigned
	log.Printf("tunnel is up: %s via %s", curIP, cfg.TunGateway)

	cleanup := func() {
		clearRUBypass(physLUID, gw, ruPrefixes)
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

	// Single TUN reader feeding the current session; packets are dropped
	// while disconnected.
	tunCh := make(chan []byte, 256)
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				log.Printf("read tun: %v", err)
				time.Sleep(time.Second)
				continue
			}
			stats.tunRx.Add(1)
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case tunCh <- pkt:
			default: // no active session or channel full: drop
			}
		}
	}()

	// Periodic stats for debugging.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			log.Printf("stats: tun_rx=%d conn_tx=%d conn_rx=%d tun_tx=%d",
				stats.tunRx.Load(), stats.connTx.Load(), stats.connRx.Load(), stats.tunTx.Load())
		}
	}()

	// Main loop: pump until the connection breaks, then reconnect forever.
	for {
		err = pump(conn, dev, tunCh)
		conn.Close()
		log.Printf("connection lost: %v (reconnect in 3s)", err)
		time.Sleep(3 * time.Second)

		for {
			conn, assigned, err = connectOnce()
			if err == nil {
				break
			}
			log.Printf("reconnect: %v (retry in 5s)", err)
			time.Sleep(5 * time.Second)
		}
		if assigned != curIP {
			if err := setTunIP(assigned); err != nil {
				log.Printf("set ip: %v", err)
				conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
			curIP = assigned
		}
		log.Printf("tunnel is up: %s via %s", curIP, cfg.TunGateway)
	}
}
