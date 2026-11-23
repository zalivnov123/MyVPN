// Command server accepts VPN clients over TLS and forwards their IP
// packets to the internet through a Linux TUN interface.
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"personalvpn/internal/config"
	"personalvpn/internal/protocol"
	"personalvpn/internal/tun"
)

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	if len(out) > 0 {
		log.Printf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultIface() (string, error) {
	out, err := exec.Command("sh", "-c", "ip -4 route show default | awk '{print $5; exit}'").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func setupNetwork(cfg config.ServerConfig) error {
	if err := run("ip", "link", "set", "dev", cfg.TunName, "up"); err != nil {
		return err
	}
	// Ignore error if address already exists.
	_ = run("ip", "addr", "add", cfg.TunCIDR, "dev", cfg.TunName)
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	iface, err := defaultIface()
	if err != nil || iface == "" {
		iface = "eth0"
	}
	subnet := strings.Split(cfg.TunCIDR, "/")[0]
	subnet = subnet[:strings.LastIndex(subnet, ".")] + ".0/24"
	log.Printf("NAT: %s via %s", subnet, iface)
	return run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE")
}

var tunWriteMu sync.Mutex

// auth reads the token frame sent by the client right after the TLS handshake.
// Token prefixed with "echo:" selects the diagnostic echo mode.
func auth(conn net.Conn, token string) (echo bool, err error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 256)
	n, err := protocol.ReadPacket(conn, buf)
	if err != nil {
		return false, err
	}
	got := buf[:n]
	if rest, ok := strings.CutPrefix(string(got), "echo:"); ok {
		got = []byte(rest)
		echo = true
	}
	if subtle.ConstantTimeCompare(got, []byte(token)) != 1 {
		return false, fmt.Errorf("bad token")
	}
	return echo, nil
}

// echoMode is a diagnostic: bounce every received frame back to the sender.
func echoMode(conn net.Conn) {
	log.Printf("echo session: %s", conn.RemoteAddr())
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, err := protocol.ReadPacket(conn, buf)
		if err != nil {
			log.Printf("echo session ended: %v", err)
			return
		}
		if err := protocol.WritePacket(conn, buf[:n]); err != nil {
			log.Printf("echo session ended: %v", err)
			return
		}
	}
}

func handle(conn net.Conn, dev *tun.Device, token string) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	echo, err := auth(conn, token)
	if err != nil {
		log.Printf("auth failed from %s: %v", remote, err)
		return
	}
	if echo {
		echoMode(conn)
		return
	}
	log.Printf("client connected: %s", remote)
	defer log.Printf("client disconnected: %s", remote)

	if tc, ok := conn.(*tls.Conn); ok {
		if uc := tc.NetConn(); uc != nil {
			if tcp, ok := uc.(*net.TCPConn); ok {
				tcp.SetKeepAlive(true)
				tcp.SetKeepAlivePeriod(30 * time.Second)
			}
		}
	}

	errc := make(chan error, 2)

	// conn -> TUN (packets from client to the internet)
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := protocol.ReadPacket(conn, buf)
			if err != nil {
				errc <- fmt.Errorf("read conn: %w", err)
				return
			}
			tunWriteMu.Lock()
			err = dev.WritePacket(buf[:n])
			tunWriteMu.Unlock()
			if err != nil {
				errc <- fmt.Errorf("write tun: %w", err)
				return
			}
		}
	}()

	// TUN -> conn (replies from the internet to the client)
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				errc <- fmt.Errorf("read tun: %w", err)
				return
			}
			if err := protocol.WritePacket(conn, buf[:n]); err != nil {
				errc <- fmt.Errorf("write conn: %w", err)
				return
			}
		}
	}()

	log.Printf("session error: %v", <-errc)
}

func main() {
	configPath := flag.String("config", "server.json", "path to config file")
	flag.Parse()

	var cfg config.ServerConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		log.Fatal(err)
	}

	dev, err := tun.Create(cfg.TunName)
	if err != nil {
		log.Fatalf("create tun: %v (run as root)", err)
	}
	defer dev.Close()

	if err := setupNetwork(cfg); err != nil {
		log.Printf("network setup warning: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("load TLS cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (TLS 1.3)", cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, dev, cfg.Token)
	}
}
