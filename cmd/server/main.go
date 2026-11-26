// Command server accepts VPN clients over an SSH-forwarded connection and
// forwards their IP packets to the internet through a Linux TUN interface.
// Multiple clients are served simultaneously: each gets its own tunnel IP
// from the 10.8.0.x pool, replies are dispatched by destination address.
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	// Skip if the rule already exists (server restarts would duplicate it).
	if err := run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"); err == nil {
		return nil
	}
	return run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE")
}

var tunWriteMu sync.Mutex

// clientSession is one connected VPN client with its assigned tunnel IP.
type clientSession struct {
	conn    net.Conn
	user    string
	ip      netip.Addr
	writeMu sync.Mutex
}

var (
	sessionsMu sync.Mutex
	sessions   = map[netip.Addr]*clientSession{}
	byUser     = map[string]*clientSession{}
)

// allocIP picks a free address from the 10.8.0.2-10.8.0.254 pool.
func allocIP() (netip.Addr, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for i := 2; i < 255; i++ {
		addr := netip.AddrFrom4([4]byte{10, 8, 0, byte(i)})
		if _, taken := sessions[addr]; !taken {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IP pool exhausted")
}

// registerSession adds a session, kicking the user's previous one if any:
// one token == one active connection.
func registerSession(s *clientSession) {
	var oldConn net.Conn
	sessionsMu.Lock()
	if prev := byUser[s.user]; prev != nil && prev != s {
		oldConn = prev.conn
		delete(sessions, prev.ip)
	}
	byUser[s.user] = s
	sessions[s.ip] = s
	sessionsMu.Unlock()
	if oldConn != nil {
		log.Printf("user %s: kicking previous session (%s)", s.user, s.ip)
		oldConn.Close()
	}
}

func unregisterSession(s *clientSession) {
	sessionsMu.Lock()
	if sessions[s.ip] == s {
		delete(sessions, s.ip)
	}
	if byUser[s.user] == s {
		delete(byUser, s.user)
	}
	sessionsMu.Unlock()
}

// tunReader is the single reader of the TUN device: it dispatches reply
// packets to the right client by destination IPv4 address.
func tunReader(dev *tun.Device) {
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, err := dev.ReadPacket(buf)
		if err != nil {
			log.Printf("tun reader: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue // IPv4 only
		}
		dst := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]})
		sessionsMu.Lock()
		s := sessions[dst]
		sessionsMu.Unlock()
		if s == nil {
			continue
		}
		s.writeMu.Lock()
		err = protocol.WritePacket(s.conn, buf[:n])
		s.writeMu.Unlock()
		if err != nil {
			log.Printf("dispatch to %s: %v", dst, err)
		}
	}
}

const decoyPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Dota 2 Memes - Fresh Daily</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:60px auto">
<h1>Dota 2 Memes</h1>
<p>Fresh memes every day. We are currently moving to a new server, come back soon!</p>
</body>
</html>`

// serveDecoy answers an HTTP probe with a harmless web page.
func serveDecoy(conn net.Conn, req []byte) {
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nServer: nginx\r\nConnection: close\r\n\r\n%s", len(decoyPage), decoyPage)
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

// usernameForToken resolves the token to a username (constant-time compare).
func usernameForToken(cfg config.ServerConfig, token string) string {
	for name, tok := range cfg.Users {
		if subtle.ConstantTimeCompare([]byte(token), []byte(tok)) == 1 {
			return name
		}
	}
	if cfg.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(cfg.Token)) == 1 {
		return "default"
	}
	return ""
}

func handle(conn net.Conn, dev *tun.Device, cfg config.ServerConfig) {
	defer conn.Close()
	remote := conn.RemoteAddr()

	// Read the first bytes: our client sends a framed token (starts with a
	// zero length byte), HTTP probes send a verb like "GET".
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first := make([]byte, 2048)
	n, err := conn.Read(first)
	if err != nil {
		return
	}
	if n == 0 || first[0] != 0x00 {
		serveDecoy(conn, first[:n])
		return
	}
	conn.SetReadDeadline(time.Time{})

	if n < 2 {
		return
	}
	frameLen := int(first[0])<<8 | int(first[1])
	if frameLen != n-2 {
		log.Printf("bad first frame from %s", remote)
		return
	}
	got := first[2:n]
	echo := false
	if rest, ok := strings.CutPrefix(string(got), "echo:"); ok {
		got = []byte(rest)
		echo = true
	}
	user := usernameForToken(cfg, string(got))
	if user == "" {
		log.Printf("auth failed from %s", remote)
		return
	}
	if echo {
		echoMode(conn)
		return
	}

	ip, err := allocIP()
	if err != nil {
		log.Printf("no free IP for %s: %v", remote, err)
		return
	}
	if err := protocol.WritePacket(conn, []byte("ip:"+ip.String()+"/24")); err != nil {
		return
	}
	sess := &clientSession{conn: conn, user: user, ip: ip}
	registerSession(sess)
	defer unregisterSession(sess)

	log.Printf("client connected: %s, user %s, tunnel IP %s", remote, user, ip)
	defer log.Printf("client disconnected: %s (%s, %s)", remote, user, ip)

	// conn -> TUN (packets from this client to the internet)
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, err := protocol.ReadPacket(conn, buf)
		if err != nil {
			log.Printf("session %s error: %v", ip, err)
			return
		}
		tunWriteMu.Lock()
		err = dev.WritePacket(buf[:n])
		tunWriteMu.Unlock()
		if err != nil {
			log.Printf("session %s write tun: %v", ip, err)
			return
		}
	}
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

	go tunReader(dev)

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (plain, reached via SSH forward)", cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, dev, cfg)
	}
}
