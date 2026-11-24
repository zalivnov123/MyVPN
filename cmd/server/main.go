// Command server accepts VPN clients over TLS and forwards their IP
// packets to the internet through a Linux TUN interface.
package main

import (
	"crypto/subtle"
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
	// Skip if the rule already exists (server restarts would duplicate it).
	if err := run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"); err == nil {
		return nil
	}
	return run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE")
}

var tunWriteMu sync.Mutex

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

func handle(conn net.Conn, dev *tun.Device, token string) {
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
	if subtle.ConstantTimeCompare(got, []byte(token)) != 1 {
		log.Printf("auth failed from %s", remote)
		return
	}
	if echo {
		echoMode(conn)
		return
	}
	log.Printf("client connected: %s", remote)
	defer log.Printf("client disconnected: %s", remote)

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
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
		go handle(conn, dev, cfg.Token)
	}
}
