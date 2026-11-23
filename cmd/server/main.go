// Command server accepts one VPN client and forwards its IP packets
// to the internet through a Linux TUN interface.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

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

func handle(conn net.Conn, dev *tun.Device) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log.Printf("client connected: %s", remote)
	defer log.Printf("client disconnected: %s", remote)

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
			if err := dev.WritePacket(buf[:n]); err != nil {
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
	log.Printf("listening on %s", cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		// Personal VPN: serve one client at a time.
		handle(conn, dev)
	}
}
