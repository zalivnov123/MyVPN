// Command client connects a Windows machine to the VPN server:
// creates a wintun adapter, routes traffic through the tunnel.
// Requires administrator privileges.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

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

func main() {
	configPath := flag.String("config", "client.json", "path to config file")
	flag.Parse()

	var cfg config.ClientConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		log.Fatal(err)
	}

	serverIP, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		log.Fatalf("bad server_addr: %v", err)
	}

	conn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		log.Fatalf("connect to %s: %v", cfg.ServerAddr, err)
	}
	log.Printf("connected to %s", cfg.ServerAddr)

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
	if err := physLUID.AddRoute(netip.PrefixFrom(netip.MustParseAddr(serverIP), 32), gw, 1); err != nil {
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
		_ = physLUID.DeleteRoute(netip.PrefixFrom(netip.MustParseAddr(serverIP), 32), gw)
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

	// TUN -> server
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				errc <- err
				return
			}
			if err := protocol.WritePacket(conn, buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	// server -> TUN
	go func() {
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, err := protocol.ReadPacket(conn, buf)
			if err != nil {
				errc <- err
				return
			}
			if err := dev.WritePacket(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	err = <-errc
	log.Printf("connection lost: %v", err)
	cleanup()
}
