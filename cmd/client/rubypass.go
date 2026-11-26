package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const ruListURL = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
const ruListMaxAge = 7 * 24 * time.Hour

func ruListPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "ru-aggregated.zone"
	}
	return filepath.Join(filepath.Dir(exe), "ru-aggregated.zone")
}

// loadRUPrefixes returns RU IP prefixes, refreshing the cached zone file
// when older than a week. Falls back to a stale cache if download fails.
func loadRUPrefixes() ([]netip.Prefix, error) {
	path := ruListPath()
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) > ruListMaxAge {
		if err := downloadRUList(path); err != nil {
			if st != nil {
				log.Printf("ru list: download failed (%v), using stale cache", err)
			} else {
				return nil, err
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var prefixes []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes, sc.Err()
}

func downloadRUList(path string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(ruListURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ru list: http %d", resp.StatusCode)
	}
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// loadRUPrefixesSafe wraps loadRUPrefixes with a non-fatal error path.
func loadRUPrefixesSafe() []netip.Prefix {
	prefixes, err := loadRUPrefixes()
	if err != nil {
		log.Printf("ru bypass: %v (disabled)", err)
		return nil
	}
	return prefixes
}

// resolveBypassDomains resolves domains to /32 prefixes (for direct routing
// of sites like Ozon whose IPs are not in the RU zone list).
func resolveBypassDomains(domains []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, d := range domains {
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", d)
		if err != nil {
			log.Printf("bypass domain %s: resolve: %v", d, err)
			continue
		}
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Is4() {
				prefixes = append(prefixes, netip.PrefixFrom(a, 32))
			}
		}
		log.Printf("bypass domain %s: %d IPs direct", d, len(ips))
	}
	return prefixes
}

// applyRURoutes routes the given prefixes via the physical gateway (direct, no VPN).
func applyRURoutes(physLUID winipcfg.LUID, gw netip.Addr, prefixes []netip.Prefix) {
	routes := make([]*winipcfg.RouteData, 0, len(prefixes))
	for _, p := range prefixes {
		routes = append(routes, &winipcfg.RouteData{Destination: p, NextHop: gw, Metric: 1})
	}
	if err := physLUID.AddRoutes(routes); err != nil {
		log.Printf("ru bypass: add routes: %v", err)
		return
	}
	log.Printf("ru bypass: %d RU prefixes routed directly via %s", len(routes), gw)
}

func clearRUBypass(physLUID winipcfg.LUID, gw netip.Addr, prefixes []netip.Prefix) {
	for _, p := range prefixes {
		_ = physLUID.DeleteRoute(p, gw)
	}
}
