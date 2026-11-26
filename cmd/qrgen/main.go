// Command qrgen builds the mobile config (single JSON with inline key)
// and renders it as a QR code PNG for scanning by the Android app.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/skip2/go-qrcode"

	"personalvpn/internal/config"
)

func main() {
	configPath := flag.String("config", "client.json", "desktop client config")
	keyPath := flag.String("key", "vultr_vpn", "private key file")
	outQR := flag.String("qr", "mobile-config-qr.png", "output QR png")
	outJSON := flag.String("json", "mobile-config.json", "output mobile config json")
	token := flag.String("token", "", "override token (generate config for a specific user)")
	flag.Parse()

	var cfg config.ClientConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *token != "" {
		cfg.Token = *token
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read key:", err)
		os.Exit(1)
	}

	mobile := map[string]string{
		"ssh_addr":     cfg.SSHAddr,
		"ssh_user":     cfg.SSHUser,
		"ssh_key_data": base64.StdEncoding.EncodeToString(key),
		"ssh_host_key": cfg.SSHHostKeyB64,
		"vpn_addr":     cfg.VPNAddr,
		"token":        cfg.Token,
		"dns":          cfg.DNS,
	}
	data, err := json.Marshal(mobile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outJSON, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := qrcode.WriteFile(string(data), qrcode.Medium, 512, *outQR); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	absQR, _ := filepath.Abs(*outQR)
	absJSON, _ := filepath.Abs(*outJSON)
	fmt.Println("QR:   ", absQR)
	fmt.Println("JSON: ", absJSON)
}
