// Package config loads JSON configuration files for client and server.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ServerConfig struct {
	ListenAddr string `json:"listen_addr"` // e.g. ":443"
	TunName    string `json:"tun_name"`    // e.g. "vpn0"
	TunCIDR    string `json:"tun_cidr"`    // e.g. "10.8.0.1/24"
	Token      string `json:"token"`       // shared secret
	CertFile   string `json:"cert_file"`   // TLS certificate (self-signed ok)
	KeyFile    string `json:"key_file"`    // TLS private key
}

type ClientConfig struct {
	ServerAddr      string `json:"server_addr"` // e.g. "64.176.74.108:443"
	TunName         string `json:"tun_name"`    // e.g. "MyVPN"
	TunIP           string `json:"tun_ip"`      // e.g. "10.8.0.2/24"
	TunGateway      string `json:"tun_gateway"` // e.g. "10.8.0.1"
	DNS             string `json:"dns"`         // e.g. "1.1.1.1"
	Token           string `json:"token"`
	CertFingerprint string `json:"cert_fingerprint"` // sha256 of server cert, hex without colons
	SNI             string `json:"sni"`              // ServerName for TLS ClientHello, e.g. "www.microsoft.com"
}

func Load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}
