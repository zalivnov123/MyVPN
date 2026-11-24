// Package config loads JSON configuration files for client and server.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ServerConfig struct {
	ListenAddr string `json:"listen_addr"` // e.g. "127.0.0.1:8443" (reached via SSH forward)
	TunName    string `json:"tun_name"`    // e.g. "vpn0"
	TunCIDR    string `json:"tun_cidr"`    // e.g. "10.8.0.1/24"
	Token      string `json:"token"`       // shared secret
}

type ClientConfig struct {
	SSHAddr       string `json:"ssh_addr"`     // e.g. "64.176.74.108:442"
	SSHUser       string `json:"ssh_user"`     // e.g. "vpn"
	SSHKeyFile    string `json:"ssh_key_file"` // path to private key
	SSHHostKeyB64 string `json:"ssh_host_key"` // server host public key, base64 (ed25519)
	VPNAddr    string `json:"vpn_addr"`     // server-side address via SSH forward, e.g. "127.0.0.1:8443"
	TunName    string `json:"tun_name"`     // e.g. "MyVPN"
	TunIP      string `json:"tun_ip"`       // e.g. "10.8.0.2/24"
	TunGateway string `json:"tun_gateway"`  // e.g. "10.8.0.1"
	DNS        string `json:"dns"`          // e.g. "1.1.1.1"
	Token      string `json:"token"`
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
