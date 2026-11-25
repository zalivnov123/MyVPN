// Package mobilelib exposes the VPN client core to Android via gomobile.
// Lifecycle: SetProtector -> SetEvents -> Connect -> StartPump -> Stop.
// Kotlin side owns the VpnService interface and reconnection policy.
package mobilelib

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"personalvpn/internal/config"
	"personalvpn/internal/protocol"
)

// Protector is implemented in Kotlin: VpnService.protect(fd) keeps the SSH
// socket outside the VPN interface (otherwise the tunnel loops into itself).
type Protector interface {
	Protect(fd int32) bool
}

// Events receives state changes and log lines.
type Events interface {
	OnLog(msg string)
	OnStateChange(state string)
}

var (
	protector Protector
	events    Events

	mu      sync.Mutex
	conn    net.Conn
	sshConn *ssh.Client
	tunDev  *os.File
	running bool
)

func SetProtector(p Protector) { mu.Lock(); protector = p; mu.Unlock() }
func SetEvents(e Events)       { mu.Lock(); events = e; mu.Unlock() }

func logf(format string, args ...any) {
	mu.Lock()
	e := events
	mu.Unlock()
	if e != nil {
		e.OnLog(fmt.Sprintf(format, args...))
	}
}

func setState(s string) {
	mu.Lock()
	e := events
	mu.Unlock()
	if e != nil {
		e.OnStateChange(s)
	}
}

// IsRunning reports whether a pump loop is active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// Connect dials the server over SSH, authenticates and returns the assigned
// tunnel IP CIDR (e.g. "10.8.0.2/24"). configJSON is the full client.json.
func Connect(configJSON string) (string, error) {
	var cfg config.ClientConfig
	if err := config.Parse([]byte(configJSON), &cfg); err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(cfg.SSHKeyDataB64)
	if err != nil {
		key = []byte(cfg.SSHKeyDataB64) // not base64: treat as raw PEM
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("parse ssh key: %w", err)
	}
	hostKey, err := base64.StdEncoding.DecodeString(cfg.SSHHostKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode ssh_host_key: %w", err)
	}
	pubKey, err := ssh.ParsePublicKey(hostKey)
	if err != nil {
		return "", fmt.Errorf("parse ssh_host_key: %w", err)
	}

	protect := func(fd uintptr) {
		mu.Lock()
		p := protector
		mu.Unlock()
		if p != nil && !p.Protect(int32(fd)) {
			logf("warning: protect(%d) failed", fd)
		}
	}
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var cerr error
			c.Control(func(fd uintptr) { protect(fd) })
			return cerr
		},
	}
	rawConn, err := dialer.Dial("tcp", cfg.SSHAddr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", cfg.SSHAddr, err)
	}
	sshCfg := &ssh.ClientConfig{
		User:              cfg.SSHUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(pubKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           15 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(rawConn, cfg.SSHAddr, sshCfg)
	if err != nil {
		rawConn.Close()
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)

	vpnConn, err := client.Dial("tcp", cfg.VPNAddr)
	if err != nil {
		client.Close()
		return "", fmt.Errorf("ssh forward to %s: %w", cfg.VPNAddr, err)
	}
	if err := protocol.WritePacket(vpnConn, []byte(cfg.Token)); err != nil {
		vpnConn.Close()
		client.Close()
		return "", err
	}
	vpnConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	abuf := make([]byte, 64)
	an, err := protocol.ReadPacket(vpnConn, abuf)
	vpnConn.SetReadDeadline(time.Time{})
	if err != nil {
		vpnConn.Close()
		client.Close()
		return "", fmt.Errorf("ip assignment: %w", err)
	}
	assigned := ""
	if rest, ok := strings.CutPrefix(string(abuf[:an]), "ip:"); ok {
		assigned = rest
	} else {
		vpnConn.Close()
		client.Close()
		return "", fmt.Errorf("unexpected server greeting")
	}

	mu.Lock()
	conn = vpnConn
	sshConn = client
	mu.Unlock()

	logf("connected, assigned %s", assigned)
	return assigned, nil
}

// StartPump starts forwarding packets between the Android VPN interface
// (tunFD) and the server. Returns immediately; watch Events for state.
func StartPump(tunFD int) error {
	mu.Lock()
	c := conn
	mu.Unlock()
	if c == nil {
		return fmt.Errorf("not connected: call Connect first")
	}
	dev := os.NewFile(uintptr(tunFD), "tun")
	if dev == nil {
		return fmt.Errorf("bad tun fd %d", tunFD)
	}
	mu.Lock()
	tunDev = dev
	running = true
	mu.Unlock()
	setState("running")

	go func() {
		errc := make(chan error, 2)

		// TUN -> server
		go func() {
			buf := make([]byte, protocol.MaxPacketSize)
			for {
				n, err := dev.Read(buf)
				if err != nil {
					errc <- fmt.Errorf("read tun: %w", err)
					return
				}
				if err := protocol.WritePacket(c, buf[:n]); err != nil {
					errc <- fmt.Errorf("write conn: %w", err)
					return
				}
			}
		}()

		// server -> TUN
		go func() {
			buf := make([]byte, protocol.MaxPacketSize)
			for {
				n, err := protocol.ReadPacket(c, buf)
				if err != nil {
					errc <- fmt.Errorf("read conn: %w", err)
					return
				}
				if _, err := dev.Write(buf[:n]); err != nil {
					errc <- fmt.Errorf("write tun: %w", err)
					return
				}
			}
		}()

		err := <-errc
		logf("pump stopped: %v", err)
		Stop()
		setState("lost")
	}()
	return nil
}

// Stop closes the session.
func Stop() {
	mu.Lock()
	c, sc, td := conn, sshConn, tunDev
	conn, sshConn, tunDev, running = nil, nil, nil, false
	mu.Unlock()
	if c != nil {
		c.Close()
	}
	if sc != nil {
		sc.Close()
	}
	if td != nil {
		td.Close()
	}
	setState("stopped")
}
