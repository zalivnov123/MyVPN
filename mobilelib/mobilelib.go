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
	gen     int64 // connection generation: stale sessions must not kill new ones
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

// connectVia performs one full connection attempt to a specific address.
func connectVia(cfg config.ClientConfig, addr string, signer ssh.Signer, pubKey ssh.PublicKey) (net.Conn, *ssh.Client, string, error) {
	protect := func(fd uintptr) {
		mu.Lock()
		p := protector
		mu.Unlock()
		if p != nil && !p.Protect(int32(fd)) {
			logf("warning: protect(%d) failed", fd)
		}
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var cerr error
			c.Control(func(fd uintptr) { protect(fd) })
			return cerr
		},
	}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, nil, "", err
	}
	sshCfg := &ssh.ClientConfig{
		User:              cfg.SSHUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(pubKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(rawConn, addr, sshCfg)
	if err != nil {
		rawConn.Close()
		return nil, nil, "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)

	vpnConn, err := client.Dial("tcp", cfg.VPNAddr)
	if err != nil {
		client.Close()
		return nil, nil, "", fmt.Errorf("ssh forward to %s: %w", cfg.VPNAddr, err)
	}
	if err := protocol.WritePacket(vpnConn, []byte(cfg.Token)); err != nil {
		vpnConn.Close()
		client.Close()
		return nil, nil, "", err
	}
	vpnConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	abuf := make([]byte, 64)
	an, err := protocol.ReadPacket(vpnConn, abuf)
	vpnConn.SetReadDeadline(time.Time{})
	if err != nil {
		vpnConn.Close()
		client.Close()
		return nil, nil, "", fmt.Errorf("ip assignment: %w", err)
	}
	assigned, ok := strings.CutPrefix(string(abuf[:an]), "ip:")
	if !ok {
		vpnConn.Close()
		client.Close()
		return nil, nil, "", fmt.Errorf("unexpected server greeting")
	}
	return vpnConn, client, assigned, nil
}

// Connect dials the server over SSH, trying each address from ssh_addrs
// in order, authenticates and returns the assigned tunnel IP CIDR.
// configJSON is the full client.json.
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

	addrs := cfg.SSHAddrs
	if len(addrs) == 0 {
		addrs = []string{cfg.SSHAddr}
	}
	var vpnConn net.Conn
	var client *ssh.Client
	var assigned string
	var lastErr error
	for _, addr := range addrs {
		vpnConn, client, assigned, lastErr = connectVia(cfg, addr, signer, pubKey)
		if lastErr == nil {
			logf("connected via %s, assigned %s", addr, assigned)
			break
		}
		logf("port %s failed: %v", addr, lastErr)
	}
	if vpnConn == nil {
		return "", lastErr
	}

	mu.Lock()
	conn = vpnConn
	sshConn = client
	gen++
	myGen := gen
	mu.Unlock()

	// SSH keepalive: detect dead connections while the phone sleeps.
	go func(sc *ssh.Client, g int64) {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			<-t.C
			mu.Lock()
			current := sshConn == sc && gen == g
			mu.Unlock()
			if !current {
				return
			}
			if _, _, err := sc.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				logf("keepalive failed: %v", err)
				stopIfCurrent(g)
				setState("lost")
				return
			}
		}
	}(client, myGen)

	return assigned, nil
}

// StartPump starts forwarding packets between the Android VPN interface
// (tunFD) and the server. Returns immediately; watch Events for state.
func StartPump(tunFD int) error {
	mu.Lock()
	c := conn
	g := gen
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
		stopIfCurrent(g)
		setState("lost")
	}()
	return nil
}

// stopIfCurrent tears down the session only if it is still the current one
// (a kicked/ended old session must not kill a fresh connection).
func stopIfCurrent(g int64) {
	mu.Lock()
	if gen != g {
		mu.Unlock()
		return
	}
	gen++
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
}

// Stop closes the session.
func Stop() {
	mu.Lock()
	g := gen
	mu.Unlock()
	stopIfCurrent(g)
	setState("stopped")
}
