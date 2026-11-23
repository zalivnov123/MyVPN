//go:build windows

package tun

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const ringCapacity = 0x400000 // 4 MiB

// Device wraps a wintun adapter and session.
type Device struct {
	Adapter   *wintun.Adapter
	session   *wintun.Session
	closing   chan struct{}
	closeOnce sync.Once
}

// Create creates a wintun adapter with the given name and starts a session.
func Create(name string) (*Device, error) {
	adapter, err := wintun.CreateAdapter(name, "PersonalVPN", nil)
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}
	return &Device{
		Adapter: adapter,
		session: &session,
		closing: make(chan struct{}),
	}, nil
}

// ReadPacket blocks until a packet arrives and copies it into buf.
func (d *Device) ReadPacket(buf []byte) (int, error) {
	for {
		select {
		case <-d.closing:
			return 0, fmt.Errorf("device closed")
		default:
		}
		pkt, err := d.session.ReceivePacket()
		if err == windows.ERROR_NO_MORE_ITEMS {
			// Ring is empty: wait on the session event (with a timeout so
			// Close() can interrupt us).
			windows.WaitForSingleObject(d.session.ReadWaitEvent(), 200)
			continue
		}
		if err != nil {
			return 0, err
		}
		n := copy(buf, pkt)
		d.session.ReleaseReceivePacket(pkt)
		return n, nil
	}
}

func (d *Device) WritePacket(pkt []byte) error {
	buf, err := d.session.AllocateSendPacket(len(pkt))
	if err != nil {
		return err
	}
	copy(buf, pkt)
	d.session.SendPacket(buf)
	return nil
}

func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closing)
		d.session.End()
		// Give a blocked reader time to leave ReceivePacket before the
		// adapter handle is closed.
		time.Sleep(300 * time.Millisecond)
		d.Adapter.Close()
	})
	return nil
}
