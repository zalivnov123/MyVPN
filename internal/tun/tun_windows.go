//go:build windows

package tun

import (
	"fmt"

	"golang.zx2c4.com/wintun"
)

const ringCapacity = 0x400000 // 4 MiB

// Device wraps a wintun adapter and session.
type Device struct {
	Adapter *wintun.Adapter
	session *wintun.Session
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
	return &Device{Adapter: adapter, session: &session}, nil
}

// ReadPacket returns a copy of the next packet from the ring buffer.
func (d *Device) ReadPacket(buf []byte) (int, error) {
	pkt, err := d.session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	n := copy(buf, pkt)
	d.session.ReleaseReceivePacket(pkt)
	return n, nil
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
	d.session.End()
	d.Adapter.Close()
	return nil
}
