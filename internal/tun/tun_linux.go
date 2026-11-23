//go:build linux

package tun

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	cloneDevice = "/dev/net/tun"
	iffTUN      = 0x0001
	iffNOPI     = 0x1000
	tunSETIFF   = 0x400454ca
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// Device wraps a Linux TUN interface file.
type Device struct {
	file *os.File
}

// Create opens /dev/net/tun and creates (or attaches to) a TUN interface.
func Create(name string) (*Device, error) {
	f, err := os.OpenFile(cloneDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cloneDevice, err)
	}
	var req ifreq
	copy(req.name[:], name)
	req.flags = iffTUN | iffNOPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}
	return &Device{file: f}, nil
}

func (d *Device) ReadPacket(buf []byte) (int, error) {
	return d.file.Read(buf)
}

func (d *Device) WritePacket(pkt []byte) error {
	_, err := d.file.Write(pkt)
	return err
}

func (d *Device) Close() error {
	return d.file.Close()
}
