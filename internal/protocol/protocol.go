// Package protocol implements length-prefixed framing for IP packets
// over a reliable stream (TCP/TLS/WebSocket).
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const MaxPacketSize = 65535

// WritePacket writes one packet: 2-byte big-endian length + payload.
func WritePacket(w io.Writer, payload []byte) error {
	if len(payload) > MaxPacketSize {
		return fmt.Errorf("packet too large: %d bytes", len(payload))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	buf := make([]byte, 0, 2+len(payload))
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// ReadPacket reads one packet into buf and returns its length.
func ReadPacket(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("packet too large: %d > %d", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
