package x365

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// HandleSOCKS5 handles a single SOCKS5 connection, tunneling it through X365.
// Exported for use by the mobile binding package.
func HandleSOCKS5(client net.Conn, cfg *X365Config) {
	handleSOCKS5(client, cfg)
}

// handleSOCKS5 handles a single SOCKS5 connection, tunneling it through X365.
func handleSOCKS5(client net.Conn, cfg *X365Config) {
	defer client.Close()

	buf := make([]byte, 256)
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return
	}
	client.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	var targetHost string
	var targetPort uint16

	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			return
		}
		targetHost = string(buf[:domainLen])
	case 0x04:
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return
		}
		targetHost = net.IP(buf[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	targetPort = binary.BigEndian.Uint16(buf[:2])

	if cmd != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	logf("SOCKS5", "%s:%d via %s", targetHost, targetPort, cfg.Path)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	remote, err := Dial(ctx, cfg, targetHost, targetPort)
	if err != nil {
		logf("DIAL", "failed to %s:%d via %s: %v", targetHost, targetPort, cfg.Path, err)
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	logf("TUNNEL", "established %s:%d via %s", targetHost, targetPort, cfg.Path)
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, remote)
		done <- struct{}{}
	}()
	<-done
}
