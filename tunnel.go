package x365

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Dial establishes a tunnel to targetHost:targetPort through the X365 server.
// Returns a net.Conn that reads/writes through the chunked HTTP/1.1 tunnel.
func Dial(ctx context.Context, cfg *X365Config, targetHost string, targetPort uint16) (net.Conn, error) {
	serverAddr := net.JoinHostPort(cfg.Server, fmt.Sprintf("%d", cfg.Port))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	tlsConn, err := realityDial(ctx, rawConn, cfg.SNI, cfg.PublicKey, cfg.ShortID, cfg.Fingerprint)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	header := buildX365Header(cfg.UUID, targetPort, targetHost)

	httpReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\n\r\n",
		cfg.Path, cfg.SNI)
	if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write http request: %w", err)
	}

	chunk := fmt.Sprintf("%x\r\n", len(header))
	if _, err := tlsConn.Write([]byte(chunk)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write chunk size: %w", err)
	}
	if _, err := tlsConn.Write(header); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write x365 header: %w", err)
	}
	if _, err := tlsConn.Write([]byte("\r\n")); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write chunk end: %w", err)
	}

	reader := bufio.NewReader(tlsConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read status: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		tlsConn.Close()
		return nil, fmt.Errorf("server returned: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("read headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	firstChunk, err := readChunk(reader)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read ack chunk: %w", err)
	}
	if len(firstChunk) >= 4 && string(firstChunk[:4]) == "X365" {
		// Tunnel established
	} else {
		tlsConn.Close()
		return nil, fmt.Errorf("unexpected ack: %x", firstChunk)
	}

	conn := &chunkedConn{
		tls:    tlsConn,
		reader: reader,
	}
	return conn, nil
}

func readChunk(r *bufio.Reader) ([]byte, error) {
	sizeLine, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	sizeLine = strings.TrimSpace(sizeLine)
	var size int
	fmt.Sscanf(sizeLine, "%x", &size)
	if size == 0 {
		return nil, nil
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	r.Discard(2)
	return data, nil
}

type chunkedConn struct {
	tls    net.Conn
	reader *bufio.Reader
}

func (c *chunkedConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	chunk := fmt.Sprintf("%x\r\n", len(b))
	if _, err := c.tls.Write([]byte(chunk)); err != nil {
		return 0, err
	}
	n, err := c.tls.Write(b)
	if err != nil {
		return n, err
	}
	if _, err := c.tls.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if c.reader.Buffered() == 0 {
		data, err := readChunk(c.reader)
		if err != nil {
			return 0, err
		}
		if data == nil {
			return 0, io.EOF
		}
		c.reader = bufio.NewReader(io.MultiReader(bytesReader(data), c.reader))
	}
	return c.reader.Read(b)
}

func bytesReader(data []byte) io.Reader {
	return &simpleReader{data: data}
}

type simpleReader struct {
	data []byte
	pos  int
}

func (r *simpleReader) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (c *chunkedConn) Close() error {
	c.tls.Write([]byte("0\r\n\r\n"))
	return c.tls.Close()
}

func (c *chunkedConn) LocalAddr() net.Addr        { return c.tls.LocalAddr() }
func (c *chunkedConn) RemoteAddr() net.Addr       { return c.tls.RemoteAddr() }
func (c *chunkedConn) SetDeadline(t time.Time) error       { return c.tls.SetDeadline(t) }
func (c *chunkedConn) SetReadDeadline(t time.Time) error    { return c.tls.SetReadDeadline(t) }
func (c *chunkedConn) SetWriteDeadline(t time.Time) error   { return c.tls.SetWriteDeadline(t) }
