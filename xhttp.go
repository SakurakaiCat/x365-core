package x365

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2InitialWindow is the HTTP/2 default initial window size (both connection
// and stream level) when neither side advertises otherwise.
const h2InitialWindow = 65535

// h2MaxFrame is the default SETTINGS_MAX_FRAME_SIZE, always safe to send.
const h2MaxFrame = 16384

// debug enables frame-level logging to stderr when X365_DEBUG=1.
var xhttpDebug = os.Getenv("X365_DEBUG") == "1"

func dbgf(format string, args ...any) {
	if xhttpDebug {
		fmt.Fprintf(os.Stderr, "[x365-xhttp] "+format+"\n", args...)
	}
}

// DialXHTTP establishes a tunnel to targetHost:targetPort through the X365
// server using the XHTTP transport: a single HTTP/2 POST request whose body
// carries the X365 binary protocol, tunneled over a REALITY TLS connection.
// The returned net.Conn is a full-duplex stream: writes become DATA frames on
// the request body, reads consume the response body.
func DialXHTTP(ctx context.Context, cfg *X365Config, targetHost string, targetPort uint16) (net.Conn, error) {
	if cfg.Path == "" {
		return nil, errors.New("xhttp: empty path in config")
	}
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

	// Wire format: connection preface followed by an empty SETTINGS frame
	// (no PRIORITY / WINDOW_UPDATE), which is the minimal legal handshake
	// and the shape the server expects.
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write preface: %w", err)
	}

	w := bufio.NewWriterSize(tlsConn, 32*1024)
	fr := http2.NewFramer(w, tlsConn)
	fr.ReadMetaHeaders = hpack.NewDecoder(h2MaxFrame, func(hpack.HeaderField) {})

	c := &h2Conn{tls: tlsConn, fr: fr, w: w, connWin: h2InitialWindow, streamWin: h2InitialWindow}
	c.scond = sync.NewCond(&c.smu)
	c.rcond = sync.NewCond(&c.rmu)

	writeFrame := func(write func() error) error {
		c.wmu.Lock()
		defer c.wmu.Unlock()
		if err := write(); err != nil {
			return err
		}
		return w.Flush()
	}

	if err := writeFrame(func() error { return fr.WriteSettings() }); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write settings: %w", err)
	}

	// Request path and headers: the path gets an "?x_padding=" filler of
	// 'X' bytes appended, plus the browser-shaped header set the server
	// expects (content-type, user-agent, referer).
	reqPath := strings.TrimSuffix(cfg.Path, "/") + "/?x_padding=" + strings.Repeat("X", xPaddingLen)
	var hdrBlock bytes.Buffer
	enc := hpack.NewEncoder(&hdrBlock)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: cfg.SNI},
		{Name: ":path", Value: reqPath},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "user-agent", Value: BrowserUserAgent},
		{Name: "referer", Value: "https://" + cfg.SNI + reqPath},
	}
	if cfg.Token != "" {
		fields = append(fields, hpack.HeaderField{Name: "authorization", Value: "Bearer " + cfg.Token})
	}
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("hpack encode: %w", err)
		}
	}
	if err := writeFrame(func() error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: hdrBlock.Bytes(),
			EndHeaders:    true,
		})
	}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write headers: %w", err)
	}
	dbgf("HEADERS written, block=%x", hdrBlock.Bytes())

	// First request-body bytes: the X365 header selecting the tunnel target.
	if err := writeFrame(func() error {
		return fr.WriteData(1, false, buildX365Header(cfg.UUID, targetPort, targetHost))
	}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("write x365 header: %w", err)
	}

	// Read frames until the tunnel is confirmed: the server answers with its
	// SETTINGS (which we ack), a response HEADERS frame, and the 5-byte
	// "X365" + status acknowledgement as the first DATA payload.
	var leftover []byte
	confirmed := false
	for !confirmed {
		f, err := fr.ReadFrame()
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("read frame: %w", err)
		}
		dbgf("recv %T", f)
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := writeFrame(func() error { return fr.WriteSettingsAck() }); err != nil {
					tlsConn.Close()
					return nil, fmt.Errorf("write settings ack: %w", err)
				}
			}
		case *http2.MetaHeadersFrame:
			for _, hf := range f.Fields {
				if hf.Name == ":status" && hf.Value != "200" {
					tlsConn.Close()
					return nil, fmt.Errorf("server returned: %s", hf.Value)
				}
			}
		case *http2.DataFrame:
			data := f.Data()
			if len(data) < 5 || string(data[:4]) != "X365" {
				tlsConn.Close()
				return nil, fmt.Errorf("xhttp: unexpected ack: %x", data)
			}
			if status := data[4]; status != 0x00 {
				tlsConn.Close()
				return nil, fmt.Errorf("x365: server status 0x%02x", status)
			}
			leftover = data[5:]
			confirmed = true
		case *http2.RSTStreamFrame:
			tlsConn.Close()
			return nil, fmt.Errorf("xhttp: stream reset by server (code %d)", f.ErrCode)
		case *http2.GoAwayFrame:
			tlsConn.Close()
			return nil, fmt.Errorf("xhttp: server sent GOAWAY (code %d)", f.ErrCode)
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := writeFrame(func() error { return fr.WritePing(true, f.Data) }); err != nil {
					tlsConn.Close()
					return nil, fmt.Errorf("write ping ack: %w", err)
				}
			}
		}
	}
	if len(leftover) > 0 {
		c.push(leftover)
		_ = c.returnCredit(uint32(len(leftover)))
	}
	go c.readLoop()
	return c, nil
}

// h2Conn adapts a single HTTP/2 stream (id 1) to a net.Conn.
type h2Conn struct {
	tls net.Conn
	fr  *http2.Framer
	w   *bufio.Writer

	wmu sync.Mutex // serializes frame writes and flushes

	smu       sync.Mutex
	scond     *sync.Cond
	connWin   int32 // connection-level send window
	streamWin int32 // stream-level send window
	werr      error

	rmu     sync.Mutex
	rcond   *sync.Cond
	rbuf    [][]byte
	rclosed bool
	rerr    error
}

// lockAndWrite runs a frame write under the write lock and flushes.
func (c *h2Conn) lockAndWrite(write func() error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := write(); err != nil {
		return err
	}
	return c.w.Flush()
}

// push copies data into the read buffer. Copying is mandatory: the http2
// Framer returns DataFrame payloads as views into its reusable internal
// buffer, which the next ReadFrame overwrites.
func (c *h2Conn) push(data []byte) {
	if len(data) == 0 {
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	c.rmu.Lock()
	c.rbuf = append(c.rbuf, buf)
	c.rmu.Unlock()
	c.rcond.Broadcast()
}

func (c *h2Conn) failWrites(err error) {
	c.smu.Lock()
	if c.werr == nil {
		c.werr = err
	}
	c.smu.Unlock()
	c.scond.Broadcast()
}

func (c *h2Conn) failReads(err error) {
	c.rmu.Lock()
	if c.rerr == nil {
		c.rerr = err
	}
	c.rclosed = true
	c.rmu.Unlock()
	c.rcond.Broadcast()
}

// returnCredit gives flow-control credit back to the server for n consumed
// bytes, on both the stream and the connection.
func (c *h2Conn) returnCredit(n uint32) error {
	if n == 0 {
		return nil
	}
	return c.lockAndWrite(func() error {
		if err := c.fr.WriteWindowUpdate(0, n); err != nil {
			return err
		}
		return c.fr.WriteWindowUpdate(1, n)
	})
}

// readLoop consumes server frames, feeding DATA payloads into the read
// buffer and tracking flow-control updates for writes.
func (c *h2Conn) readLoop() {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			dbgf("readLoop exit: %v", err)
			if err == io.EOF {
				c.failWrites(io.EOF)
			} else {
				c.failWrites(fmt.Errorf("read: %w", err))
			}
			c.failReads(io.EOF)
			return
		}
		switch f := f.(type) {
		case *http2.DataFrame:
			dbgf("readLoop DATA %d bytes", len(f.Data()))
			c.push(f.Data())
			if f.StreamEnded() {
				c.failReads(io.EOF)
				return
			}
		case *http2.WindowUpdateFrame:
			c.smu.Lock()
			if f.StreamID == 0 {
				c.connWin += int32(f.Increment)
			} else {
				c.streamWin += int32(f.Increment)
			}
			c.smu.Unlock()
			c.scond.Broadcast()
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.lockAndWrite(func() error { return c.fr.WriteSettingsAck() })
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				c.lockAndWrite(func() error { return c.fr.WritePing(true, f.Data) })
			}
		case *http2.RSTStreamFrame:
			err := fmt.Errorf("stream reset by server (code %d)", f.ErrCode)
			c.failWrites(err)
			c.failReads(err)
			return
		case *http2.GoAwayFrame:
			err := fmt.Errorf("server sent GOAWAY (code %d)", f.ErrCode)
			c.failWrites(err)
			c.failReads(err)
			return
		}
	}
}

func (c *h2Conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	for len(c.rbuf) == 0 && !c.rclosed {
		c.rcond.Wait()
	}
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf[0])
		if n == len(c.rbuf[0]) {
			c.rbuf[0] = nil
			c.rbuf = c.rbuf[1:]
		} else {
			c.rbuf[0] = c.rbuf[0][n:]
		}
		c.rmu.Unlock()
		_ = c.returnCredit(uint32(n))
		return n, nil
	}
	err := c.rerr
	c.rmu.Unlock()
	if err != nil {
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, err
	}
	return 0, io.EOF
}

func (c *h2Conn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		c.smu.Lock()
		for c.werr == nil && min32(c.connWin, c.streamWin) <= 0 {
			c.scond.Wait()
		}
		if c.werr != nil {
			err := c.werr
			c.smu.Unlock()
			return total, err
		}
		n := min32(min32(int32(len(b)), h2MaxFrame), min32(c.connWin, c.streamWin))
		c.connWin -= n
		c.streamWin -= n
		c.smu.Unlock()

		chunk := b[:n]
		err := c.lockAndWrite(func() error {
			return c.fr.WriteData(1, false, chunk)
		})
		if err != nil {
			c.failWrites(err)
			return total, err
		}
		total += int(n)
		b = b[n:]
		dbgf("Write: sent %d bytes (total %d)", n, total)
	}
	return total, nil
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func (c *h2Conn) Close() error {
	c.failWrites(io.ErrClosedPipe)
	c.failReads(io.ErrClosedPipe)
	return c.tls.Close()
}

func (c *h2Conn) LocalAddr() net.Addr                { return c.tls.LocalAddr() }
func (c *h2Conn) RemoteAddr() net.Addr               { return c.tls.RemoteAddr() }
func (c *h2Conn) SetDeadline(t time.Time) error      { return c.tls.SetDeadline(t) }
func (c *h2Conn) SetReadDeadline(t time.Time) error  { return c.tls.SetReadDeadline(t) }
func (c *h2Conn) SetWriteDeadline(t time.Time) error { return c.tls.SetWriteDeadline(t) }
