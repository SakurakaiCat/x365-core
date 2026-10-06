package x365

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// X365Config holds the parsed configuration from an x365:// URI.
type X365Config struct {
	UUID        [16]byte
	Server      string
	Port        uint16
	Path        string
	Host        string
	SNI         string
	PublicKey   string
	ShortID     string
	Fingerprint string
	// Transport selects the wire protocol: "xhttp" (XHTTP over HTTP/2, the
	// default) or "h1" (the legacy HTTP/1.1 chunked transport). The h1
	// transport expects the server-side auth token below; xhttp does not
	// require it (but it is sent when set, matching normal client traffic).
	Transport string
	// Token is the account JWT ("access token"). Recommended for both
	// transports; the server is strictest about it on the h1 route.
	Token string
}

// Wire-format constants.
const (
	// BrowserUserAgent is the user-agent sent with tunnel requests (Chrome
	// 120 on Windows 64-bit), matching the traffic profile the server expects.
	BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	// xPaddingLen is the length of the "?x_padding=" filler appended to the
	// request path (observed: 65 'X' bytes).
	xPaddingLen = 65
)

// Label extracts the human-readable name from the URI fragment (e.g. "#香港").
func Label(uri string) string {
	if idx := strings.Index(uri, "#"); idx >= 0 {
		return strings.TrimSpace(uri[idx+1:])
	}
	return ""
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return uuid, err
	}
	copy(uuid[:], b)
	return uuid, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	for len(s)%4 != 0 {
		s += "="
	}
	dec := make([]byte, 0, len(s)*3/4)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lookup := func(c byte) int {
		for i := 0; i < len(alphabet); i++ {
			if alphabet[i] == c {
				return i
			}
		}
		return -1
	}
	var val uint32
	var bits int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		idx := lookup(c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base64 char: %c", c)
		}
		val = (val << 6) | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			dec = append(dec, byte(val>>uint(bits)))
			val &= (1 << uint(bits)) - 1
		}
	}
	return dec, nil
}

// ParseURI parses an x365:// URI into an X365Config.
func ParseURI(uri string) (*X365Config, error) {
	if !strings.HasPrefix(uri, "x365://") {
		return nil, errors.New("not an x365:// URI")
	}
	uri = strings.TrimPrefix(uri, "x365://")

	if idx := strings.Index(uri, "#"); idx >= 0 {
		uri = uri[:idx]
	}

	var query string
	if idx := strings.Index(uri, "?"); idx >= 0 {
		query = uri[idx+1:]
		uri = uri[:idx]
	}

	atIdx := strings.Index(uri, "@")
	if atIdx < 0 {
		return nil, errors.New("missing @ in x365:// URI")
	}
	uuidStr := uri[:atIdx]
	hostPort := uri[atIdx+1:]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	cfg := &X365Config{
		UUID:   uuid,
		Server: host,
		Port:   port,
	}

	if query != "" {
		vals, err := url.ParseQuery(query)
		if err != nil {
			return nil, err
		}
		cfg.Path = vals.Get("path")
		cfg.Host = vals.Get("host")
		cfg.SNI = vals.Get("sni")
		if cfg.SNI == "" {
			cfg.SNI = cfg.Host
		}
		cfg.PublicKey = vals.Get("pbk")
		cfg.ShortID = vals.Get("sid")
		cfg.Fingerprint = vals.Get("fp")
		if cfg.Fingerprint == "" {
			cfg.Fingerprint = "chrome"
		}
		cfg.Token = vals.Get("token")
		t := vals.Get("type")
		if t == "" {
			t = vals.Get("network")
		}
		switch t {
		case "":
			cfg.Transport = "xhttp" // default transport
		case "xhttp", "splithttp":
			cfg.Transport = "xhttp"
		case "h1", "http":
			cfg.Transport = "h1"
		default:
			return nil, fmt.Errorf("unsupported transport %q", t)
		}
	}

	return cfg, nil
}

// buildX365Header constructs the binary X365 protocol header.
func buildX365Header(uuid [16]byte, port uint16, targetHost string) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, 'X', '3', '6', '5', 0x01) // magic + const
	buf = append(buf, 0x01)                     // TCP
	buf = append(buf, uuid[:]...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	buf = append(buf, pb...)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x03)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, 0x02)
		buf = append(buf, byte(len(targetHost)))
		buf = append(buf, []byte(targetHost)...)
	}
	return buf
}
