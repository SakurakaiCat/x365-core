package x365

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// realityDial performs the Reality TLS handshake (xray-core 26.3.27 compatible).
func realityDial(ctx context.Context, rawConn net.Conn, serverName, pbkStr, sidStr, fingerprint string) (net.Conn, error) {
	publicKey, err := decodeBase64URL(pbkStr)
	if err != nil {
		return nil, fmt.Errorf("decode pbk: %w", err)
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid pbk length: %d", len(publicKey))
	}

	var shortID [8]byte
	n, err := hex.Decode(shortID[:], []byte(sidStr))
	if err != nil {
		return nil, fmt.Errorf("decode sid: %w", err)
	}
	if n > 8 {
		return nil, fmt.Errorf("sid too long: %d", n)
	}

	verified := false
	var authKey []byte
	verifyPeer := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				continue
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return errors.New("no certs")
		}
		if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if hmac.Equal(h.Sum(nil), certs[0].Signature) {
				verified = true
				return nil
			}
		}
		return nil
	}

	uConfig := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifyPeer,
		NextProtos:             []string{"h2", "http/1.1"},
	}

	uConn := utls.UClient(rawConn, uConfig, utls.HelloChrome_Auto)
	uConn.BuildHandshakeState()

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0] = 26 // xray-core Version_x
	hello.SessionId[1] = 3  // Version_y
	hello.SessionId[2] = 27 // Version_z
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID[:])

	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh pubkey: %w", err)
	}
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		return nil, errors.New("no ECDHE key share")
	}
	authKey, err = ecdhe.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	aesBlock, _ := aes.NewCipher(authKey)
	aesGcm, _ := cipher.NewGCM(aesBlock)
	aesGcm.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if !verified {
		return nil, errors.New("REALITY handshake FAILED (server returned fallback cert)")
	}
	return uConn, nil
}
