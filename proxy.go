package x365

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
)

// ProxyManager manages the SOCKS5 server lifecycle for a single X365 node.
type ProxyManager struct {
	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc
	current  *X365Config
	running  bool
}

// NewProxyManager creates a new ProxyManager.
func NewProxyManager() *ProxyManager {
	return &ProxyManager{}
}

// Start begins listening on listenAddr and tunneling connections through cfg.
// If a server is already running, it is stopped first.
func (pm *ProxyManager) Start(cfg *X365Config, listenAddr string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		pm.stopLocked()
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	pm.listener = ln
	pm.cancel = cancel
	pm.current = cfg
	pm.running = true

	go pm.acceptLoop(ctx, ln, cfg)

	log.Printf("SOCKS5 server listening on %s (node %s)", listenAddr, cfg.Path)
	return nil
}

// Stop shuts down the SOCKS5 server.
func (pm *ProxyManager) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.stopLocked()
}

func (pm *ProxyManager) stopLocked() error {
	if !pm.running {
		return nil
	}
	pm.running = false
	if pm.cancel != nil {
		pm.cancel()
		pm.cancel = nil
	}
	var err error
	if pm.listener != nil {
		err = pm.listener.Close()
		pm.listener = nil
	}
	pm.current = nil
	return err
}

// IsRunning returns whether the SOCKS5 server is currently active.
func (pm *ProxyManager) IsRunning() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.running
}

// CurrentNode returns the currently connected node config, or nil if not running.
func (pm *ProxyManager) CurrentNode() *X365Config {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.current
}

func (pm *ProxyManager) acceptLoop(ctx context.Context, ln net.Listener, cfg *X365Config) {
	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("accept: %v", err)
				continue
			}
		}
		go handleSOCKS5(client, cfg)
	}
}

// ErrNotRunning is returned when an operation requires a running proxy.
var ErrNotRunning = errors.New("proxy not running")
