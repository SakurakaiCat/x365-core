package x365

import (
	"fmt"
	"log"
	"sync"
)

// LogFunc is the signature for log callbacks. Set via SetLogger.
type LogFunc func(format string, args ...interface{})

var (
	logMu  sync.RWMutex
	logFn  LogFunc
)

// SetLogger installs a custom log callback. Pass nil to revert to the default
// (standard library log.Printf). This is used by the mobile binding to forward
// Go-side logs (SOCKS5 connections, tunnel errors, etc.) to the Android UI.
func SetLogger(fn LogFunc) {
	logMu.Lock()
	defer logMu.Unlock()
	logFn = fn
}

// loggerf is the internal dispatch: if a custom callback is set, it is used;
// otherwise the standard log.Printf is called.
func loggerf(format string, args ...interface{}) {
	logMu.RLock()
	fn := logFn
	logMu.RUnlock()

	if fn != nil {
		fn(format, args...)
		return
	}
	log.Printf(format, args...)
}

// logf is a convenience wrapper that prepends a prefix.
func logf(prefix, format string, args ...interface{}) {
	loggerf("[%s] "+format, append([]interface{}{prefix}, args...)...)
}

// ensure log is referenced even when a custom logger is set
var _ = log.Printf
var _ = fmt.Sprintf
