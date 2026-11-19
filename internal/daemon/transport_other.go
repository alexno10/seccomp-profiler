//go:build !windows

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/profile"
)

var unixSocketUmaskMu sync.Mutex

func listenControl(network, address string) (net.Listener, error) {
	if network == "unix" {
		if err := profile.EnsureNoSymlinkDir(filepath.Dir(address), 0o755); err != nil {
			return nil, fmt.Errorf("prepare control socket dir: %w", err)
		}
		if fi, err := os.Lstat(address); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("refusing to remove non-socket path %q", address)
			}
			// Do not steal an active daemon's socket.
			if conn, dErr := net.DialTimeout("unix", address, 200*time.Millisecond); dErr == nil {
				_ = conn.Close()
				return nil, fmt.Errorf("control socket %q is already in use", address)
			}
			if err := os.Remove(address); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("remove stale control socket %q: %w", address, err)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}

		// Create the Unix socket with atomic 0600 permissions (eliminates the
		// post-Listen os.Chmod race / symlink window).
		unixSocketUmaskMu.Lock()
		oldUmask := syscall.Umask(0o177)
		ln, err := net.Listen(network, address)
		syscall.Umask(oldUmask)
		unixSocketUmaskMu.Unlock()
		return ln, err
	}
	return net.Listen(network, address)
}

func dialControl(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}
