//go:build !windows

package daemon

import (
	"net"
	"os"
	"time"
)

func listenControl(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		// Force root-only socket access regardless of process umask so local
		// unprivileged users cannot issue STOP or probe control commands.
		if err := os.Chmod(address, 0o600); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

func dialControl(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}
