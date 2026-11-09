//go:build !windows

package daemon

import (
	"net"
	"time"
)

func listenControl(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func dialControl(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}
