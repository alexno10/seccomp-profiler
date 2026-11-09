//go:build windows

package daemon

import (
	"net"
	"sync"
	"time"
)

// The Windows path exists only so unit tests can run on a Windows dev box
// (the daemon itself requires Linux eBPF). Windows AppContainer sandboxes can
// block WinSock socket creation, so tests fall back to an in-process
// net.Pipe listener instead of shipping test scaffolding in the shared code.

var (
	inprocMu        sync.Mutex
	inprocListeners = make(map[string]*pipeListener)
)

type pipeAddr string

func (p pipeAddr) Network() string { return "pipe" }
func (p pipeAddr) String() string  { return string(p) }

type pipeListener struct {
	addr   string
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		inprocMu.Lock()
		delete(inprocListeners, l.addr)
		inprocMu.Unlock()
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.addr) }

func listenControl(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err == nil {
		return ln, nil
	}
	pl := &pipeListener{
		addr:   address,
		ch:     make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
	inprocMu.Lock()
	inprocListeners[address] = pl
	inprocMu.Unlock()
	return pl, nil
}

func dialControl(network, address string, timeout time.Duration) (net.Conn, error) {
	inprocMu.Lock()
	pl, ok := inprocListeners[address]
	inprocMu.Unlock()
	if ok {
		c1, c2 := net.Pipe()
		select {
		case pl.ch <- c1:
			return c2, nil
		case <-pl.closed:
			_ = c1.Close()
			_ = c2.Close()
			return nil, net.ErrClosed
		}
	}
	return net.DialTimeout(network, address, timeout)
}
