//go:build linux

package ebpf

import (
	"errors"
	"sync"
	"testing"
)

func TestLinuxCollectorCloseDetachIdempotentAndClosedGuards(t *testing.T) {
	c := &linuxCollector{
		eventsCh: make(chan KernelEvent, 1),
		doneCh:   make(chan struct{}),
		readDone: make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := c.Detach(); err != nil {
				t.Errorf("Detach[%d] unexpected error: %v", idx, err)
			}
			if idx%2 == 0 {
				_, _ = c.Flush()
				_, _, _ = c.FlushCgroup(42)
				_, _ = c.ErrorStats()
				_ = c.TrackCgroup(42)
				_ = c.DeleteCgroup(42)
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close[%d] unexpected error: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	if err := c.Detach(); err != nil {
		t.Fatalf("post-Close Detach() error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}

	if err := c.TrackCgroup(100); !errors.Is(err, errCollectorClosed) {
		t.Fatalf("TrackCgroup after Close = %v, want %v", err, errCollectorClosed)
	}
	if _, err := c.Flush(); !errors.Is(err, errCollectorClosed) {
		t.Fatalf("Flush after Close = %v, want %v", err, errCollectorClosed)
	}
	if _, _, err := c.FlushCgroup(100); !errors.Is(err, errCollectorClosed) {
		t.Fatalf("FlushCgroup after Close = %v, want %v", err, errCollectorClosed)
	}
	if err := c.DeleteCgroup(100); !errors.Is(err, errCollectorClosed) {
		t.Fatalf("DeleteCgroup after Close = %v, want %v", err, errCollectorClosed)
	}
	if _, err := c.ErrorStats(); !errors.Is(err, errCollectorClosed) {
		t.Fatalf("ErrorStats after Close = %v, want %v", err, errCollectorClosed)
	}
}

func TestLinuxCollectorCloseWaitsForReadLoopExit(t *testing.T) {
	c := &linuxCollector{
		eventsCh:    make(chan KernelEvent, 1),
		doneCh:      make(chan struct{}),
		readDone:    make(chan struct{}),
		readStarted: true,
	}

	readExited := make(chan struct{})
	go func() {
		defer close(readExited)
		defer close(c.readDone)
		defer close(c.eventsCh)
		<-c.doneCh
	}()

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	select {
	case <-readExited:
	default:
		t.Fatal("Close() returned before readLoop exited")
	}
	if _, ok := <-c.Events(); ok {
		t.Fatal("Events() channel should be closed after Close() returns")
	}
}
