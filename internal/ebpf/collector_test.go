package ebpf_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

func TestDecodeKernelEvent(t *testing.T) {
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, uint32(ebpf.EventCgroupMkdir))
	_ = binary.Write(&raw, binary.LittleEndian, uint32(0))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(424242))
	var pathBytes [256]byte
	copy(pathBytes[:], "/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope")
	raw.Write(pathBytes[:])

	ev, err := ebpf.DecodeKernelEvent(raw.Bytes())
	if err != nil {
		t.Fatalf("DecodeKernelEvent failed: %v", err)
	}
	if ev.CgroupID != 424242 || ev.CgroupPath == "" || ev.ExecFilename != "" {
		t.Fatalf("unexpected decoded mkdir event: %+v", ev)
	}

	raw.Reset()
	_ = binary.Write(&raw, binary.LittleEndian, uint32(ebpf.EventExec))
	_ = binary.Write(&raw, binary.LittleEndian, uint32(0))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(424242))
	var execBytes [256]byte
	copy(execBytes[:], "/usr/local/bin/python3")
	raw.Write(execBytes[:])

	evExec, err := ebpf.DecodeKernelEvent(raw.Bytes())
	if err != nil {
		t.Fatalf("DecodeKernelEvent exec failed: %v", err)
	}
	if evExec.CgroupID != 424242 || evExec.ExecFilename != "/usr/local/bin/python3" {
		t.Fatalf("unexpected decoded exec event: %+v", evExec)
	}
}

func isHexCharMirror(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func checkHexAnchorMirror(path *[256]byte, anchor int) bool {
	if !isHexCharMirror(path[anchor]) {
		return false
	}
	left := 0
	for k := 1; k <= 63; k++ {
		if !isHexCharMirror(path[anchor-k]) {
			break
		}
		left++
	}
	needed := 63 - left
	for r := 1; r <= 63; r++ {
		if r > needed {
			return true
		}
		if !isHexCharMirror(path[anchor+r]) {
			return false
		}
	}
	return true
}

func has64HexIDMirror(s string) bool {
	var buf [256]byte
	if len(s) >= 256 {
		copy(buf[:255], s[:255])
	} else {
		copy(buf[:], s)
	}
	return checkHexAnchorMirror(&buf, 63) || checkHexAnchorMirror(&buf, 127) || checkHexAnchorMirror(&buf, 191)
}

func TestAnchor64HexDetectionExhaustiveOffsets(t *testing.T) {
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for start := 0; start <= 191; start++ {
		prefix := bytes.Repeat([]byte{'/'}, start)
		path := string(prefix) + cid + ".scope"
		if len(path) > 255 {
			path = path[:255]
		}
		if !has64HexIDMirror(path) {
			t.Fatalf("expected 64-hex match at start offset %d", start)
		}
	}
	// 63 hex chars must never match at any offset
	shortCID := cid[:63]
	for start := 0; start <= 192; start++ {
		prefix := bytes.Repeat([]byte{'/'}, start)
		path := string(prefix) + shortCID + ".scope"
		if len(path) > 255 {
			path = path[:255]
		}
		if has64HexIDMirror(path) {
			t.Fatalf("unexpected match for 63-hex string at offset %d", start)
		}
	}
}
