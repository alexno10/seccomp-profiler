//go:build linux

package main

import (
	"fmt"
	"syscall"
)

func kernelRelease() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", fmt.Errorf("uname: %w", err)
	}
	buf := make([]byte, 0, len(u.Release))
	for _, b := range u.Release {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf), nil
}
