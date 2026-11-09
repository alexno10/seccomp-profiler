//go:build linux

package docker

import (
	"os"
	"syscall"
)

func statInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, syscall.EINVAL
	}
	return st.Ino, nil
}
