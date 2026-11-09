//go:build !linux

package docker

import (
	"fmt"
	"os"
	"reflect"
)

// statInode is only exercised by unit tests on non-Linux platforms; the
// daemon itself never runs off-Linux.
func statInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys := fi.Sys()
	if sys == nil {
		return 0, fmt.Errorf("no underlying stat info for %s", path)
	}
	v := reflect.ValueOf(sys)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	f := v.FieldByName("Ino")
	if !f.IsValid() {
		return 0, fmt.Errorf("no Ino field on stat for %s", path)
	}
	return f.Uint(), nil
}
