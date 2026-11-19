//go:build !linux

package main

func kernelRelease() (string, error) {
	return "", nil
}
