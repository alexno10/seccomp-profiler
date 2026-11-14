//go:build !linux

package ebpf

import "fmt"

func NewCollector(_ string) (Collector, error) {
	return nil, fmt.Errorf("eBPF collector requires a Linux host (kernel 5.19+ with BTF and cgroup v2)")
}
