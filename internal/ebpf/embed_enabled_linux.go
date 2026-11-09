//go:build linux && embed_bpf

package ebpf

import _ "embed"

//go:embed profiler.bpf.o
var embeddedBPFObj []byte
