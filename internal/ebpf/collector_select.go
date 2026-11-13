package ebpf

// SelectBPFCollectionSource determines whether NewCollector loads the embedded
// eBPF object bytes or reads an external .bpf.o file from disk.
//
// Security invariant: when embeddedBPFObj is present (embeddedLen > 0), ambient
// disk files (such as bpf/profiler.bpf.o in a checked-out PR workspace) and
// env-var overrides must not shadow the release-signed embedded bytecode. Only an
// explicit CLI override (explicitPath) or a no-embed build (embeddedLen == 0)
// resolves an external file path.
func SelectBPFCollectionSource(explicitPath string, embeddedLen int, fallbackResolve func(string) string) (useEmbedded bool, diskPath string) {
	if explicitPath != "" {
		return false, explicitPath
	}
	if embeddedLen > 0 {
		return true, ""
	}
	if fallbackResolve != nil {
		return false, fallbackResolve("")
	}
	return false, ""
}
