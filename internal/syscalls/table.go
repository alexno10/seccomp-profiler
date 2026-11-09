package syscalls

//go:generate go run ./gen

type Arch string

const (
	ArchAMD64 Arch = "amd64"
	ArchARM64 Arch = "arm64"
)

func NameByNumber(arch Arch, nr int) (string, bool) {
	switch arch {
	case ArchAMD64:
		name, ok := nameByNr_amd64[nr]
		return name, ok
	case ArchARM64:
		name, ok := nameByNr_arm64[nr]
		return name, ok
	default:
		return "", false
	}
}

func NumberByName(arch Arch, name string) (int, bool) {
	switch arch {
	case ArchAMD64:
		nr, ok := nrByName_amd64[name]
		return nr, ok
	case ArchARM64:
		nr, ok := nrByName_arm64[name]
		return nr, ok
	default:
		return 0, false
	}
}

func SeccompArchitectures(arch Arch, includeCompat bool) []string {
	switch arch {
	case ArchARM64:
		if includeCompat {
			return []string{"SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"}
		}
		return []string{"SCMP_ARCH_AARCH64"}
	default:
		if includeCompat {
			return []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}
		}
		return []string{"SCMP_ARCH_X86_64"}
	}
}
