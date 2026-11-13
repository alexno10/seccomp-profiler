package ebpf_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
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

func TestBPFErrorStatsAndSafetyInvariants(t *testing.T) {
	bpfSrc, err := os.ReadFile(filepath.Join("..", "..", "bpf", "profiler.bpf.c"))
	if err != nil {
		t.Fatalf("read profiler.bpf.c: %v", err)
	}
	src := string(bpfSrc)

	// Task 1: error_stats must use BPF_MAP_TYPE_ARRAY so slot 0 is pre-allocated.
	if !strings.Contains(src, "#define BPF_MAP_TYPE_ARRAY 2") {
		t.Fatal("missing BPF_MAP_TYPE_ARRAY definition")
	}
	errorStatsIdx := strings.Index(src, "} error_stats SEC(\".maps\");")
	if errorStatsIdx == -1 || errorStatsIdx < 160 {
		t.Fatalf("unexpected error_stats definition in profiler.bpf.c")
	}
	errorStatsBlock := src[errorStatsIdx-160 : errorStatsIdx]
	if !strings.Contains(errorStatsBlock, "BPF_MAP_TYPE_ARRAY") {
		t.Fatalf("error_stats must use BPF_MAP_TYPE_ARRAY, got:\n%s", errorStatsBlock)
	}

	// Task 1: id < 0 must be checked before is_compat_syscall(id) so syscall(-1) hits oob_syscalls.
	sysEnterIdx := strings.Index(src, "int handle_sys_enter(")
	if sysEnterIdx == -1 {
		t.Fatal("missing handle_sys_enter")
	}
	sysEnterBody := src[sysEnterIdx:]
	negIdx := strings.Index(sysEnterBody, "id < 0")
	compatIdx := strings.Index(sysEnterBody, "is_compat_syscall(id)")
	if negIdx == -1 || compatIdx == -1 || negIdx > compatIdx {
		t.Fatalf("handle_sys_enter must check id < 0 before is_compat_syscall(id) (negIdx=%d compatIdx=%d)", negIdx, compatIdx)
	}

	// Task 1: unsupported target arch must fail compile instead of defaulting to x86.
	if !strings.Contains(src, "__TARGET_ARCH_x86") || !strings.Contains(src, "#error") {
		t.Fatal("profiler.bpf.c must explicitly check __TARGET_ARCH_x86 and error on unsupported arch")
	}

	// Task 2: is_runtime_selfref must not treat empty filename as self-ref.
	selfRefIdx := strings.Index(src, "int is_runtime_selfref(")
	if selfRefIdx == -1 {
		t.Fatal("missing is_runtime_selfref")
	}
	selfRefEnd := strings.Index(src[selfRefIdx:], "\n}")
	selfRefBody := src[selfRefIdx : selfRefIdx+selfRefEnd]
	if strings.Contains(selfRefBody, "filename[0] == '\\0'") {
		t.Fatal("is_runtime_selfref must not treat empty filename as self-referential")
	}

	// Task 2: post-exec in handle_sched_process_exec must not keep tid suppressed solely via is_runtime_comm.
	execIdx := strings.Index(src, "int handle_sched_process_exec(")
	if execIdx == -1 {
		t.Fatal("missing handle_sched_process_exec")
	}
	execBody := src[execIdx:sysEnterIdx]
	if strings.Contains(execBody, "is_runtime_comm(comm)") {
		t.Fatal("handle_sched_process_exec must not suppress workload entrypoints merely named runc/crun")
	}

	// Task 2: sched_process_exit cleanup must exist.
	if !strings.Contains(src, "tracepoint/sched/sched_process_exit") {
		t.Fatal("missing sched_process_exit cleanup hook")
	}

	// Task 2: fork/exec hooks must block non-runtime threads already inside syscalls_per_cgroup.
	forkIdx := strings.Index(src, "int handle_sched_process_fork(")
	execEnterIdx := strings.Index(src, "int handle_exec_enter(")
	if forkIdx == -1 || execEnterIdx == -1 {
		t.Fatal("missing fork or exec_enter hook")
	}
	forkBody := src[forkIdx:execEnterIdx]
	if !strings.Contains(forkBody, "syscalls_per_cgroup") {
		t.Fatal("handle_sched_process_fork must reject untracked threads inside tracked container cgroups")
	}
	execEnterBody := src[execEnterIdx:execIdx]
	if !strings.Contains(execEnterBody, "syscalls_per_cgroup") {
		t.Fatal("handle_exec_enter must reject untracked threads inside tracked container cgroups")
	}

	// Tracked runtime_tids (e.g. runc child whose comm became "exe" after execve("/proc/self/exe")
	// before ensure_cloned_binary()'s fexecve(memfd) and before prctl(PR_SET_NAME)) must keep
	// exec_pending and fork propagation without re-checking is_runtime_family_comm.
	assertRuntimeGuardWrapsCommCheck := func(fnName, body string) {
		t.Helper()
		guardIdx := strings.Index(body, "if (!bpf_map_lookup_elem(&runtime_tids")
		if guardIdx == -1 {
			t.Fatalf("%s missing !runtime_tids guard", fnName)
		}
		openIdx := strings.Index(body[guardIdx:], "{")
		if openIdx == -1 {
			t.Fatalf("%s malformed !runtime_tids block", fnName)
		}
		depth := 0
		blockEnd := -1
		for i := guardIdx + openIdx; i < len(body); i++ {
			switch body[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					blockEnd = i + 1
				}
			}
			if blockEnd != -1 {
				break
			}
		}
		if blockEnd == -1 {
			t.Fatalf("%s unclosed !runtime_tids block", fnName)
		}
		guardBlock := body[guardIdx:blockEnd]
		if !strings.Contains(guardBlock, "syscalls_per_cgroup") || !strings.Contains(guardBlock, "is_runtime_family_comm") {
			t.Fatalf("%s must check is_runtime_family_comm only inside the !runtime_tids guard so runtime tids renamed to \"exe\" across /proc/self/exe are not dropped", fnName)
		}
		if strings.Contains(body[blockEnd:], "is_runtime_family_comm") {
			t.Fatalf("%s must not require is_runtime_family_comm outside the !runtime_tids guard", fnName)
		}
	}
	assertRuntimeGuardWrapsCommCheck("handle_sched_process_fork", forkBody)
	assertRuntimeGuardWrapsCommCheck("handle_exec_enter", execEnterBody)

	// Task 2: execve/execveat must be dispatched from raw_tracepoint/sys_enter (not
	// tracepoint/syscalls/sys_enter_execve{,at}) because cilium/ebpf link.Tracepoint
	// attaches perf events on CPU 0 only and misses syscalls on CPUs 1..N on Linux 7.0+.
	for _, banned := range []string{"sys_enter_execve", "sys_enter_execveat", "bpf_trace_printk", "bpf_printk("} {
		if strings.Contains(src, banned) {
			t.Fatalf("profiler.bpf.c must not use %q", banned)
		}
	}
	if !strings.Contains(src, "int is_execve_syscall(") {
		t.Fatal("missing is_execve_syscall helper in profiler.bpf.c")
	}
	execDispatchIdx := strings.Index(sysEnterBody, "if (is_execve_syscall(id))")
	statsCheckIdx := strings.Index(sysEnterBody, "if (!stats)")
	if execDispatchIdx == -1 || statsCheckIdx == -1 || execDispatchIdx > statsCheckIdx {
		t.Fatalf("handle_sys_enter must dispatch is_execve_syscall(id) before !stats early return (execIdx=%d statsIdx=%d)", execDispatchIdx, statsCheckIdx)
	}
	collectorLinuxSrc, err := os.ReadFile(filepath.Join(".", "collector_linux.go"))
	if err != nil {
		t.Fatalf("read collector_linux.go: %v", err)
	}
	for _, banned := range []string{"sys_enter_execve", "sys_enter_execveat"} {
		if strings.Contains(string(collectorLinuxSrc), banned) {
			t.Fatalf("collector_linux.go must not attach per-syscall tracepoint %q", banned)
		}
	}
}

func TestSelectBPFCollectionSourcePrecedence(t *testing.T) {
	// 1. When embeddedBPFObj is present and no explicit CLI --bpf-obj was passed,
	// embedded bytecode MUST take precedence over ambient CWD/env files.
	useEmbed, diskPath := ebpf.SelectBPFCollectionSource("", 1024, func(string) string {
		return "bpf/profiler.bpf.o"
	})
	if !useEmbed || diskPath != "" {
		t.Fatalf("expected embeddedBPFObj precedence when explicit=\"\" and embeddedLen>0, got useEmbed=%v diskPath=%q", useEmbed, diskPath)
	}

	// 2. Explicit --bpf-obj CLI flag takes precedence even when embeddedBPFObj exists.
	useEmbed, diskPath = ebpf.SelectBPFCollectionSource("/opt/custom/profiler.bpf.o", 1024, func(string) string {
		return "bpf/profiler.bpf.o"
	})
	if useEmbed || diskPath != "/opt/custom/profiler.bpf.o" {
		t.Fatalf("expected explicit path override, got useEmbed=%v diskPath=%q", useEmbed, diskPath)
	}

	// 3. When embeddedBPFObj is absent (no_embed_bpf), fall back to disk resolver.
	useEmbed, diskPath = ebpf.SelectBPFCollectionSource("", 0, func(string) string {
		return "/usr/local/share/seccomp-profiler/profiler.bpf.o"
	})
	if useEmbed || diskPath != "/usr/local/share/seccomp-profiler/profiler.bpf.o" {
		t.Fatalf("expected fallback disk path when embeddedLen==0, got useEmbed=%v diskPath=%q", useEmbed, diskPath)
	}

	collectorLinuxSrc, err := os.ReadFile(filepath.Join(".", "collector_linux.go"))
	if err != nil {
		t.Fatalf("read collector_linux.go: %v", err)
	}
	if !strings.Contains(string(collectorLinuxSrc), "SelectBPFCollectionSource(") {
		t.Fatal("collector_linux.go must use SelectBPFCollectionSource to ensure embeddedBPFObj precedence")
	}
}
