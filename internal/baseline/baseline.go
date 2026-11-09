package baseline

import (
	"path/filepath"
	"sort"
	"strings"
)

type Mode string

const (
	ModeNone     Mode = "none"
	ModeMinimal  Mode = "minimal"
	ModeStandard Mode = "standard"
)

const (
	SourceObserved   = "observed"
	SourceRuntime    = "baseline-runtime"
	SourceLifecycle  = "baseline-lifecycle"
	SourceExtraAllow = "extra-allow"
)

func LangSource(lang string) string {
	return "baseline-lang:" + lang
}

var runtimeSyscalls = []string{
	"access",
	"arch_prctl",
	"capget",
	"capset",
	"chdir",
	"dup2",
	"dup3",
	"epoll_create1",
	"epoll_ctl",
	"epoll_pwait",
	"execve",
	"faccessat",
	"faccessat2",
	"fchown",
	"fcntl",
	"fstat",
	"fstatfs",
	"futex",
	"getcwd",
	"getdents64",
	"getegid",
	"geteuid",
	"getgid",
	"getgroups",
	"getpid",
	"getppid",
	"getrandom",
	"gettid",
	"getuid",
	"ioctl",
	"lseek",
	"mmap",
	"mprotect",
	"newfstatat",
	"openat",
	"openat2",
	"pipe2",
	"ppoll",
	"prctl",
	"pread64",
	"prlimit64",
	"pselect6",
	"read",
	"readlinkat",
	"rseq",
	"set_robust_list",
	"set_tid_address",
	"setgid",
	"setgroups",
	"setresgid",
	"setresuid",
	"setuid",
	"statfs",
	"statx",
	"write",
	"writev",
}

var lifecycleSyscalls = []string{
	"brk",
	"clock_gettime",
	"clock_nanosleep",
	"close",
	"close_range",
	"exit",
	"exit_group",
	"madvise",
	"munmap",
	"nanosleep",
	"restart_syscall",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"sched_yield",
	"sigaltstack",
	"tgkill",
}

var langSyscalls = map[string][]string{
	"go": {
		"arch_prctl",
		"epoll_create1",
		"epoll_ctl",
		"epoll_pwait",
		"fcntl",
		"fstat",
		"getrandom",
		"getsockname",
		"mmap",
		"mprotect",
		"newfstatat",
		"pipe2",
		"pread64",
		"rseq",
		"sched_getaffinity",
		"set_tid_address",
		"uname",
	},
	"node": {
		"epoll_create1",
		"epoll_ctl",
		"epoll_pwait",
		"eventfd2",
		"fcntl",
		"fstat",
		"getcwd",
		"getrandom",
		"mmap",
		"mprotect",
		"newfstatat",
		"pipe2",
		"pread64",
		"rseq",
		"set_robust_list",
		"set_tid_address",
		"uname",
	},
	"python": {
		"fcntl",
		"fstat",
		"getcwd",
		"getdents64",
		"getrandom",
		"lseek",
		"mmap",
		"mprotect",
		"newfstatat",
		"pread64",
		"rseq",
		"set_robust_list",
		"set_tid_address",
		"sysinfo",
		"uname",
	},
	"java": {
		"clock_getres",
		"fstat",
		"getcwd",
		"getdents64",
		"getrandom",
		"lseek",
		"mmap",
		"mprotect",
		"newfstatat",
		"pread64",
		"prlimit64",
		"rseq",
		"sched_getaffinity",
		"set_robust_list",
		"set_tid_address",
		"sysinfo",
		"uname",
	},
}

func LayerSyscalls(mode Mode, runtimeName string) map[string][]string {
	out := make(map[string][]string)
	if mode == ModeMinimal || mode == ModeStandard {
		out[SourceRuntime] = append([]string(nil), runtimeSyscalls...)
	}
	if mode == ModeStandard {
		out[SourceLifecycle] = append([]string(nil), lifecycleSyscalls...)
	}
	rt := strings.ToLower(strings.TrimSpace(runtimeName))
	if rt != "" && rt != "none" && rt != "auto" {
		if list, ok := langSyscalls[rt]; ok {
			out[LangSource(rt)] = append([]string(nil), list...)
		}
	}
	return out
}

func DetectRuntimes(executedBins []string, imageName string) []string {
	seen := make(map[string]bool)
	for _, b := range executedBins {
		base := strings.ToLower(filepath.Base(strings.ReplaceAll(b, "\\", "/")))
		switch {
		case strings.HasPrefix(base, "python") || strings.HasPrefix(base, "pypy"):
			seen["python"] = true
		case base == "node" || base == "nodejs":
			seen["node"] = true
		case base == "java":
			seen["java"] = true
		case base == "go":
			seen["go"] = true
		}
	}
	imgLower := strings.ToLower(imageName)
	switch {
	case strings.Contains(imgLower, "python"):
		seen["python"] = true
	case strings.Contains(imgLower, "node"):
		seen["node"] = true
	case strings.Contains(imgLower, "openjdk") || strings.Contains(imgLower, "temurin") || strings.Contains(imgLower, "java"):
		seen["java"] = true
	case strings.Contains(imgLower, "golang"):
		seen["go"] = true
	}

	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
