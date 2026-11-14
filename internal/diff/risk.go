package diff

type RiskLevel string

const (
	RiskHigh   RiskLevel = "high"
	RiskMedium RiskLevel = "medium"
	RiskLow    RiskLevel = "low"
)

var highRiskSyscalls = map[string]string{
	"ptrace":            "Container escape / process memory inspection & injection",
	"process_vm_readv":  "Direct cross-process memory read",
	"process_vm_writev": "Direct cross-process memory write",
	"process_madvise":   "Cross-process memory manipulation",
	"pidfd_getfd":       "Steal file descriptors from other processes",
	"mount":             "Filesystem namespace manipulation",
	"umount2":           "Filesystem namespace manipulation",
	"fsopen":            "New mount API filesystem manipulation",
	"fsmount":           "New mount API filesystem manipulation",
	"fsconfig":          "New mount API filesystem manipulation",
	"fspick":            "New mount API filesystem manipulation",
	"move_mount":        "New mount API filesystem manipulation",
	"open_tree":         "New mount API filesystem manipulation",
	"mount_setattr":     "New mount API filesystem manipulation",
	"pivot_root":        "Root filesystem replacement",
	"unshare":           "Kernel namespace creation / escape vector",
	"setns":             "Kernel namespace switching",
	"bpf":               "Kernel eBPF program loading / tracing",
	"perf_event_open":   "Kernel performance monitoring / side-channel surface",
	"userfaultfd":       "Kernel heap exploitation primitive (page fault handling)",
	"io_uring_setup":    "io_uring kernel async interface (large historical CVE surface)",
	"io_uring_enter":    "io_uring kernel async interface (large historical CVE surface)",
	"io_uring_register": "io_uring kernel async interface (large historical CVE surface)",
	"keyctl":            "Kernel keyring manipulation",
	"add_key":           "Kernel keyring manipulation",
	"request_key":       "Kernel keyring manipulation",
	"init_module":       "Kernel module loading",
	"finit_module":      "Kernel module loading",
	"delete_module":     "Kernel module unloading",
	"kexec_load":        "Kernel replacement (kexec)",
	"kexec_file_load":   "Kernel replacement (kexec)",
	"open_by_handle_at": "Host filesystem traversal (Docker Shocker escape)",
	"name_to_handle_at": "File handle extraction for open_by_handle_at",
	"kcmp":              "Kernel process comparison / information leak",
	"ioperm":            "Direct hardware I/O port access",
	"iopl":              "Direct hardware I/O privilege level change",
	"swapon":            "Host swap manipulation",
	"swapoff":           "Host swap manipulation",
	"reboot":            "System reboot / halt",
	"acct":              "Process accounting manipulation",
	"quotactl":          "Filesystem quota manipulation",
	"quotactl_fd":       "Filesystem quota manipulation via file descriptor",
	"syslog":            "Kernel ring buffer (dmesg) access",
	"clock_settime":     "System clock manipulation (keystone/timing attacks)",
	"clock_adjtime":     "Kernel clock adjustment",
	"settimeofday":      "System clock manipulation",
	"adjtimex":          "Kernel time adjustment",
	"sethostname":       "Host (UTS namespace outside container) identity change",
	"setdomainname":     "Host (UTS namespace outside container) identity change",
	"personality":       "Execution domain change (disable ASLR via ADDR_NO_RANDOMIZE)",
	"modify_ldt":        "Architecture-specific x86 LDT modification",
	"lsm_set_self_attr": "Linux Security Module self-attribute modification",
	"fanotify_init":     "Kernel filesystem notification (host-wide file monitoring)",
	"lookup_dcookie":    "Kernel cookie lookup / tracing surface",
	"move_pages":        "Cross-process page migration",
	"migrate_pages":     "Cross-process page migration",
	"uselib":            "Legacy shared library loading (binary injection vector)",
	"vhangup":           "Terminal hangup manipulation",
}

var mediumRiskSyscalls = map[string]string{
	"socket":    "New network or IPC socket creation",
	"connect":   "Outbound network or socket connection",
	"bind":      "Network port or socket binding",
	"listen":    "Listening for incoming connections",
	"accept":    "Accepting incoming connections",
	"accept4":   "Accepting incoming connections",
	"execve":    "Executing new binary",
	"execveat":  "Executing new binary via file descriptor",
	"clone":     "Process or thread creation (namespace flags must stay arg-constrained)",
	"clone3":    "Process or thread creation (namespace flags must stay arg-constrained)",
	"fork":      "Child process creation",
	"vfork":     "Child process creation",
	"chown":     "File ownership modification",
	"fchown":    "File ownership modification",
	"fchownat":  "File ownership modification",
	"lchown":    "Symlink ownership modification",
	"chmod":     "File permission / setuid bit modification",
	"fchmod":    "File permission / setuid bit modification",
	"fchmodat":  "File permission / setuid bit modification",
	"fchmodat2": "File permission / setuid bit modification",
	"setuid":    "User identity change",
	"setgid":    "Group identity change",
	"setgroups": "Supplementary group identity change",
	"setfsuid":  "Filesystem user identity change",
	"setfsgid":  "Filesystem group identity change",
	"setreuid":  "Real/effective user ID change",
	"setregid":  "Real/effective group ID change",
	"setresuid": "Real/effective/saved user ID change",
	"setresgid": "Real/effective/saved group ID change",
	"capset":    "Process capability modification",
	"chroot":    "Root directory change",
	"mknod":     "Special or device node creation",
	"mknodat":   "Special or device node creation",
	"ioctl":     "Device-specific control operation",
}

// ClassifySyscall classifies a syscall by name only (assumes an unconditional
// allow rule). Callers that know whether the rule carries argument constraints
// should use ClassifySyscallRule instead.
func ClassifySyscall(name string) (RiskLevel, string) {
	return ClassifySyscallRule(name, false)
}

// ClassifySyscallRule classifies a syscall rule. clone/clone3 only match the
// medium tier when the allow rule is arg-constrained (CLONE_NEW* masked out);
// an unconditional clone allow is equivalent to unshare and is high risk.
func ClassifySyscallRule(name string, hasArgs bool) (RiskLevel, string) {
	if reason, ok := highRiskSyscalls[name]; ok {
		return RiskHigh, reason
	}
	if reason, ok := mediumRiskSyscalls[name]; ok {
		if (name == "clone" || name == "clone3") && !hasArgs {
			return RiskHigh, "Unconditional clone allow enables namespace creation (equivalent to unshare); constrain with CLONE_NEW* arg mask"
		}
		return RiskMedium, reason
	}
	return RiskLow, "Standard container process operation"
}
