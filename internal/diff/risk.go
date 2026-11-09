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
	"mount":             "Filesystem namespace manipulation",
	"umount2":           "Filesystem namespace manipulation",
	"pivot_root":        "Root filesystem replacement",
	"unshare":           "Kernel namespace creation / escape vector",
	"setns":             "Kernel namespace switching",
	"bpf":               "Kernel eBPF program loading / tracing",
	"perf_event_open":   "Kernel performance monitoring / side-channel surface",
	"userfaultfd":       "Kernel heap exploitation primitive (page fault handling)",
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
	"ioperm":            "Direct hardware I/O port access",
	"iopl":              "Direct hardware I/O privilege level change",
	"swapon":            "Host swap manipulation",
	"swapoff":           "Host swap manipulation",
	"reboot":            "System reboot / halt",
	"acct":              "Process accounting manipulation",
	"quotactl":          "Filesystem quota manipulation",
	"syslog":            "Kernel ring buffer (dmesg) access",
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
	"clone":     "Process or thread creation / namespace flags",
	"clone3":    "Process or thread creation / namespace flags",
	"fork":      "Child process creation",
	"vfork":     "Child process creation",
	"chown":     "File ownership modification",
	"fchown":    "File ownership modification",
	"fchownat":  "File ownership modification",
	"lchown":    "Symlink ownership modification",
	"chmod":     "File permission / setuid bit modification",
	"fchmod":    "File permission / setuid bit modification",
	"fchmodat":  "File permission / setuid bit modification",
	"setuid":    "User identity change",
	"setgid":    "Group identity change",
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

func ClassifySyscall(name string) (RiskLevel, string) {
	if reason, ok := highRiskSyscalls[name]; ok {
		return RiskHigh, reason
	}
	if reason, ok := mediumRiskSyscalls[name]; ok {
		return RiskMedium, reason
	}
	return RiskLow, "Standard container process operation"
}
