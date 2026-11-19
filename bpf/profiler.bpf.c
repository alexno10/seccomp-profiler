// SPDX-License-Identifier: GPL-2.0 OR MIT
// eBPF Seccomp Profiler kernel programs (Linux 5.19+ tracepoints)
//
// Container-runtime (runc/crun) suppression model:
//   1. raw_tracepoint/sys_enter (execve/execveat): if the tid is already in
//      runtime_tids, or not in a tracked container cgroup with a runtime-family
//      comm BEFORE the exec, mark the tid in exec_pending (dispatched here
//      instead of per-syscall tracepoints so all online CPUs fire).
//   2. raw_tracepoint/sched_process_fork: children forked by runtime-family
//      threads are marked in runtime_tids so their pre-exec setup syscalls
//      (setns, mount, ...) are suppressed (covers crun which does not re-exec).
//   3. tracepoint/sched/sched_process_exec: an exec is only treated as a
//      runtime self-exec when the exec was *initiated by runc/crun* (pending
//      flag) AND lands on an exact self-referential procfs/fd target
//      (/proc/self/exe, /proc/self/fd/<digits>, /dev/fd/<digits>). Every other
//      exec unmarks the tid and activates/records the cgroup - including
//      /proc/self/root/* paths, container entrypoints named "runc"/"crun",
//      application re-execs via /proc/self/exe, and fexecve.
//   4. raw_tracepoint/sys_enter: suppression is keyed ONLY on the tid map,
//      and workload threads inside syscalls_per_cgroup can never add tids to
//      runtime_tids or exec_pending via prctl(PR_SET_NAME, "runc").

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_ANY 0
#define BPF_NOEXIST 1

#define STATE_PENDING_EXEC 1

#define EVENT_CGROUP_MKDIR 1
#define EVENT_EXEC 2

#define MAX_SYSCALLS 512
#define MAX_PATH_LEN 512

#define TS_COMPAT 0x0002
#define TIF_32BIT (1ULL << 22)

struct syscall_stats {
	__u64 counts[MAX_SYSCALLS];
	__u64 compat_count;
};

struct error_counters {
	__u64 cgroup_map_full;
	__u64 ringbuf_drops;
	__u64 oob_syscalls;
	__u64 path_truncations;
	__u64 read_errors;
};

struct kernel_event {
	__u32 type;
	__u32 pad;
	__u64 cgroup_id;
	char path[MAX_PATH_LEN];
};

// Keep the zeroed initializer in .rodata so it never touches the 512B BPF stack.
static const struct syscall_stats empty_stats = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} candidate_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct syscall_stats);
} syscalls_per_cgroup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} runtime_tids SEC(".maps");

// TIDs whose in-flight execve was initiated by runc/crun (comm before exec).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} exec_pending SEC(".maps");

// Kernel-side error counters: BPF_MAP_TYPE_ARRAY pre-allocates slot 0 so
// increments always succeed without userspace map initialization. Any non-zero
// value means visibility was lost and userspace must fail closed.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct error_counters);
} error_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static void *(*bpf_get_current_task)(void) = (void *)35;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)115;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

struct trace_event_raw_sched_process_exec {
	__u64 unused;
	__u32 __data_loc_filename;
	int pid;
	int old_pid;
};

struct bpf_raw_tracepoint_args {
	__u64 args[2];
};

// Minimal CO-RE cgroup hierarchy structs resolved by name against kernel BTF
// (used in raw_tracepoint/cgroup_mkdir to filter cgroup v1 hierarchies and
// propagate active tracking into newly created container sub-cgroups).
struct kernfs_node {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup_root {
	int hierarchy_id;
} __attribute__((preserve_access_index));

struct cgroup;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys_state *parent;
} __attribute__((preserve_access_index));

struct cgroup {
	struct cgroup_subsys_state self;
	struct cgroup_root *root;
	struct kernfs_node *kn;
} __attribute__((preserve_access_index));

static __inline struct error_counters *get_error_counters(void) {
	__u32 zero = 0;
	return bpf_map_lookup_elem(&error_stats, &zero);
}

static __inline int is_hex_char(unsigned char c) {
	unsigned int d = (unsigned int)c - '0';
	unsigned int h = (unsigned int)c - 'a';
	return (d < 10U) | (h < 6U);
}

static __inline int check_hex_anchor(const char *path, int anchor) {
	if (!is_hex_char((unsigned char)path[anchor])) {
		return 0;
	}
	int left = 0;
	for (int k = 1; k <= 63; k++) {
		if (!is_hex_char((unsigned char)path[anchor - k])) {
			break;
		}
		left++;
	}
	int needed = 63 - left;
	for (int r = 1; r <= 63; r++) {
		if (r > needed) {
			return 1;
		}
		if (!is_hex_char((unsigned char)path[anchor + r])) {
			return 0;
		}
	}
	return 1;
}

// Every 64-byte substring inside NUL-terminated path[0..510] straddles at
// least one of these 7 fixed anchor offsets (63..447).
static __inline int has_64_hex_id(const char *path) {
	if (check_hex_anchor(path, 63)) {
		return 1;
	}
	if (check_hex_anchor(path, 127)) {
		return 1;
	}
	if (check_hex_anchor(path, 191)) {
		return 1;
	}
	if (check_hex_anchor(path, 255)) {
		return 1;
	}
	if (check_hex_anchor(path, 319)) {
		return 1;
	}
	if (check_hex_anchor(path, 383)) {
		return 1;
	}
	if (check_hex_anchor(path, 447)) {
		return 1;
	}
	return 0;
}

static __inline int is_runtime_comm(const char *comm) {
	if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c' &&
	    (comm[4] == '\0' || comm[4] == ':' || comm[4] == '_')) {
		return 1;
	}
	if (comm[0] == 'c' && comm[1] == 'r' && comm[2] == 'u' && comm[3] == 'n' &&
	    (comm[4] == '\0' || comm[4] == ':')) {
		return 1;
	}
	return 0;
}

// Runtime family for FORK-TIME marking: runc/crun plus the containerd v2
// shim. containerd-shim-runc-v2 links runc as a library and forks the
// container-init and "docker exec" children itself, so those children are
// only recognizable by their parent's comm ("containerd-shim", truncated to
// the 15-char limit). Such processes either live in host cgroups (where
// suppression is a no-op) or are genuine runtime family.
static __inline int is_runtime_family_comm(const char *comm) {
	if (is_runtime_comm(comm)) {
		return 1;
	}
	if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n' && comm[3] == 't' &&
	    comm[4] == 'a' && comm[5] == 'i' && comm[6] == 'n' && comm[7] == 'e' &&
	    comm[8] == 'r' && comm[9] == 'd' && comm[10] == '-' && comm[11] == 's' &&
	    comm[12] == 'h' && comm[13] == 'i' && comm[14] == 'm') {
		return 1;
	}
	return 0;
}

// Minimal CO-RE-annotated task_struct/thread_info: member offsets are resolved
// BY NAME against the kernel's BTF instead of hardcoded offsets.
struct thread_info {
#if defined(__TARGET_ARCH_arm64)
	unsigned long flags;
#elif defined(__TARGET_ARCH_x86)
	__u32 status;
#endif
} __attribute__((preserve_access_index));

struct task_struct {
	struct thread_info thread_info;
	int pid;
} __attribute__((preserve_access_index));

static __inline int is_decimal_fd(const char *s) {
	int digits = 0;
	for (int i = 0; i < 12; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '\0') {
			return digits > 0;
		}
		if (c < '0' || c > '9') {
			return 0;
		}
		digits++;
	}
	return 0;
}

// Self-referential exec targets used by runc bootstrap re-execs. Only
// consulted for execs that runtime initiated (exec_pending). Strictly matches
// exact "/proc/self/exe", "/proc/self/fd/<digits>", or "/dev/fd/<digits>" so
// paths like "/proc/self/root/bin/sh" or "/memfd:app" cannot keep a container
// workload suppressed in runtime_tids.
static __inline int is_runtime_selfref(const char *filename) {
	// Exact "/proc/self/exe\0"
	if (filename[0] == '/' && filename[1] == 'p' && filename[2] == 'r' && filename[3] == 'o' &&
	    filename[4] == 'c' && filename[5] == '/' && filename[6] == 's' && filename[7] == 'e' &&
	    filename[8] == 'l' && filename[9] == 'f' && filename[10] == '/' &&
	    filename[11] == 'e' && filename[12] == 'x' && filename[13] == 'e' && filename[14] == '\0') {
		return 1;
	}
	// Exact "/proc/self/fd/<digits>\0"
	if (filename[0] == '/' && filename[1] == 'p' && filename[2] == 'r' && filename[3] == 'o' &&
	    filename[4] == 'c' && filename[5] == '/' && filename[6] == 's' && filename[7] == 'e' &&
	    filename[8] == 'l' && filename[9] == 'f' && filename[10] == '/' &&
	    filename[11] == 'f' && filename[12] == 'd' && filename[13] == '/') {
		return is_decimal_fd(&filename[14]);
	}
	// Exact "/dev/fd/<digits>\0"
	if (filename[0] == '/' && filename[1] == 'd' && filename[2] == 'e' && filename[3] == 'v' &&
	    filename[4] == '/' && filename[5] == 'f' && filename[6] == 'd' && filename[7] == '/') {
		return is_decimal_fd(&filename[8]);
	}
	return 0;
}

static __inline int is_compat_syscall(long id) {
#if defined(__TARGET_ARCH_arm64)
	(void)id;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->read_errors, 1);
		}
		return 0;
	}
	unsigned long flags = 0;
	if (bpf_probe_read_kernel(&flags, sizeof(flags),
	    __builtin_preserve_access_index(&task->thread_info.flags)) != 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->read_errors, 1);
		}
		return 0;
	}
	if (flags & TIF_32BIT) {
		return 1;
	}
	return 0;
#elif defined(__TARGET_ARCH_x86)
	if (id >= 0 && (id & 0x40000000L)) {
		return 1;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->read_errors, 1);
		}
		return 0;
	}
	__u32 status = 0;
	if (bpf_probe_read_kernel(&status, sizeof(status),
	    __builtin_preserve_access_index(&task->thread_info.status)) != 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->read_errors, 1);
		}
		return 0;
	}
	if (status & TS_COMPAT) {
		return 1;
	}
	return 0;
#else
#error "unsupported target architecture: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif
}

// Match native execve/execveat numbers for the target arch. Only consulted on
// raw_tracepoint/sys_enter so exec detection runs across all online CPUs even
// when perf_syscall_enter skips CPUs without per-CPU perf events.
static __inline int is_execve_syscall(long id) {
#if defined(__TARGET_ARCH_arm64)
	return id == 221 /* __NR_execve */ || id == 281 /* __NR_execveat */;
#elif defined(__TARGET_ARCH_x86)
	return id == 59 /* __NR_execve */ || id == 322 /* __NR_execveat */;
#else
#error "unsupported target architecture: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif
}

// Cgroup v2 creation & sub-cgroup propagation: attached as raw_tracepoint
// (args[0] = struct cgroup *cgrp, args[1] = const char *path) so we can:
//   - ignore cgroup v1 multi-hierarchy events (hierarchy_id != 0),
//   - propagate active tracking immediately into sub-cgroups created by tracked
//     containers (even if a process migrates into them without execve),
//   - detect >=511-byte path truncations fail-closed.
SEC("raw_tracepoint/cgroup_mkdir")
int handle_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
	const char *path_ptr = (const char *)ctx->args[1];
	if (!cgrp || !path_ptr) {
		return 0;
	}

	struct cgroup_root *root = 0;
	if (bpf_probe_read_kernel(&root, sizeof(root),
	    __builtin_preserve_access_index(&cgrp->root)) != 0 || !root) {
		return 0;
	}
	int hierarchy_id = -1;
	if (bpf_probe_read_kernel(&hierarchy_id, sizeof(hierarchy_id),
	    __builtin_preserve_access_index(&root->hierarchy_id)) != 0 || hierarchy_id != 0) {
		return 0;
	}

	struct kernfs_node *kn = 0;
	if (bpf_probe_read_kernel(&kn, sizeof(kn),
	    __builtin_preserve_access_index(&cgrp->kn)) != 0 || !kn) {
		return 0;
	}
	__u64 cgroup_id = 0;
	if (bpf_probe_read_kernel(&cgroup_id, sizeof(cgroup_id),
	    __builtin_preserve_access_index(&kn->id)) != 0 || cgroup_id == 0) {
		return 0;
	}

	__u8 parent_active = 0;
	struct cgroup *cur = cgrp;
	#pragma unroll
	for (int depth = 0; depth < 8; depth++) {
		struct cgroup_subsys_state *pcss = 0;
		if (bpf_probe_read_kernel(&pcss, sizeof(pcss),
		    __builtin_preserve_access_index(&cur->self.parent)) != 0 || !pcss) {
			break;
		}
		struct cgroup *pcgrp = 0;
		if (bpf_probe_read_kernel(&pcgrp, sizeof(pcgrp),
		    __builtin_preserve_access_index(&pcss->cgroup)) != 0 || !pcgrp) {
			break;
		}
		struct kernfs_node *pkn = 0;
		if (bpf_probe_read_kernel(&pkn, sizeof(pkn),
		    __builtin_preserve_access_index(&pcgrp->kn)) != 0 || !pkn) {
			break;
		}
		__u64 pcg_id = 0;
		if (bpf_probe_read_kernel(&pcg_id, sizeof(pcg_id),
		    __builtin_preserve_access_index(&pkn->id)) != 0 || pcg_id == 0) {
			break;
		}
		if (bpf_map_lookup_elem(&syscalls_per_cgroup, &pcg_id)) {
			parent_active = 1;
			break;
		}
		cur = pcgrp;
	}

	if (parent_active) {
		long ret = bpf_map_update_elem(&syscalls_per_cgroup, &cgroup_id, &empty_stats, BPF_NOEXIST);
		if (ret != 0 && ret != -17) {
			struct error_counters *e = get_error_counters();
			if (e) {
				__sync_fetch_and_add(&e->cgroup_map_full, 1);
			}
		}
	}

	struct kernel_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->ringbuf_drops, 1);
		}
		return 0;
	}

	__builtin_memset(ev->path, 0, 256);
	__builtin_memset(ev->path + 256, 0, 256);
	long n = bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path_ptr);
	if (n <= 0 || n == sizeof(ev->path)) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->path_truncations, 1);
		}
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	if (!parent_active && !has_64_hex_id(ev->path)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	if (!parent_active) {
		__u8 state = STATE_PENDING_EXEC;
		long ret = bpf_map_update_elem(&candidate_cgroups, &cgroup_id, &state, BPF_ANY);
		if (ret != 0) {
			struct error_counters *e = get_error_counters();
			if (e) {
				__sync_fetch_and_add(&e->cgroup_map_full, 1);
			}
		}
	}

	ev->type = EVENT_CGROUP_MKDIR;
	ev->pad = 0;
	ev->cgroup_id = cgroup_id;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// Children forked by the runtime family (runc/crun/containerd-shim) are
// pre-marked so their pre-first-exec setup syscalls (setns, mount, ...)
// inside an already-active container cgroup are suppressed. Threads already
// running inside an active tracked container (syscalls_per_cgroup) without
// existing runtime membership cannot mark children via prctl(PR_SET_NAME).
//
// Attached as a RAW tracepoint: sched_process_fork carries no dynamic data,
// so the kernel's tracepoint-link ctx-size check
//   perf_event_set_bpf_prog(): max_ctx_offset > trace_event_get_offsets()
// rejects ANY direct ctx read with a misleading EPERM on kernels that ship
// it (6.8+). Raw tracepoints bypass that check entirely, and the child pid
// is resolved via CO-RE by member name.
SEC("raw_tracepoint/sched_process_fork")
int handle_sched_process_fork(struct bpf_raw_tracepoint_args *ctx) {
	__u32 parent_tid = (__u32)bpf_get_current_pid_tgid();
	// Already-tracked runtime tids keep propagating to forked children even if
	// kernel comm is temporarily "exe" across /proc/self/exe before prctl(PR_SET_NAME).
	if (!bpf_map_lookup_elem(&runtime_tids, &parent_tid)) {
		__u64 cgroup_id = bpf_get_current_cgroup_id();
		if (bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id)) {
			return 0;
		}
		char comm[16] = {};
		bpf_get_current_comm(comm, sizeof(comm));
		if (!is_runtime_family_comm(comm)) {
			return 0;
		}
	}
	// args[0] = parent task_struct, args[1] = child task_struct (TP_PROTO).
	__u64 child_ptr = 0;
	if (bpf_probe_read_kernel(&child_ptr, sizeof(child_ptr), (const char *)ctx + 8) != 0 || child_ptr == 0) {
		return 0;
	}
	int pid = 0;
	if (bpf_probe_read_kernel(&pid, sizeof(pid),
	    __builtin_preserve_access_index(&((struct task_struct *)child_ptr)->pid)) != 0) {
		return 0;
	}
	__u32 child_tid = (__u32)pid;
	if (child_tid == 0) {
		return 0;
	}
	__u8 one = 1;
	bpf_map_update_elem(&runtime_tids, &child_tid, &one, BPF_ANY);
	return 0;
}

static __inline int handle_exec_enter(__u64 cgroup_id) {
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	// Already-tracked runtime tids retain exec_pending across self-reexecs such as
	// runc's ensure_cloned_binary() fexecve(memfd), where kernel comm is "exe"
	// after execve("/proc/self/exe") and before prctl(PR_SET_NAME).
	if (!bpf_map_lookup_elem(&runtime_tids, &tid)) {
		if (bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id)) {
			return 0;
		}
		char comm[16] = {};
		bpf_get_current_comm(comm, sizeof(comm));
		if (!is_runtime_family_comm(comm)) {
			return 0;
		}
	}
	__u8 one = 1;
	bpf_map_update_elem(&exec_pending, &tid, &one, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	int old_pid_raw = ctx->old_pid;
	__u32 old_tid = old_pid_raw > 0 ? (__u32)old_pid_raw : 0;

	__u32 data_loc = ctx->__data_loc_filename;
	__u16 offset = data_loc & 0xffff;

	__u8 *cand = bpf_map_lookup_elem(&candidate_cgroups, &cgroup_id);
	struct syscall_stats *existing = 0;
	if (!cand) {
		existing = bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id);
	}

	if (!cand && !existing) {
		// Outside tracked/candidate container cgroups: clean up stale runtime_tids
		// and exec_pending entries on normal host/helper execs (I2/I3).
		__u8 pending = 0;
		__u8 has_rt = 0;
		if (bpf_map_lookup_elem(&exec_pending, &tid)) {
			pending = 1;
		}
		if (old_tid != 0 && old_tid != tid && bpf_map_lookup_elem(&exec_pending, &old_tid)) {
			pending = 1;
		}
		if (bpf_map_lookup_elem(&runtime_tids, &tid)) {
			has_rt = 1;
		} else if (old_tid != 0 && old_tid != tid && bpf_map_lookup_elem(&runtime_tids, &old_tid)) {
			has_rt = 1;
		}
		if (!pending && !has_rt) {
			return 0;
		}
		bpf_map_delete_elem(&exec_pending, &tid);
		if (old_tid != 0 && old_tid != tid) {
			bpf_map_delete_elem(&exec_pending, &old_tid);
		}
		char short_fname[32] = {};
		long read_ok = -1;
		if (offset >= 12U && offset < 4096U) {
			const char *fname_ptr = (const char *)ctx + offset;
			read_ok = bpf_probe_read_kernel_str(short_fname, sizeof(short_fname), fname_ptr);
		}
		if (pending && read_ok > 0 && is_runtime_selfref(short_fname)) {
			__u8 one = 1;
			bpf_map_update_elem(&runtime_tids, &tid, &one, BPF_ANY);
			if (old_tid != 0 && old_tid != tid) {
				bpf_map_delete_elem(&runtime_tids, &old_tid);
			}
			return 0;
		}
		bpf_map_delete_elem(&runtime_tids, &tid);
		if (old_tid != 0 && old_tid != tid) {
			bpf_map_delete_elem(&runtime_tids, &old_tid);
		}
		return 0;
	}

	__u8 pending = 0;
	if (bpf_map_lookup_elem(&exec_pending, &tid)) {
		pending = 1;
	}
	bpf_map_delete_elem(&exec_pending, &tid);
	if (old_tid != 0 && old_tid != tid) {
		// Propagate pre-exec marker across de_thread() TID swap (non-leader execve).
		if (bpf_map_lookup_elem(&exec_pending, &old_tid)) {
			pending = 1;
		}
		bpf_map_delete_elem(&exec_pending, &old_tid);
	}

	struct kernel_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->ringbuf_drops, 1);
		}
		// Still unmark runtime_tids and activate the cgroup so syscalls are not lost.
		bpf_map_delete_elem(&runtime_tids, &tid);
		if (old_tid != 0 && old_tid != tid) {
			bpf_map_delete_elem(&runtime_tids, &old_tid);
		}
		if (cand) {
			bpf_map_delete_elem(&candidate_cgroups, &cgroup_id);
		}
		long ret = bpf_map_update_elem(&syscalls_per_cgroup, &cgroup_id, &empty_stats, BPF_NOEXIST);
		if (ret != 0 && ret != -17) {
			if (e) {
				__sync_fetch_and_add(&e->cgroup_map_full, 1);
			}
		}
		return 0;
	}

	__builtin_memset(ev->path, 0, 256);
	__builtin_memset(ev->path + 256, 0, 256);
	long read_ok = -1;
	if (offset >= 12U && offset < 4096U) {
		const char *fname_ptr = (const char *)ctx + offset;
		read_ok = bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), fname_ptr);
	}

	if (read_ok > 0 && pending && is_runtime_selfref(ev->path)) {
		// runc bootstrap re-exec: keep the tid suppressed until it
		// execs the real container workload. Do not match on comm so
		// container entrypoints named "runc"/"crun" are never suppressed.
		__u8 one = 1;
		bpf_map_update_elem(&runtime_tids, &tid, &one, BPF_ANY);
		if (old_tid != 0 && old_tid != tid) {
			bpf_map_delete_elem(&runtime_tids, &old_tid);
		}
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	// Any other exec (including unreadable filename fallback, container entrypoint,
	// secondary "docker exec", or application /proc/self/exe re-exec) is a
	// workload thread: unmark and record.
	bpf_map_delete_elem(&runtime_tids, &tid);
	if (old_tid != 0 && old_tid != tid) {
		bpf_map_delete_elem(&runtime_tids, &old_tid);
	}

	if (cand) {
		bpf_map_delete_elem(&candidate_cgroups, &cgroup_id);
	}
	long ret = bpf_map_update_elem(&syscalls_per_cgroup, &cgroup_id, &empty_stats, BPF_NOEXIST);
	if (ret != 0 && ret != -17 /* -EEXIST: secondary execs, expected */) {
		// Any other error (typically -ENOSPC on a full map) means the
		// cgroup's syscalls will not be recorded.
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->cgroup_map_full, 1);
		}
	}

	ev->type = EVENT_EXEC;
	ev->pad = 0;
	ev->cgroup_id = cgroup_id;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_process_exit(struct bpf_raw_tracepoint_args *ctx) {
	(void)ctx;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&runtime_tids, &tid);
	bpf_map_delete_elem(&exec_pending, &tid);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	long id = (long)ctx->args[1];
	int is_execve = is_execve_syscall(id);

	if (is_execve) {
		handle_exec_enter(cgroup_id);
	}

	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct syscall_stats *stats = bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id);
	if (!stats) {
		// If a runtime helper called execve outside any container cgroup and it
		// failed (-ENOENT/-EACCES), clear stale exec_pending on its next syscall.
		if (!is_execve && bpf_map_lookup_elem(&exec_pending, &tid)) {
			bpf_map_delete_elem(&exec_pending, &tid);
		}
		return 0;
	}

	// Suppression is keyed on tids only. No comm check: a workload renaming
	// itself to "runc" via prctl(PR_SET_NAME) is still recorded.
	if (bpf_map_lookup_elem(&runtime_tids, &tid)) {
		if (!is_execve && bpf_map_lookup_elem(&exec_pending, &tid)) {
			bpf_map_delete_elem(&exec_pending, &tid);
		}
		return 0;
	}

	if (id < 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->oob_syscalls, 1);
		}
		return 0;
	}
	if (is_compat_syscall(id)) {
		__sync_fetch_and_add(&stats->compat_count, 1);
		return 0;
	}
	__u64 uid = (__u64)id;
	if (uid >= MAX_SYSCALLS) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->oob_syscalls, 1);
		}
		return 0;
	}
	__sync_fetch_and_add(&stats->counts[uid], 1);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
