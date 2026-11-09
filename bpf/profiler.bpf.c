// SPDX-License-Identifier: GPL-2.0 OR MIT
// eBPF Seccomp Profiler kernel programs (Linux 5.19+ tracepoints)
//
// Container-runtime (runc/crun) suppression model:
//   1. tracepoint/syscalls/sys_enter_execve{,at}: if the thread's comm BEFORE
//      the exec is runc/crun, mark the tid in exec_pending.
//   2. tracepoint/sched/process_fork: children forked by runc/crun are marked
//      in runtime_tids so their pre-exec setup syscalls (setns, mount, ...)
//      are suppressed (covers crun which does not re-exec).
//   3. tracepoint/sched/sched_process_exec: an exec is only treated as a
//      runtime self-exec when the exec was *initiated by runc/crun* (pending
//      flag) AND lands on a self-referential binary (/proc/self/*, /dev/fd/*,
//      /memfd:*) or keeps the runtime comm. Every other exec unmarks the tid
//      and activates/records the cgroup - including application re-execs via
//      /proc/self/exe and fexecve, which the profiler must record.
//   4. raw_tracepoint/sys_enter: suppression is keyed ONLY on the tid map.
//      There is no comm check here, so a container renaming itself to "runc"
//      with prctl(PR_SET_NAME) cannot hide its syscalls anymore.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_ANY 0
#define BPF_NOEXIST 1

#define STATE_PENDING_EXEC 1
#define STATE_ACTIVE 2

#define EVENT_CGROUP_MKDIR 1
#define EVENT_EXEC 2

#define MAX_SYSCALLS 512
#define MAX_PATH_LEN 256

#define TS_COMPAT 0x0002
#define TIF_32BIT (1ULL << 22)

struct syscall_stats {
	__u32 counts[MAX_SYSCALLS];
	__u32 compat_count;
	__u32 pad;
};

struct error_counters {
	__u64 cgroup_map_full;
	__u64 ringbuf_drops;
	__u64 oob_syscalls;
};

struct kernel_event {
	__u32 type;
	__u32 pad;
	__u64 cgroup_id;
	char path[MAX_PATH_LEN];
};

struct thread_info_prefix {
	unsigned long flags;
	unsigned long syscall_work;
	__u32 status;
};

// Keep the 2KB zeroed initializer in .rodata so it never touches the 512B BPF stack.
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

// Kernel-side error counters: any non-zero value means visibility was lost
// and userspace must warn or fail the gate (fail-closed, not fail-open).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct error_counters);
} error_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kernel_event);
} scratch_events SEC(".maps");

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
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;

struct trace_event_raw_cgroup_mkdir {
	__u64 unused;
	int root;
	int level;
	__u64 id;
	__u32 __data_loc_path;
};

struct trace_event_raw_sched_process_exec {
	__u64 unused;
	__u32 __data_loc_filename;
	int pid;
	int old_pid;
};

struct trace_event_raw_sched_process_fork {
	__u64 unused;
	char parent_comm[16];
	int parent_pid;
	char child_comm[16];
	int child_pid;
};

struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	__u64 args[6];
};

struct bpf_raw_tracepoint_args {
	__u64 args[2];
};

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

// Every 64-byte substring inside NUL-terminated path[0..254] straddles index 63, 127, or 191.
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

// Self-referential exec targets used by runc/crun bootstrap re-execs. Only
// consulted for execs that runc/crun initiated (exec_pending), so application
// re-execs of /proc/self/exe or fexecve/memfd payloads are never suppressed.
static __inline int is_runtime_selfref(const char *filename) {
	if (filename[0] == '\0' || (filename[0] == '/' && filename[1] == '\0')) {
		return 1;
	}
	// "/proc/self/" (covers both "/proc/self/exe" and "/proc/self/fd/<N>")
	if (filename[0] == '/' && filename[1] == 'p' && filename[2] == 'r' && filename[3] == 'o' &&
	    filename[4] == 'c' && filename[5] == '/' && filename[6] == 's' && filename[7] == 'e' &&
	    filename[8] == 'l' && filename[9] == 'f' && filename[10] == '/') {
		return 1;
	}
	// "/dev/fd/"
	if (filename[0] == '/' && filename[1] == 'd' && filename[2] == 'e' && filename[3] == 'v' &&
	    filename[4] == '/' && filename[5] == 'f' && filename[6] == 'd' && filename[7] == '/') {
		return 1;
	}
	// "/memfd:" (cloned memfd re-execs)
	if (filename[0] == '/' && filename[1] == 'm' && filename[2] == 'e' && filename[3] == 'm' &&
	    filename[4] == 'f' && filename[5] == 'd' && filename[6] == ':') {
		return 1;
	}
	return 0;
}

static __inline int is_compat_syscall(long id) {
#if defined(__TARGET_ARCH_arm64)
	(void)id;
	void *task = bpf_get_current_task();
	if (!task) {
		return 0;
	}
	unsigned long flags = 0;
	if (bpf_probe_read_kernel(&flags, sizeof(flags), task) == 0) {
		if (flags & TIF_32BIT) {
			return 1;
		}
	}
	return 0;
#else
	if (id & 0x40000000L) {
		return 1;
	}
	void *task = bpf_get_current_task();
	if (!task) {
		return 0;
	}
	struct thread_info_prefix ti = {};
	if (bpf_probe_read_kernel(&ti, sizeof(ti), task) == 0) {
		if (ti.status & TS_COMPAT) {
			return 1;
		}
	}
	return 0;
#endif
}

SEC("tracepoint/cgroup/cgroup_mkdir")
int handle_cgroup_mkdir(struct trace_event_raw_cgroup_mkdir *ctx) {
	__u32 zero = 0;
	struct kernel_event *ev = bpf_map_lookup_elem(&scratch_events, &zero);
	if (!ev) {
		return 0;
	}

	__u32 data_loc = ctx->__data_loc_path;
	__u16 offset = data_loc & 0xffff;
	const char *path_ptr = (const char *)ctx + offset;

	__builtin_memset(ev->path, 0, sizeof(ev->path));
	long n = bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path_ptr);
	if (n <= 0) {
		return 0;
	}

	if (!has_64_hex_id(ev->path)) {
		return 0;
	}

	__u64 cgroup_id = ctx->id;
	__u8 state = STATE_PENDING_EXEC;
	long ret = bpf_map_update_elem(&candidate_cgroups, &cgroup_id, &state, BPF_ANY);
	if (ret != 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->cgroup_map_full, 1);
		}
	}

	ev->type = EVENT_CGROUP_MKDIR;
	ev->pad = 0;
	ev->cgroup_id = cgroup_id;
	if (bpf_ringbuf_output(&events, ev, sizeof(*ev), 0) != 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->ringbuf_drops, 1);
		}
	}
	return 0;
}

// Children forked by runc/crun are pre-marked so their pre-first-exec setup
// syscalls (setns, mount, ...) inside an already-active container cgroup are
// suppressed. The marker is cleared as soon as the child execs the workload.
SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
	char comm[16] = {};
	bpf_get_current_comm(comm, sizeof(comm));
	if (!is_runtime_comm(comm)) {
		return 0;
	}
	__u32 child_tid = (__u32)ctx->child_pid;
	if (child_tid == 0) {
		return 0;
	}
	__u8 one = 1;
	bpf_map_update_elem(&runtime_tids, &child_tid, &one, BPF_ANY);
	return 0;
}

static __inline int handle_exec_enter(void) {
	char comm[16] = {};
	bpf_get_current_comm(comm, sizeof(comm));
	if (!is_runtime_comm(comm)) {
		return 0;
	}
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u8 one = 1;
	bpf_map_update_elem(&exec_pending, &tid, &one, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
	return handle_exec_enter();
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
	return handle_exec_enter();
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 cand_state = 0;
	__u8 *cand = bpf_map_lookup_elem(&candidate_cgroups, &cgroup_id);
	if (cand) {
		cand_state = *cand;
	} else {
		struct syscall_stats *existing = bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id);
		if (!existing) {
			return 0;
		}
	}

	__u32 zero = 0;
	struct kernel_event *ev = bpf_map_lookup_elem(&scratch_events, &zero);
	if (!ev) {
		return 0;
	}

	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	char comm[16] = {};
	bpf_get_current_comm(comm, sizeof(comm));

	__u32 data_loc = ctx->__data_loc_filename;
	__u16 offset = data_loc & 0xffff;
	const char *fname_ptr = (const char *)ctx + offset;

	__builtin_memset(ev->path, 0, sizeof(ev->path));
	if (bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), fname_ptr) <= 0) {
		// An unreadable filename would look like a self-ref exec and keep
		// runc marked; treat it as a workload exec instead (fail open to
		// recording, never to suppression).
		bpf_map_delete_elem(&runtime_tids, &tid);
		bpf_map_delete_elem(&exec_pending, &tid);
		if (cand_state == STATE_PENDING_EXEC) {
			__u8 active = STATE_ACTIVE;
			bpf_map_update_elem(&candidate_cgroups, &cgroup_id, &active, BPF_ANY);
		}
		bpf_map_update_elem(&syscalls_per_cgroup, &cgroup_id, &empty_stats, BPF_NOEXIST);
		ev->type = EVENT_EXEC;
		ev->pad = 0;
		ev->cgroup_id = cgroup_id;
		bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);
		return 0;
	}

	__u8 pending = 0;
	__u8 *p = bpf_map_lookup_elem(&exec_pending, &tid);
	if (p) {
		pending = *p;
	}
	bpf_map_delete_elem(&exec_pending, &tid);

	if (pending && (is_runtime_comm(comm) || is_runtime_selfref(ev->path))) {
		// runc/crun bootstrap re-exec: keep the tid suppressed until it
		// execs the real container workload.
		__u8 one = 1;
		bpf_map_update_elem(&runtime_tids, &tid, &one, BPF_ANY);
		return 0;
	}

	// Any other exec - the container entrypoint itself, secondary
	// "docker exec" workloads, application /proc/self/exe re-execs - is a
	// workload thread: unmark and record.
	bpf_map_delete_elem(&runtime_tids, &tid);

	if (cand_state == STATE_PENDING_EXEC) {
		__u8 active = STATE_ACTIVE;
		bpf_map_update_elem(&candidate_cgroups, &cgroup_id, &active, BPF_ANY);
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
	if (bpf_ringbuf_output(&events, ev, sizeof(*ev), 0) != 0) {
		struct error_counters *e = get_error_counters();
		if (e) {
			__sync_fetch_and_add(&e->ringbuf_drops, 1);
		}
	}
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct syscall_stats *stats = bpf_map_lookup_elem(&syscalls_per_cgroup, &cgroup_id);
	if (!stats) {
		return 0;
	}

	// Suppression is keyed on tids only. No comm check: a workload renaming
	// itself to "runc" via prctl(PR_SET_NAME) is still recorded.
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&runtime_tids, &tid)) {
		return 0;
	}

	long id = (long)ctx->args[1];
	if (is_compat_syscall(id)) {
		__sync_fetch_and_add(&stats->compat_count, 1);
		return 0;
	}
	__u64 uid = (__u64)id;
	if (id < 0 || uid >= MAX_SYSCALLS) {
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
