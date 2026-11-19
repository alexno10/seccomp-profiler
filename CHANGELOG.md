# Changelog

## 1.2.1 (2026-11-20)

Comprehensive security and reliability audit remediation release across eBPF kernel tracing, syscall tables, Go daemon/correlator/selector/profile/diff/report engines, GitHub Action supply-chain isolation, and CI workflows.

### Security

- **Hardened eBPF runtime suppression & hierarchy tracking (`bpf/profiler.bpf.c`, `internal/ebpf`, `internal/syscalls`):** `is_runtime_selfref()` strictly matches exact `/proc/self/exe`, `/proc/self/fd/<digits>`, and `/dev/fd/<digits>` (removing `/memfd:` and prefix bypasses via `/proc/self/root/*`); `raw_tracepoint/cgroup_mkdir` filters cgroup v2 hierarchies (`hierarchy_id == 0`), walks 8 parent levels via CO-RE to immediately propagate active tracking into sub-cgroups created without `execve`, and checks 512-byte paths with 7 anchors (`63..447`) and a fail-closed `path_truncations` counter; `raw_tracepoint/sched_process_exit` attachment is mandatory; syscall tables updated through Linux 6.13–6.19 (`open_tree_attr`, `uprobe`, `setxattrat`–`removexattrat`, `file_getattr/setattr`, `listns`) with fail-closed rejection of unknown nonzero syscall IDs; embedded bytecode is protected and `resolveBPFObjectPath` avoids CWD `bpf/profiler.bpf.o` when `euid == 0`.
- **Privilege & filesystem boundary hardening (`internal/profile`, `internal/diff`, `internal/daemon`, `action/`):** replaced symlink-following writes and post-rename `os.Chown` TOCTOU with symlink-free directory checks, `O_NOFOLLOW`, `os.Root`-contained operations, and pre-rename file-descriptor `Chown`; isolated `mode: stop` and `post.js` via root-owned `/run/seccomp-profiler/session.json` and `/run/seccomp-profiler/baseline-*` snapshots so `$GITHUB_ENV` poisoning or PR workspace tampering cannot hijack root execution or baseline validation; moved root binary cache under `/usr/lib/seccomp-profiler` (`0755 root:root`) with staged digest checks; enforced unix socket `0600` creation under `umask(0177)` and non-socket/live-daemon checks; isolated `git` baseline checkouts with `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `core.symlinks=false`, and `submodule.recurse=false`; locked `COSIGN_CERT_IDENTITY_REGEXP` directly to `PINNED_RELEASE_VERSION` under a sanitized Cosign env; escaped `<`, `>`, `[`, `]` in Markdown/HTML Job Summary cells.
- **Closed OCI Seccomp gate & merge bypasses (`internal/diff`, `internal/profile`):** `hasCloneNamespaceMask` rejects duplicate `args[].index` OR-splitting and `index > 5`; `LoadOCIProfile` handles `archMap` safely and fails closed on unsupported conditional Docker `includes`/`excludes` or unknown fields; non-native architectures are checked even with empty committed `architectures`; `EvaluateGate` treats unapproved `ArgsChanged` loosening at `high-risk`; `MergeCommittedIntoOCI` preserves conditional/deny rules and deduplicates non-ALLOW rules deterministically without runtime `-EEXIST`; approvals support explicit `scope` (`add`, `escalate`, `args-change`, `all`) so unscoped approvals cannot waive escalations; `clone3` is always high-risk and high/medium tiers now include `open_tree_attr`, `mknod`, `mknodat`, `chroot`, `fchroot`, `mbind`, `set_mempolicy`, `fanotify_mark`, `memfd_secret`, `seccomp`, `process_mrelease`, `pidfd_open`, `prctl`, `statmount`, and `listmount`.

### Fixed

- **eBPF 64-bit counters, CO-RE & verifier safety (`bpf/profiler.bpf.c`, `internal/ebpf`, `internal/syscalls`):** widened `syscall_stats` counters (`counts[512]`, `compat_count`) and correlator hit sums to 64-bit; converted `is_compat_syscall()` to CO-RE `task_struct.thread_info` with fail-closed `read_errors` tracking; replaced per-CPU `scratch_events` copy with `bpf_ringbuf_reserve`/`submit`/`discard`; deleted active keys from `candidate_cgroups` on activation; propagated `ctx->old_pid` across `de_thread` TID swaps and cleaned stale `runtime_tids`/`exec_pending` entries on failed/host execs; added `barrier_var` + `map_has_elem` helper to satisfy the kernel BPF verifier; tracked userspace `decode_errors` and fixed lock contention in `TrackCgroup`/`DeleteCgroup`; unified generated syscall tables into arch-neutral `internal/syscalls/zsyscalls_gen.go`.
- **Daemon, Docker correlator & selector reliability (`internal/daemon`, `internal/docker`, `internal/selector`):** eliminated `executeStop()` / consumer `s.mu` self-deadlock and `sync.WaitGroup` reuse panic; added transient `acceptLoop` backoff, 32-connection cap, and proper `stoppedMarker`/`stopped` handling across error paths; fixed `streamDockerEventsSince` scanner-error deadlock via context cancellation and `bufio.Reader`; guarded against replayed older `die`/`stop`/`destroy` events on restarted containers and coalesced live/dead stats; moved cgroup inode resolution off the event stream loop and capped/deduplicated `cgroupBins`; checked `*exec.ExitError.Stderr` in `isContainerNotFoundErr`; fixed pre-write drift & gate ordering in `executeStop()`; fixed `exclude-images` precedence with `targets`, case-insensitive `BaselineMode`/`GroupBy`, `targets` parser bugs, and real `"container"` image name collisions.
- **Profile building, CLI, Action & CI (`internal/profile`, `internal/report`, `cmd/seccomp-profiler`, `action/`, `.github/workflows/`):** auto-added constrained `clone` (`clone3-fallback`) whenever `clone3` maps to `ENOSYS`; propagated and aggregated `KernelErrors` across `merge` shards; keyed `lock.json` by path with legacy target-name fallback; fixed `baseline-ref: none` on PRs and real `merge_group` `GITHUB_EVENT_PATH` parsing; failed closed in `post.js` if the daemon crashes after readiness; detected early child exits in `startDaemon`; moved version check to in-process `syscall.Uname`, validated config before eBPF load, fixed `args` counting in `high-risk-count`, updated `SECURITY.md`, added `go test -race ./...` in CI, and aligned `-X main.version` across `Makefile` and `release.yml`.

## 1.2.0 (2026-11-14)

Comprehensive security, reliability, and parser hardening release across the eBPF tracer, security gate, Docker correlator, GitHub Action, and CLI.

### Security

- **eBPF runtime suppression & error counter hardening:** `error_stats` now uses `BPF_MAP_TYPE_ARRAY` so slot `0` is always kernel-allocated; `execve`/`execveat` dispatch runs from `raw_tracepoint/sys_enter` across all CPUs; `sched_process_exit` cleans up `runtime_tids` and `exec_pending` on thread exit; processes already inside an active tracked container cgroup cannot spoof `runc`/`crun`/`containerd-shim` comm names to suppress syscalls; negative syscall numbers are counted in `oob_syscalls` before compat checks.
- **Closed security gate bypasses (`internal/diff`, `internal/profile`):** newly added conditional rules (`Args`), `SCMP_ACT_LOG` rules, multiple conditional rules per syscall, `ArgsChanged`, `DefaultAction` drift, and `Architectures` drift are all tracked and enforced by `EvaluateGate`; empty syscall actions are rejected.
- **Hand-edit lock integrity (`lock.json`):** `UpdateCommittedProfiles` refuses to overwrite existing profiles when `lock.json` is missing, unreadable, or lacks the target entry, writing `.suggested.json` instead.
- **GitHub Action & daemon privilege boundaries (`action/`, `internal/daemon`, `internal/ebpf`):** `post.js` prioritizes `GITHUB_STATE` over mutable `GITHUB_ENV` and re-verifies cached binary SHA-256 digests before `sudo` execution; binaries install atomically; embedded eBPF bytecode takes precedence over untrusted working-directory `.o` files unless `SECCOMP_PROFILER_BPF_OBJ` is explicitly set; `PATH` and git refs are sanitized; control sockets enforce `0600` (unix) or loopback-only binding (`tcp://`); root file writes reject symlinks.
- **Expanded syscall risk tiers & fail-closed parsers:** added `quotactl_fd`, `clock_adjtime`, `modify_ldt`, and `lsm_set_self_attr` (high-risk) plus `setgroups`, `setfsuid`, `setfsgid`, and `fchmodat2` (medium-risk); `ParseTargetsInputWithErr` and `LoadApprovals` fail closed on malformed syntax, unknown keys, duplicate approvals, `.suggested` target suffixes, or missing-label empty matches.
- **Release workflow hardening (`.github/workflows/release.yml`):** enforced job-scoped permissions, `persist-credentials: false`, `go generate` drift checks, tag/version consistency checks, and `mktemp -d` Cosign installation.

### Fixed

- **Docker & DinD/rootless cgroup correlation (`internal/docker`):** `ExtractContainerID` matches the innermost (last) 64-hex container ID for nested DinD paths; cgroup v2 (`0::`) entries take priority; `docker inspect` calls enforce timeouts; `<100ms` container `die`/`destroy` events drain late ring-buffer events before deleting BPF maps.
- **Collector lifecycle & shutdown synchronization (`internal/ebpf`, `internal/daemon`):** synchronized `Close()`, `Detach()`, `Flush()`, `FlushCgroup()`, `DeleteCgroup()`, and `ErrorStats()` to prevent concurrent shutdown panics; direct little-endian decoding in `DecodeKernelEvent` rejects unknown event types.
- **CLI & reporting (`cmd/seccomp-profiler`, `internal/report`):** `seccomp-profiler diff` renders per-target Markdown tables with full cell escaping; `merge` supports `--prune` and `--on-change`; `internal/syscalls/gen` resolves paths via `runtime.Caller(0)` and skips `__NR_syscalls`; `SeccompArchitectures` fails closed on unknown architectures.

## 1.1.1 (2026-11-10)

Bugfix release for the v1.1.0 daemon on current CI runners.

- **Fixed:** `sched_process_fork` failed to attach on kernels with the tracepoint-link ctx-size check (6.8+): `perf_event_set_bpf_prog` compares `max_ctx_offset` against `trace_event_get_offsets`, which only accounts for *dynamic* data — and this tracepoint has none, so any direct ctx read was refused at link time with a misleading `permission denied` (the program itself loaded fine). The child pid is now read with `bpf_probe_read_kernel` from the fixed ctx offset (`max_ctx_offset` stays 0). Diagnosed against kernel v6.8 source.
- **Fixed:** the three suppression-refinement hooks (`sched_process_fork`, `sys_enter_execve`, `sys_enter_execveat`) now attach best-effort with a loud warning instead of killing the daemon; losing one can only over-record runtime setup syscalls of secondary `docker exec` workloads (over-permissive, never under-recorded), and a kernel quirk must not take the whole profiler down.
- **CI:** the positive e2e high-risk probe uses `add_key`/`keyctl` (capability-free) instead of `unshare`, which the current runner fleet (kernel 7.0-azure) refuses inside containers even with `seccomp=unconfined` and `CAP_SYS_ADMIN`. The daemon-environment leak check now actually reads the root daemon's environ (`sudo cat`); the previous `< /proc/...` redirect silently failed as the non-root step user and voided the check.

## 1.1.0 (2026-11-10)

Security hardening release driven by the v1.0.0 code review.

### Security

- **Gate cannot be widened from inside a PR** (review #1): committed profile and `accepted.yml` are read from the PR base ref (`baseline-ref`, automatic on `pull_request`); PR-side edits to them are reported as drift.
- **eBPF suppression redesign** (review #3): runtime suppression now keys on the *pre-exec* comm only. Application `/proc/self/exe`, `/dev/fd/*` and fexecve re-execs are recorded again; `prctl(PR_SET_NAME, "runc")` no longer hides syscalls from the gate. Covered by positive e2e tests in CI.
- **Conditional → unconditional escalation** (review #2): dropping arg constraints is reported as high-risk drift and fails the gate; `MergeCommittedIntoOCI` can never widen a conditional allow, and generated arg rules survive merges.
- **Path traversal via target names** (review #5): names validated against `^[A-Za-z0-9._-]{1,100}$`; invalid labels skip with a reason.
- **Fail-closed kernel error counters** (review #4): `cgroup_map_full` / `ringbuf_drops` / `oob_syscalls` fail the gate when non-zero; BPF maps are cleaned per container death so they stay bounded.
- **Risk list expanded** (review #12): new mount API, io_uring, clock/hostname/personality, `kcmp`, `pidfd_getfd`, `process_madvise`, page migration, `uselib`, `vhangup`, … unconditional `clone`/`clone3` are high-risk.
- **Generated profiles hardened** (review #13): `defaultErrnoRet: 38` (ENOSYS) so libcs fall back (`clone3`→`clone`, `faccessat2`, …); `clone` is arg-constrained (`CLONE_NEW*` mask) and `clone3` answers ENOSYS unless explicitly `extra-allow`ed.
- **32-bit compat is unsupported** (review #14): profiles stay native 64-bit; compat observation fails the gate with guidance.
- **Cached release binary is re-verified** against the pinned digest on every run and cached under a versioned path (review #9); `SECCOMP_PROFILER_BIN` explicit override supported.
- **Daemon env via `sudo --preserve-env`** (review #8): `DOCKER_HOST` etc. actually reach the daemon under `env_reset`.
- Release workflow: unit tests are a required job, builds use pinned `clang-18`, `workflow_dispatch` removed, published assets are never overwritten, version injected via `-ldflags -X` (review #17).

### Fixed

- Daemon now shuts down on SIGTERM/SIGINT instead of leaving a root process with attached eBPF programs (review #7).
- Stop sequence is race-free: programs detach before the map flush and the ring buffer is drained (review Low).
- Root-owned output files are chowned back to `SUDO_UID:SUDO_GID` (review #10); writes are atomic (temp + rename).
- `on-change: update-pr` is implemented: generated profiles are written to the committed-profile location (review #6).
- `prune: true` opt-in stops re-adding syscalls removed from the committed profile (review #11).
- Inputs are validated fail-fast at daemon start (baseline typo, unknown runtime, unknown extra-allow syscall) (review #15); baseline names are filtered per target architecture on arm64.
- `docker events` stream reconnects with backoff; `merge` aligns with the daemon on corrupt committed profiles (error, not silent skip) (review #16).
- Kernel requirement raised to **5.19+** with an explicit startup check (the `cgroup_mkdir` tracepoint id is truncated to 32-bit before v5.19 and cannot be correlated).
- Shared-runner hygiene (review #20): containers are profiled only from profiler start by default (`include-preexisting` opt-in, flagged partial); `compose-project` filter; ephemeral Docker event attributes no longer leak into labels/artifacts.
- Demo media removed entirely — the project carries no bundled media (review #19).
- Markdown summary escapes label/image/reason content; `downloadFile` has timeouts and a redirect cap; batched `docker inspect`; control connections carry read deadlines; `sha256:`-only image names fall back to the container ID; Windows-only test transport isolated behind build tags; `statInode` uses `syscall.Stat_t` on Linux; action code de-duplicated into `action/lib.js`; fuzz tests for the approvals parser, glob matcher and event decoder.

## 1.0.0

Initial release: 3-hook eBPF tracer (cgroup_mkdir / sched_process_exec / raw sys_enter), Anchor-64 verifier optimization, runc/crun suppression, 4-layer provenance profiles, lock-protected outputs, semantic diff + risk gate, Sigstore-signed release binaries.
