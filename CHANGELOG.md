# Changelog

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
- Demo media removed from the repository (review #19) — assets live on the GitHub Releases page.
- Markdown summary escapes label/image/reason content; `downloadFile` has timeouts and a redirect cap; batched `docker inspect`; control connections carry read deadlines; `sha256:`-only image names fall back to the container ID; Windows-only test transport isolated behind build tags; `statInode` uses `syscall.Stat_t` on Linux; action code de-duplicated into `action/lib.js`; fuzz tests for the approvals parser, glob matcher and event decoder.

## 1.0.0

Initial release: 3-hook eBPF tracer (cgroup_mkdir / sched_process_exec / raw sys_enter), Anchor-64 verifier optimization, runc/crun suppression, 4-layer provenance profiles, lock-protected outputs, semantic diff + risk gate, Sigstore-signed release binaries.
