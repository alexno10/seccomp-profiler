# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## Reporting a Vulnerability

Please open a [private security advisory](https://github.com/alexno10/seccomp-profiler/security/advisories/new) or contact the maintainer directly. Do **not** open a public issue for exploitable findings.

## Threat Model & Security Properties

`seccomp-profiler` is a security tool, so its own attack surface is treated seriously:

1. **The gate cannot be widened from inside a PR.** The committed reference profile and `accepted.yml` are read from the PR **base ref** (`baseline-ref`), not the working tree; PR-side edits are reported as drift and require review. Defense in depth: protect `.seccomp-profiler/` in `CODEOWNERS` and enable *Require review from Code Owners*.
2. **Comm spoofing is dead.** Kernel-side suppression is keyed on per-TID markers derived from the *pre-exec* comm only; `prctl(PR_SET_NAME, "runc")` no longer hides syscalls from `raw_tracepoint/sys_enter`.
3. **Fail-closed observation.** Kernel error counters (`cgroup_map_full`, `ringbuf_drops`, `oob_syscalls`) make any lost visibility fail the gate instead of passing silently.
4. **Conditional allows never widen silently.** Dropping argument constraints (`clone` without `CLONE_NEW*` mask) is reported as high-risk escalation drift.
5. **Target names are sanitized** (`^[A-Za-z0-9._-]{1,100}$`) — container labels can never make the root daemon write outside the output directory.
6. **Supply chain:** release binaries are commit-locked (`PINNED_RELEASE_VERSION` + `PINNED_BINARY_SHA256`), signed with Sigstore keyless OIDC (fully-anchored identity regex), re-verified on every cache hit, and built by pinned `clang-18` from tag pushes only. The cosign bootstrap itself is digest-pinned.
7. **Daemon environment isolation:** the `sudo` daemon receives an explicit allowlist (`--preserve-env`) stripped of every GitHub token/secret; CI asserts no `GITHUB_TOKEN`/`ACTIONS_*` leakage into the daemon environment.
8. **Untrusted output rendering:** container labels, image names, and approval reasons are escaped before being embedded in the Job Summary markdown.

### Explicitly out of scope / known limitations
- 32-bit compat workloads: detected and failed, not profiled.
- The `tcp://` control endpoint (testing only) has no authentication.
- Branch protection is still required for the CODEOWNERS mechanism to be enforceable.

## Hardening Recommendations for Users

- Pin the action by commit SHA (as shown in the README) and keep `.seccomp-profiler/` under CODEOWNERS.
- Treat generated profiles as code: review `.suggested.json` output instead of hand-editing generated files.
- Prefer `prune: true` once profiles are stable so removed syscalls actually disappear.
