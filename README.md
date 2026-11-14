# eBPF Seccomp Profiler (`seccomp-profiler`)

Automatically generate and audit Docker [Seccomp](https://docs.docker.com/engine/security/seccomp/) profiles during your GitHub Actions tests — **without changing a single line of your application or test commands**.

---

## Why Use This Action?

Writing Seccomp profiles by hand is notoriously hard: allow too little and your container crashes in production; allow too much and you leave dangerous kernel syscalls (`ptrace`, `mount`, `unshare`, `bpf`) wide open.

**`seccomp-profiler` solves this automatically in CI:**
1. **Watches your containers in the background** using Linux eBPF while your normal `docker run`, `docker compose`, or **Testcontainers** tests run (even containers that finish in under 10 milliseconds).
2. **Builds ready-to-use `seccomp.json` profiles** for each service/image by combining the syscalls your container actually used with safe container-startup and shutdown baselines.
3. **Protects your Pull Requests** by comparing new syscall behavior against your committed profiles, highlighting high-risk syscalls in the **GitHub Job Summary**, and failing the build if an unapproved high-risk syscall appears.

---

## Requirements

| Requirement | Why |
|---|---|
| Linux runner with **kernel ≥ 5.19** | The `cgroup_mkdir` tracepoint exposes a full 64-bit cgroup id only from v5.19 (on 5.15–5.18 it is a truncated `int` that cannot be correlated). The daemon fails fast with a clear error on older kernels. |
| cgroup v2 | Cgroup-id based container correlation. |
| `sudo` (root) for the daemon | eBPF tracepoints + raw tracepoint attachment. |
| Docker CLI available | `docker events` / `docker inspect` metadata. |
| GitHub-hosted `ubuntu-24.04` / `ubuntu-24.04-arm` runners, or self-hosted equivalents | Verified in this repo's CI on both architectures. |

32-bit (compat) binaries are detected but **not supported**: compat hits fail the security gate with an explanatory message, and generated profiles stay native 64-bit only.

---

## Quick Start (Zero Config)

Add one step before your tests. When the job finishes, `seccomp-profiler` automatically stops, writes the profiles, and posts a visual report to your **GitHub Job Summary**:

```yaml
steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6

  - name: Start Seccomp Profiler
    uses: alexno10/seccomp-profiler@ec9aca791d4bc39b5ccebbbd9f1f52a3dd60a868 # v1.1.1

  - name: Run your existing tests (Docker, Compose, or Testcontainers)
    run: docker compose run --rm api go test ./...
```

---

## Saving & Enforcing Generated Profiles

If you want to upload the generated profiles as workflow artifacts or test them immediately inside the same job, call the action a second time with `mode: stop`:

```yaml
steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6

  - name: Start Seccomp Profiler
    uses: alexno10/seccomp-profiler@ec9aca791d4bc39b5ccebbbd9f1f52a3dd60a868 # v1.1.1
    with:
      mode: start

  - name: Run integration tests
    run: docker run --rm myorg/api:test ./run-tests.sh

  - name: Stop Profiler & Generate Profiles
    id: seccomp
    uses: alexno10/seccomp-profiler@ec9aca791d4bc39b5ccebbbd9f1f52a3dd60a868 # v1.1.1
    with:
      mode: stop

  - name: Verify container runs with the generated Seccomp profile
    run: |
      docker run --rm \
        --security-opt seccomp=.seccomp-profiler/profiles/api.json \
        myorg/api:test ./healthcheck.sh

  - name: Upload Seccomp Profiles
    uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
    with:
      name: seccomp-profiles
      path: ${{ steps.seccomp.outputs.profiles-dir }}
```

---

## The Security Gate Cannot Be Widened From Inside a PR

Both the committed reference profile **and** `.seccomp-profiler/accepted.yml` are read from the **PR base ref** (`baseline-ref`, automatic on `pull_request` events), not from the working tree. A PR that adds `ptrace` to its own profile, or that self-approves `ptrace` in `accepted.yml`, gains nothing: the pristine base versions are used for comparison and approval. Changes to those files inside a PR are reported as drift warnings in the Job Summary and still require review.

Set `baseline-ref: none` to disable (e.g. for scheduled runs on `main`), or pass an explicit ref.

> [!IMPORTANT]
> Protect `.seccomp-profiler/` and your committed profile directory in `.github/CODEOWNERS` so approval entries require security team review, and enable **Require review from Code Owners** in branch protection:
>
> ```gitignore
> .seccomp-profiler/ @myorg/security-team
> seccomp/           @myorg/security-team
> ```

## Approving New High-Risk Syscalls

Because approvals are read from the base ref, merge intentional approval entries to your base branch first (through a CODEOWNERS-protected PR), then rebase:

```yaml
version: 1
accepted:
  - target: api
    syscall: bpf
    reason: "Required by internal observability agent"
    expires: 2027-01-01
```

---

## Hardening Built Into Generated Profiles

- `defaultErrnoRet: 38` (ENOSYS) so glibc/musl fall back to older syscall paths instead of crashing (`clone3` → `clone`, `faccessat2`, `statx`, `rseq`).
- `clone` is never allowed unconditionally: the generated profile masks the `CLONE_NEW*` namespace flags (like Docker's default profile), and `clone3` is answered with ENOSYS so libcs fall back. Use `extra-allow: clone` to consciously opt out.
- A syscall that was only allowed under argument constraints can never silently become an unconditional allow — such escalations are reported as high-risk drift and fail the gate.

---

## Inputs & Outputs

### Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `start` | `start` or `stop`. If `mode: stop` is not called explicitly, the `post:` hook stops the profiler automatically at the end of the job. |
| `baseline-ref` | `""` (auto) | Git ref to read the committed profile and approvals from. Empty = the PR base ref on `pull_request` events, otherwise the working tree. `none` disables. |
| `targets` | `""` (auto) | Optional selector rules (`image` / `labels` -> target name). When empty, all non-infra containers are profiled automatically. |
| `group-by` | `auto` | How multiple containers are grouped into a single profile: `auto` (`com.docker.compose.service` label, falling back to image name), `compose-service`, `image`, or `label:<key>`. |
| `exclude-images` | `""` | Additional image globs to ignore (appended to built-in exclusions like `testcontainers/ryuk:*` and `moby/buildkit:*`). |
| `compose-project` | `""` | Only profile containers of this `com.docker.compose.project` (useful on shared self-hosted runners). |
| `include-preexisting` | `false` | Also profile containers that were already running at start. They are flagged `"preexisting": true` in the raw artifact because their early syscalls were never observed. |
| `output-dir` | `.seccomp-profiler/profiles` | Directory where generated `<target>.json` OCI seccomp profiles are written. |
| `committed-profile` | `.seccomp-profiler/profiles/{name}.json` | Path template, directory, or file path of committed reference profile(s) for PR diffing. |
| `baseline` | `standard` | Baseline layer mode: `standard` (runtime + safe lifecycle syscalls), `minimal` (runtime handover only), or `none` (strictly observed syscalls only). Invalid values fail fast at start. |
| `runtime` | `auto` | Language runtime baseline: `auto`, `go`, `node`, `python`, `java`, or `none`. |
| `extra-allow` | `""` | Comma- or newline-separated list of additional syscalls to allow. Unknown syscall names fail fast. |
| `prune` | `false` | Do not merge syscalls removed from the committed profile back into the generated output (restores least-privilege; removed syscalls are listed in the summary). |
| `on-change` | `report` | Policy when non-high-risk syscalls are added: `report`, `fail`, or `update-pr` (writes generated profiles to the committed-profile location for the PR author to commit). |
| `fail-on` | `high-risk` | Security gate threshold: `high-risk`, `any-new`, or `none`. |
| `allow-file` | `.seccomp-profiler/accepted.yml` | Path to the YAML file containing explicit syscall approvals. |

### Outputs

| Output | Description |
|---|---|
| `profiles-dir` | Directory containing generated `<target>.json` seccomp profiles. |
| `raw-dir` | Directory containing intermediate `<target>.profile.v1.json` provenance artifacts. |
| `new-syscalls-count` | Total number of newly added syscalls across all targets. |
| `high-risk-count` | Number of unapproved high-risk syscalls detected. |
| `gate-passed` | `true` if the security gate passed, `false` otherwise. |

The gate additionally fails when kernel-side error counters are non-zero (a BPF map filled up, a ring buffer event was dropped, or an out-of-range syscall id was seen) — an incomplete observation must never pass silently.

---

## Merging Profiles Across Matrix Jobs (CLI)

If your test suite runs across multiple parallel CI jobs, upload `.seccomp-profiler/raw/*.profile.v1.json` from each job and merge them in a final job:

```bash
seccomp-profiler merge \
  --input-dir ./raw-shards \
  --output-dir .seccomp-profiler/profiles \
  --raw-dir .seccomp-profiler/raw \
  --committed-profile ".seccomp-profiler/profiles/{name}.json" \
  --fail-on high-risk
```

---

## Architecture & Security Documentation

For a deep technical overview of the 5-hook eBPF kernel tracer, Anchor-64 verifier optimization, runc/crun suppression model (and why `prctl(PR_SET_NAME, "runc")` no longer hides syscalls), 4-layer provenance model, hand-edit lock protection, and Sigstore Cosign OIDC verification, see [**`docs/ARCHITECTURE.md`**](docs/ARCHITECTURE.md). For the security policy see [**`SECURITY.md`**](SECURITY.md).

---

## License

Released under the [MIT License](LICENSE) (`bpf/profiler.bpf.c` is dual-licensed `GPL-2.0 OR MIT`).
