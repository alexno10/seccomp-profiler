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

## Quick Start (Zero Config)

Add one step before your tests. When the job finishes, `seccomp-profiler` automatically stops, writes the profiles, and posts a visual report to your **GitHub Job Summary**:

```yaml
steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6

  - name: Start Seccomp Profiler
    uses: alexno10/seccomp-profiler@c1feb973f021cafdce692b6e2c385023d604d54d # v1.0.0

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
    uses: alexno10/seccomp-profiler@c1feb973f021cafdce692b6e2c385023d604d54d # v1.0.0
    with:
      mode: start

  - name: Run integration tests
    run: docker run --rm myorg/api:test ./run-tests.sh

  - name: Stop Profiler & Generate Profiles
    id: seccomp
    uses: alexno10/seccomp-profiler@c1feb973f021cafdce692b6e2c385023d604d54d # v1.0.0
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

## Approving New High-Risk Syscalls in PRs

By default (`fail-on: high-risk`), if a Pull Request introduces a high-risk syscall (such as `ptrace`, `mount`, or `bpf`) compared to your committed profile, the action fails the check and explains why in the Job Summary.

If the new syscall is intentional, add an approval entry with a reason (and optional expiration date) in `.seccomp-profiler/accepted.yml`:

```yaml
version: 1
accepted:
  - target: api
    syscall: bpf
    reason: "Required by internal observability agent"
    expires: 2027-01-01
```

> [!IMPORTANT]
> Protect `.seccomp-profiler/` and your committed profile directory in `.github/CODEOWNERS` so high-risk syscall approvals require security team review:
>
> ```gitignore
> .seccomp-profiler/ @myorg/security-team
> seccomp/           @myorg/security-team
> ```

---

## Inputs & Outputs

### Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `start` | `start` or `stop`. If `mode: stop` is not called explicitly, the `post:` hook stops the profiler automatically at the end of the job. |
| `targets` | `""` (auto) | Optional selector rules (`image` / `labels` -> target name). When empty, all non-infra containers are profiled automatically. |
| `group-by` | `auto` | How multiple containers are grouped into a single profile: `auto` (`com.docker.compose.service` label, falling back to image name), `compose-service`, `image`, or `label:<key>`. |
| `exclude-images` | `""` | Additional image globs to ignore (appended to built-in exclusions like `testcontainers/ryuk:*` and `moby/buildkit:*`). |
| `output-dir` | `.seccomp-profiler/profiles` | Directory where generated `<target>.json` OCI seccomp profiles are written. |
| `committed-profile` | `.seccomp-profiler/profiles/{name}.json` | Path template, directory, or file path of committed reference profile(s) for PR diffing. |
| `baseline` | `standard` | Baseline layer mode: `standard` (runtime + safe lifecycle syscalls), `minimal` (runtime handover only), or `none` (strictly observed syscalls only). |
| `runtime` | `auto` | Language runtime baseline: `auto`, `go`, `node`, `python`, `java`, or `none`. |
| `extra-allow` | `""` | Comma- or newline-separated list of additional syscalls to allow. |
| `on-change` | `report` | Policy when non-high-risk syscalls are added: `report`, `fail`, or `update-pr`. |
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

For a deep technical overview of the 3-hook eBPF kernel tracer, Anchor-64 verifier optimization, `runc` initialization suppression, 4-layer provenance model, hand-edit lock protection, and Sigstore Cosign OIDC verification, see [**`docs/ARCHITECTURE.md`**](docs/ARCHITECTURE.md).

---

## License

Released under the [MIT License](LICENSE) (`bpf/profiler.bpf.c` is dual-licensed `GPL-2.0 OR MIT`).
