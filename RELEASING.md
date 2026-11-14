# Releasing

The release flow is intentionally rigid: published assets are never overwritten, and the action pins the exact binary digest of the release it runs.

## Cut a release

1. Make sure `main` is green on both `ubuntu-24.04` and `ubuntu-24.04-arm`.
2. Bump the version:
   - `cmd/seccomp-profiler/main.go` default `version` (used when built without ldflags — must match the git tag without the leading `v`, enforced by `release.yml`),
   - `Makefile` `VERSION ?=`,
   - `CHANGELOG.md` section header (replace "unreleased").
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `Release` workflow runs unit tests, verifies generated syscall tables (`go generate ./...`), builds both architectures with pinned `clang-18`, signs with Cosign keyless OIDC, and publishes the release. It refuses to run for anything but tag pushes, rejects non-`vX.Y.Z` tags or version mismatches, and refuses to overwrite an existing release.
4. (Optional) publish the new version to the GitHub Actions Marketplace from the release page.

## Re-pin the action

The running action downloads the release binary pinned in `action/lib.js`:

```js
const PINNED_RELEASE_VERSION = "v1.2.0";
const PINNED_BINARY_SHA256 = { amd64: "...", arm64: "..." };
```

After the release is published:

1. `sha256sum dist/seccomp-profiler-linux-amd64 dist/seccomp-profiler-linux-arm64` (same values as the release's `checksums.txt`).
2. Update `PINNED_RELEASE_VERSION` and both `PINNED_BINARY_SHA256` entries in `action/lib.js`.
3. Update the matching version and SHA-256 assertions in `action/action.test.js` and the `/opt/seccomp-profiler/vX.Y.Z/` binary cache path assertions in `.github/workflows/ci.yml`.
4. Update the pinned `@<sha> # vX.Y.Z` references in `README.md` to the new release commit.
5. Commit and push to `main`. Users who pin by commit SHA keep getting the exact binary they pinned; users tracking `main` get the new one.

Until step 2 is done, CI in this repo still exercises freshly built binaries (`SECCOMP_PROFILER_BIN=/usr/local/bin/seccomp-profiler` in `ci.yml`), so the pin refresh is not on the critical path of testing the first job (`test-and-ebpf-integration`).
