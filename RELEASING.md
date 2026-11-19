# Releasing

The release flow is intentionally rigid: published assets are never overwritten, and the action pins the exact binary digest of the release it runs.

## Cut a release

1. Make sure `main` is green on both `ubuntu-24.04` and `ubuntu-24.04-arm`.
2. Bump the version:
   - `cmd/seccomp-profiler/main.go` default `version` (used when built without ldflags — must match the git tag without the leading `v`, enforced by `release.yml`),
   - `internal/profile/profile.go` default `ver` / `generatorVersion`,
   - `Makefile` `VERSION ?=`,
   - `CHANGELOG.md` section header (replace "unreleased").
3. Pre-pin deterministic release digests before tagging:
   - Extract the `amd64` / `arm64` SHA-256 digests produced by CI's `clang-18` deterministic build check (`Verify deterministic multi-arch release build (clang-18)`),
   - Update `PINNED_RELEASE_VERSION`, `PINNED_BINARY_SHA256`, `action/action.test.js`, and `.github/workflows/ci.yml` on `main` BEFORE pushing tag `vX.Y.Z`, so the tagged commit itself already pins its own release binaries (avoiding tag/pin drift).
4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `Release` workflow runs unit tests, verifies generated syscall tables (`go generate ./...`), builds both architectures with pinned `clang-18`, signs with Cosign keyless OIDC, and publishes the release. It refuses to run for anything but tag pushes, rejects non-`vX.Y.Z` tags or version mismatches, and refuses to overwrite an existing release.
5. (Optional) publish the new version to the GitHub Actions Marketplace from the release page.

## Re-pin / Sync README After Release

The running action downloads the release binary pinned in `action/lib.js`:

```js
const PINNED_RELEASE_VERSION = "v1.2.1";
const PINNED_BINARY_SHA256 = { amd64: "...", arm64: "..." };
```

After the release is published:

1. Verify `checksums.txt` from the published release matches `PINNED_BINARY_SHA256` bit-for-bit.
2. Update the pinned `@<sha> # vX.Y.Z` references in `README.md` to the exact tag commit SHA on `main`, then commit and push `main` so users pinning by SHA or by tag both get the exact verified `vX.Y.Z` commit.
