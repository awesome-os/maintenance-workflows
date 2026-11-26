# Changelog

All notable changes to `awesome-os/maintenance-workflows` (`holo-ci@v1`) are documented in this file.

## [1.1.0] - 2026-11-26

### Added
- **Governance Guards (`holo-ci verify`):** Added optional backwards-compatible `spdxLicense`, `gitattributes`, and `codeowners` guards to `HoloCiGuards` and `HoloCiGuardViolation['guard']` in `holo-ci/schema.mts` and `holo-ci/verify.mts`:
  - `spdxLicense`: validates non-truncated OSI/SPDX clause text in `LICENSE` (`MIT`, `BSD-3-Clause`, or `Apache-2.0`).
  - `gitattributes`: validates `.gitattributes` existence and `eol=lf` normalization.
  - `codeowners`: validates `.github/CODEOWNERS` or `CODEOWNERS` presence.
- **Chromium Autoroller Workflow (`.github/workflows/reusable-holo-autoroll.yml`):** Added reusable `workflow_call` autoroller running `holo-ci bump --fetch-upstream --apply-pins`, branching `autoroll/upstream-pins-<run_id>`, committing with `Bug:` and `Verified-By: holo-ci@v1` trailers, opening `type/autoroll` PRs via `gh pr create`, and optionally enabling `gh pr merge --auto --squash`.
- **Repository Governance:** Added OSI MIT `LICENSE`, `.gitattributes`, `.github/CODEOWNERS`, `CHANGELOG.md`, and dogfooded all governance guards in `holo-ci.json`.

## [1.0.0] - 2026-11-26

### Added
- **Zero-Dependency `holo-ci` Runtime (`holo-ci/`):** Node 24/26 erasable-TypeScript CI/CD runtime with `verify`, `sync`, `bump`, `pack`, `telemetry`, `maintain`, `init`, and `lock-compat` phases (`0x33564742` `holo-ci.receipt.v1`).
- **9-Ecosystem `lock-compat` Projection:** Deterministic zero-host-mutation projections for `npm`, `cargo`, `uv`, `go`, `vcpkg`, `winget`, `apt`, `composer`, and `rubygems`.
- **Reusable Workflows:** `reusable-holo-ci.yml@v1`, `reusable-holo-e2e.yml@v1` (offscreen Lavapipe + Zero-X11 E2E runner with signed `v11-oci-latest` fallback), `reusable-5os-release.yml`, `reusable-damped-gravity-cas.yml`, `reusable-gravity-pin-dedup-telemetry.yml`, `reusable-tarball-release.yml`, and `reusable-vsix-release.yml`.
