# Awesome-OS Maintenance Workflows (`awesome-os/maintenance-workflows`)

> **Centralized reusable GitHub Actions release, verification, & `holo-ci` runtime for all `awesome-os/*` repositories — zero-dependency Node 24/26 erasable-TS CI (`reusable-holo-ci.yml@v1`), 5-OS Zig C11 matrix builds (`win64`, `linux-x64`, `linux-arm64`, `macos-arm64`, `wasm32-wasi`), `.vsix` + Open VSX releases, `install.ps1` / `install.sh`, and `SHA512SUMS.txt` / `SHA256SUMS.txt`.**

## Reusable Workflows

### 1. Universal `holo-ci` Verification & Telemetry (`reusable-holo-ci.yml@v1`)

Zero-dependency Node 24/26 erasable-TypeScript runner configured via [`holo-ci.json`](holo-ci.json):

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  verify:
    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-holo-ci.yml@v1
    with:
      config-path: holo-ci.json
      node-version: '24'
      phase: verify
      working-directory: '.'
      holo-ci-ref: v1
```

#### `holo-ci` CLI Subcommands

Run directly via native Node 24/26 (`node holo-ci/cli.mts <phase> [options]`):

| Subcommand | Description |
| :--- | :--- |
| `verify` | Executes declared `tests` and `nativeGates`, verifies `docs`, and scans workflows/manifests for `zeroGhost`, `zeroCasV1`, and `zeroHttpIpc` violations. |
| `sync` | Recursively compares SHA-256 hashes across `syncPairs` and audits active git working-tree status. |
| `bump` | Validates semver upstream pins (`pinned >= upstream`) and bumps `package.json` (`--version X.Y.Z`, `--dry-run`). |
| `pack` | Generates deterministic `holo-v11-manifest.json` (`0x33564742`) and `SHA512SUMS.txt` with byte-level dedup telemetry. |
| `telemetry` | Emits `holo-ci.receipt.v1` JSON/NDJSON (`--receipt`) and appends Markdown summaries to `$GITHUB_STEP_SUMMARY` (`--emit-summary`). |
| `maintain` | Performs zero-checkout clean-box HTTP `200`, SHA-512, and Ed25519 signature verification (`node:crypto`). |
| `init` | Scaffolds a starter `holo-ci.json` manifest in the target directory. |

Common flags: `--config <path>`, `--receipt <path>`, `--emit-summary`, `--json`, `--cwd <dir>`, `--help`.

### 2. 5-OS Native Matrix Release (`reusable-5os-release.yml`)
```yaml
name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  release:
    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-5os-release.yml@main
    with:
      binary_name: my-app
      c_source: src/launcher.c
```

### 3. VSIX + Open VSX Release (`reusable-vsix-release.yml`)
```yaml
name: Release VSIX
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  release:
    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-vsix-release.yml@main
    secrets:
      OVSX_PAT: ${{ secrets.OVSX_PAT }}
```

## Quick Install & Run (Windows / Linux / macOS)

```sh
# Install / hydrate from v11 CAS via holo-pm
holo-pm install repository://github.com/awesome-os/maintenance-workflows@main

# Or project & run directly via holo-project (0-byte hardlink)
holo-project "project://cpp/maintenance-workflows?from=repository://github.com/awesome-os/maintenance-workflows@main"
```
