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
| `lock-compat` | Synthesizes a deterministic, byte-sorted npm `lockfileVersion: 3` `package-lock.json` (`holoCasStore: "v11"`, `zeroCopyNodeModules: true`) from `package.json`, `pnpm-lock.yaml`, and `max-version-lock.json` without modifying `node_modules`. |

Common flags: `--config <path>`, `--receipt <path>`, `--emit-summary`, `--json`, `--cwd <dir>`, `--out <path>`, `--dry-run`, `--max-lock <path>`, `--help`.

### Zero-Migration Strangler-Fig Hybrid Workspace Pattern (`holo-ci lock-compat`)

When migrating or interoperating between standard npm tooling and the Awesome-OS `v11` CAS / `pnpm` store without duplicating `node_modules`, use the **Zero-Migration Strangler-Fig Hybrid Workspace Pattern**:

1. **Create strangler-fig workspaces cleanly** with npm CLI:
   ```sh
   npm init -w ./workspaces/<pkg>
   ```
2. **Keep runtime dependencies deduplicated** in the zero-copy `pnpm` / `holo-v11` CAS store (`pnpm-lock.yaml` + `max-version-lock.json`).
3. **Emit or refresh `package-lock.json` (`lockfileVersion: 3`) without touching `node_modules`**:
   ```sh
   # Standard npm lockfile-only sync OR zero-dependency holo-ci synthesis
   npm i --package-lock-only
   node holo-ci/cli.mts lock-compat --cwd . --out package-lock.json --dry-run --json
   ```

`holo-ci lock-compat` reads `package.json` (`name`, `version`, `dependencies`, `devDependencies`, `workspaces`), resolves exact versions/integrity hashes from `pnpm-lock.yaml` and `max-version-lock.json` if present, and emits a deterministic byte-sorted `lockfileVersion: 3` manifest stamped with `"holoCasStore": "v11"` and `"zeroCopyNodeModules": true` while leaving `node_modules` completely untouched.

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
