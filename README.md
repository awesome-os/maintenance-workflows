<!-- DOC-STATIC-CORPUS -->

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
      node-version: '26'
      phase: verify
      working-directory: '.'
      holo-ci-ref: v1
      extra-args: ''
```

When invoking `reusable-holo-ci.yml@v1` for `bump` (for example with `extra-args: '--fetch-upstream --apply-pins'`), the job exposes `outputs.bumped` (`'true'` when `bump?.bumpedCount > 0 || bump?.packageBump?.updated` in `holo-ci-receipt.ndjson`, otherwise `'false'`) so downstream build, `pack`, and release jobs can trigger conditionally when fresh upstream versions appear.

#### `holo-ci` CLI Subcommands

Run directly via native Node 24/26 (`node holo-ci/cli.mts <phase> [options]`):

| Subcommand | Description |
| :--- | :--- |
| `verify` | Executes declared `tests` and `nativeGates`, verifies `docs`, and scans workflows/manifests for `zeroGhost`, `zeroCasV1`, and `zeroHttpIpc` violations. |
| `sync` | Recursively compares SHA-256 hashes across `syncPairs` and audits active git working-tree status. |
| `bump` | Validates semver upstream pins (`pinned >= upstream`), optionally fetches live GitHub upstream versions (`--fetch-upstream`), updates lagged pins in `holo-ci.json` (`--apply-pins`), and bumps `package.json` (`--version X.Y.Z`, `--dry-run`). |
| `pack` | Generates deterministic `holo-v11-manifest.json` (`0x33564742`) and `SHA512SUMS.txt` with byte-level dedup telemetry, and optionally materializes `<cas-dir>/v11/files/<aa>/<sha512>` CAS blobs (`--cas-dir <dir>`). |
| `telemetry` | Emits `holo-ci.receipt.v1` JSON/NDJSON (`--receipt`) and appends Markdown summaries to `$GITHUB_STEP_SUMMARY` (`--emit-summary`). |
| `maintain` | Performs zero-checkout clean-box HTTP `200`, SHA-512, and Ed25519 signature verification (`node:crypto`). |
| `init` | Scaffolds a starter `holo-ci.json` manifest in the target directory. |
| `lock-compat` | Synthesizes zero-copy `v11` CAS lock & metadata projections across 9 ecosystems (`npm`, `cargo`, `uv`, `go`, `vcpkg`, `winget`, `apt`, `composer`, `rubygems`, or `all`; aliases: `php`, `ruby`, `bundler`) into `--out-dir` without mutating `node_modules` or host package stores. |

Common flags: `--config <path>`, `--receipt <path>`, `--emit-summary`, `--json`, `--cwd <dir>`, `--fetch-upstream`, `--apply-pins`, `--cas-dir <dir>`, `--out <path>`, `--out-dir <dir>`, `--ecosystem <all|npm|cargo|uv|go|vcpkg|winget|apt|composer|rubygems>`, `--dry-run`, `--max-lock <path>`, `--help`.

### Zero-Migration Strangler-Fig Hybrid Workspace Pattern (`holo-ci lock-compat`)

When migrating or interoperating between native package managers and the Awesome-OS `v11` CAS / `pnpm` store without duplicating `node_modules` or mutating host stores, use the **Zero-Migration Strangler-Fig Hybrid Workspace Pattern**:

1. **Create strangler-fig workspaces cleanly** with npm CLI:
   ```sh
   npm init -w ./workspaces/<pkg>
   ```
2. **Keep runtime dependencies deduplicated** in the zero-copy `pnpm` / `holo-v11` CAS store (`pnpm-lock.yaml` + `max-version-lock.json`).
3. **Emit or refresh ecosystem projections without touching `node_modules` or host stores**:
   ```sh
   # Standard npm lockfile-only sync OR zero-dependency holo-ci synthesis
   npm i --package-lock-only
   node holo-ci/cli.mts lock-compat --ecosystem npm --cwd . --out package-lock.json --dry-run --json

   # Emit all 9 ecosystem projections into an isolated output directory
   node holo-ci/cli.mts lock-compat --ecosystem all --cwd . --out-dir dist/lock-compat --json

   # PHP (Composer + PHP-WASI @wp/env) and Ruby (Bundler + ruby.wasm) aliases
   node holo-ci/cli.mts lock-compat --ecosystem php --cwd . --out-dir dist/lock-compat --json
   node holo-ci/cli.mts lock-compat --ecosystem ruby --cwd . --out-dir dist/lock-compat --json
   ```

Supported `--ecosystem` targets (`default: npm`):

| Ecosystem | Projected Artifacts | Zero-Host-Mutation Invariant |
| :--- | :--- | :--- |
| `npm` | `package-lock.json` (`lockfileVersion: 3`, `holoCasStore: "v11"`, `zeroCopyNodeModules: true`) | Never writes `node_modules/.package-lock.json` or mutates `node_modules`. |
| `cargo` | `.cargo/config.toml` (`[source.crates-io] replace-with = "holo-v11"`) + `holo-cargo-compat.json` | Offline vendor CAS mapping without touching `~/.cargo`. |
| `uv` | `uv.toml` (`link-mode = "hardlink"`, `cache-dir`) + `requirements.holo-v11.txt` | Hardlink CAS cache projection without touching host Python envs. |
| `go` | `go.work` (`go 1.24`, CAS proxy metadata) | Discovers local `go.mod` modules with `v11` CAS `GOPROXY` metadata. |
| `vcpkg` | `vcpkg-configuration.json` + `pkgconfig/*.pc` (20 shared C/C++ libs incl. `cairo`, `curl`, `freetype`, `harfbuzz`, `icu4c`, `libgd`, `libgit2`, `libpng`, `librdkafka`, `libsodium`, `libvips`, `libxml2`, `libxslt`, `libzip`, `oniguruma`, `openssl`, `pixman`, `sqlite`, `zlib`, `zstd`) | Pinned `v11` C/C++ library stubs synced to `68/68` max-version defaults (`cairo 1.18.6`, `harfbuzz 15.2.0`, `libxml2 2.15.4`, `libxslt 1.1.45`, `zstd 1.6.0`, `zlib 1.4`, `sqlite 3.54.1`, `curl 8.23.0`, `icu4c 79.1`, `oniguruma 6.9.10`, `libgit2 1.9.7`, `librdkafka 2.16.0`, `libvips 8.18.7`, `freetype 2.15.0`, `libpng 1.6.59`, `pixman 0.46.4`, `openssl 4.1.0`, `libsodium 1.0.22`, `libgd 2.3.3`, `libzip 1.12.1`) and auto-discovered from `max-version-lock.json` or sibling `../t2linux-baseline/catalog/max-version-lock.json`. |
| `winget` | `winget-import.holo-v11.json` + `winget-hkcu-arp.holo-v11.json` | Zero-UAC `HKCU` portable ARP registry manifest JSON (`0` MSI installers). |
| `apt` | `dpkg-status.holo-v11` (`Status: install ok installed` virtual-provides stanzas) | Mandatory ELF `soname` gate on every stanza; zero `/var/lib/dpkg` writes. |
| `composer` *(alias: `php`)* | `composer.holo-v11.json` + `php.holo-v11.ini` + `wp-env.holo-v11.json` (`@wp/env` `php-wasi` + `sqlite-wasi`) | Symlink CAS path repo + `v11` C-extension pins; zero `vendor/` mutation. |
| `rubygems` *(aliases: `ruby`, `bundler`)* | `.bundle/config.holo-v11` + `holo-rubygems-compat.json` (C-ext SONAME map + `ruby.wasm` WASI) | Offline `v11` gem cache & system-lib flags; zero host `~/.gem` mutation. |

### 2. Offscreen Lavapipe + Zero-X11 E2E Runner (`reusable-holo-e2e.yml@v1`)

Containerized E2E workflow running on `ubuntu-latest` that resolves `ghcr.io/awesome-os/holo-e2e-runner:latest` (with automatic fallback to the signed `v11-oci-latest` release tarball + `SHA512SUMS-holo-e2e-runner.txt` verification when GHCR is unreachable), mounts the caller workspace + shared `$HOME/.b8g/cas:/var/lib/b8g/cas` volume, executes `/usr/local/bin/holo-e2e-probe` (Lavapipe software Vulkan + Zero-X11 offscreen BMP probe), [`holo-ci`](holo-ci/cli.mts) `verify`, optional `e2e-command` execution (`HOLO_E2E_ARTIFACTS`), appends a summary table (`lavapipeIcd`, `bmpSha512`, `holo-ci verify` status) to `$GITHUB_STEP_SUMMARY`, and uploads `holo-e2e-artifacts`:

```yaml
name: E2E
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  e2e:
    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-holo-e2e.yml@v1
    with:
      config-path: holo-ci.json
      e2e-command: 'node test/e2e.mts'
      working-directory: '.'
      holo-ci-ref: v1
      runner-image: 'ghcr.io/awesome-os/holo-e2e-runner:latest'
      artifacts-path: holo-e2e-artifacts
```

| Input | Default | Description |
| :--- | :--- | :--- |
| `config-path` | `'holo-ci.json'` | Path to `holo-ci.json` manifest relative to `working-directory`. |
| `e2e-command` | `''` | Optional shell command executed inside `working-directory` with `HOLO_E2E_ARTIFACTS` exported. |
| `working-directory` | `'.'` | Working directory inside the caller repository. |
| `holo-ci-ref` | `'v1'` | Git ref of `awesome-os/maintenance-workflows` checked out into `.holo-ci-runtime`. |
| `runner-image` | `'ghcr.io/awesome-os/holo-e2e-runner:latest'` | Zero-X11 Lavapipe E2E container image. |
| `artifacts-path` | `'holo-e2e-artifacts'` | Directory relative to `github.workspace` receiving `offscreen-probe.bmp`, `offscreen-probe.json`, `holo-e2e-receipt.ndjson`, and uploaded artifacts. |

### 3. 5-OS Native Matrix Release (`reusable-5os-release.yml`)
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

### 4. VSIX + Open VSX Release (`reusable-vsix-release.yml`)
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
