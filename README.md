# Awesome-OS Maintenance Workflows (`awesome-os/maintenance-workflows`)

> **Centralized reusable GitHub Actions release & maintenance workflows for all 100+ `awesome-os/*` repositories — 5-OS Zig C11 matrix builds (`win64`, `linux-x64`, `linux-arm64`, `macos-arm64`, `wasm32-wasi`), `.vsix` + Open VSX releases, `install.ps1` / `install.sh`, and `SHA256SUMS.txt`.**

## Reusable Workflows

### 1. 5-OS Native Matrix Release (`reusable-5os-release.yml`)
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

### 2. VSIX + Open VSX Release (`reusable-vsix-release.yml`)
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
