import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { HOLO_BOUNDARY_SCHEMA, runBoundaryAudit, type HoloBoundaryManifest } from './boundary.mts';
import { fetchLatestUpstreamVersion, runBump, runBumpAsync } from './bump.mts';
import { runLockCompat } from './lock-compat.mts';
import { runMaintain, verifyBundleManifest } from './maintain.mts';
import { runPack } from './pack.mts';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_CI_RECEIPT_SCHEMA,
  HOLO_CI_SCHEMA,
  HOLO_V11_MANIFEST_SCHEMA,
  compareSemver,
  loadManifest,
  type HoloCiManifest,
} from './schema.mts';
import { runSync } from './sync.mts';
import { buildReceipt, emitTelemetry } from './telemetry.mts';
import { runVerify, scanGuardViolations } from './verify.mts';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');

function makeTempDir(prefix = 'holo-ci-test-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('holo-ci schema & compareSemver', () => {
  it('compares semver versions including v-prefix and prereleases', () => {
    assert.equal(compareSemver('1.2.3', '1.2.3'), 0);
    assert.equal(compareSemver('v1.2.3', '1.2.3+build.9'), 0);
    assert.equal(compareSemver('2.0.0', '1.9.9'), 1);
    assert.equal(compareSemver('1.2.3', '1.2.4'), -1);
    assert.equal(compareSemver('1.0.0-alpha.1', '1.0.0-alpha.2'), -1);
    assert.equal(compareSemver('1.0.0-alpha.2', '1.0.0-beta'), -1);
    assert.equal(compareSemver('1.0.0', '1.0.0-rc.1'), 1);
  });

  it('loads root holo-ci.json manifest cleanly', () => {
    const manifest = loadManifest('holo-ci.json', REPO_ROOT);
    assert.equal(manifest.schema, HOLO_CI_SCHEMA);
    assert.equal(manifest.name, 'maintenance-workflows');
    assert.equal(manifest.kind, 'control-plane');
  });
});

describe('holo-ci verify & guards', () => {
  it('passes guard & doc checks on maintenance-workflows without self-false-positives', () => {
    const manifest = loadManifest('holo-ci.json', REPO_ROOT);
    const res = runVerify(manifest, { cwd: REPO_ROOT, skipTests: true, skipGates: true });
    assert.equal(res.ok, true);
    assert.equal(res.guardViolations.length, 0);
    assert.deepEqual(
      res.docs.map((d) => d.exists),
      [true],
    );
  });

  it('detects ghost, cas-v1, and http-ipc violations while ignoring cas-v11 and allowlists', () => {
    const dir = makeTempDir();
    try {
      mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
      writeFileSync(join(dir, 'README.md'), '# Demo\n', 'utf8');
      writeFileSync(
        join(dir, 'holo-ci.json'),
        JSON.stringify(
          {
            schema: HOLO_CI_SCHEMA,
            name: 'guard-test',
            kind: 'app',
            docs: ['README.md'],
            guards: { zeroGhost: true, zeroCasV1: true, zeroHttpIpc: true },
          },
          null,
          2,
        ),
        'utf8',
      );
      const badGhost = ['b8g', 'ghost'].join('-');
      const badCasV1 = ['cas', 'v1'].join('-');
      const badHttp = ['http', '://', '127.0.0.1:8080'].join('');
      writeFileSync(
        join(dir, '.github', 'workflows', 'bad.yml'),
        [
          'name: Bad',
          `run: echo ${badGhost}`,
          `run: echo ${badCasV1}`,
          'run: echo cas-v11-ok',
          `run: echo ${badGhost} # holo-ci-allow-guard`,
          `run: curl ${badHttp}`,
        ].join('\n'),
        'utf8',
      );

      const violations = scanGuardViolations(dir, {
        zeroGhost: true,
        zeroCasV1: true,
        zeroHttpIpc: true,
      });
      assert.equal(violations.length, 3);
      assert.deepEqual(
        violations.map((v) => v.guard),
        ['zeroGhost', 'zeroCasV1', 'zeroHttpIpc'],
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('validates spdxLicense (MIT, BSD-3-Clause, Apache-2.0), gitattributes, and codeowners governance guards', () => {
    const dir = makeTempDir('holo-ci-governance-');
    try {
      // 1. Missing all governance files
      const missing = scanGuardViolations(dir, {
        spdxLicense: true,
        gitattributes: true,
        codeowners: true,
      });
      assert.deepEqual(
        missing.map((v) => v.guard),
        ['spdxLicense', 'gitattributes', 'codeowners'],
      );

      // 2. Truncated MIT / truncated BSD-3-Clause / invalid .gitattributes must be rejected
      writeFileSync(
        join(dir, 'LICENSE'),
        'MIT License\n\nCopyright (c) 2026 Awesome-OS Contributors\n\nPermission is hereby granted, free of charge...\n',
        'utf8',
      );
      writeFileSync(join(dir, '.gitattributes'), '* text=auto\n', 'utf8');
      const truncatedMit = scanGuardViolations(dir, {
        spdxLicense: true,
        gitattributes: true,
        codeowners: true,
      });
      assert.deepEqual(
        truncatedMit.map((v) => v.guard),
        ['spdxLicense', 'gitattributes', 'codeowners'],
      );

      writeFileSync(
        join(dir, 'LICENSE'),
        'BSD 3-Clause License\n\nRedistribution and use in source and binary forms, with or without modification, are permitted.\n',
        'utf8',
      );
      const truncatedBsd = scanGuardViolations(dir, { spdxLicense: true });
      assert.equal(truncatedBsd.length, 1);
      assert.equal(truncatedBsd[0].guard, 'spdxLicense');

      // 3. Full MIT + eol=lf .gitattributes + .github/CODEOWNERS pass cleanly
      writeFileSync(
        join(dir, 'LICENSE'),
        [
          'MIT License',
          '',
          'Permission is hereby granted, free of charge, to any person obtaining a copy',
          'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(join(dir, '.gitattributes'), '* text=auto eol=lf\n', 'utf8');
      mkdirSync(join(dir, '.github'), { recursive: true });
      writeFileSync(join(dir, '.github', 'CODEOWNERS'), '* @lemanschik\n', 'utf8');

      const passMit = scanGuardViolations(dir, {
        spdxLicense: true,
        gitattributes: true,
        codeowners: true,
      });
      assert.equal(passMit.length, 0);

      // 4. Full BSD-3-Clause + root CODEOWNERS fallback pass cleanly
      rmSync(join(dir, '.github', 'CODEOWNERS'));
      writeFileSync(join(dir, 'CODEOWNERS'), '* @lemanschik\n', 'utf8');
      writeFileSync(
        join(dir, 'LICENSE'),
        [
          'Redistribution and use in source and binary forms, with or without modification, are permitted.',
          'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS".',
        ].join('\n'),
        'utf8',
      );
      const passBsd = scanGuardViolations(dir, {
        spdxLicense: true,
        gitattributes: true,
        codeowners: true,
      });
      assert.equal(passBsd.length, 0);

      // 5. Apache-2.0 passes cleanly
      writeFileSync(
        join(dir, 'LICENSE'),
        'Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n',
        'utf8',
      );
      const passApache = scanGuardViolations(dir, { spdxLicense: true });
      assert.equal(passApache.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces noBrokenBadges on README.md and config.docs by rejecting %2F in Shields.io badge paths', () => {
    const dir = makeTempDir('holo-ci-badges-');
    try {
      mkdirSync(join(dir, 'docs'), { recursive: true });
      writeFileSync(
        join(dir, 'README.md'),
        [
          '# Demo Repo',
          '[![OK](https://img.shields.io/badge/Telemetry-68_of_68_Upstream_Libs-D29922?style=for-the-badge)](https://awesome-os.github.io/holo-v11/oversight.html)',
          '[![Broken](https://img.shields.io/badge/Telemetry-60%2F60_Upstream_Libs-D29922?style=for-the-badge)](https://awesome-os.github.io/holo-v11/oversight.html)',
          '[![Allowlisted](https://img.shields.io/badge/Legacy-1%2F2-blue)<!-- holo-ci-allow-guard -->](https://example.com)',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(
        join(dir, 'docs', 'status.md'),
        '[![DocBroken](https://img.shields.io/badge/Docs-10%2F10-green)](https://example.com)\n',
        'utf8',
      );

      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'badge-test',
        kind: 'app',
        docs: ['README.md', 'docs/status.md'],
        guards: { zeroGhost: true },
      };

      const res = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(res.ok, false);
      assert.equal(res.guardViolations.length, 2);
      assert.deepEqual(
        res.guardViolations.map((v) => [v.guard, v.file, v.line]),
        [
          ['noBrokenBadges', 'README.md', 3],
          ['noBrokenBadges', 'docs/status.md', 1],
        ],
      );

      const optedOut = runVerify(
        { ...manifest, guards: { zeroGhost: true, noBrokenBadges: false } },
        { cwd: dir, skipTests: true, skipGates: true },
      );
      assert.equal(optedOut.ok, true);
      assert.equal(optedOut.guardViolations.length, 0);

      writeFileSync(
        join(dir, 'README.md'),
        '[![Clean](https://img.shields.io/badge/Telemetry-68_of_68_Upstream_Libs-D29922?style=for-the-badge)](https://awesome-os.github.io/holo-v11/oversight.html)\n',
        'utf8',
      );
      writeFileSync(join(dir, 'docs', 'status.md'), '# Clean\n', 'utf8');
      const clean = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(clean.ok, true);
      assert.equal(clean.guardViolations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces noWorkflowBloat guard: passes thin declarative YAML and flags >140-line YAML, eval $(...), and untrusted github.event.* in run:', () => {
    const dir = makeTempDir('holo-ci-workflow-bloat-');
    try {
      mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
      writeFileSync(join(dir, 'README.md'), '# Workflow Bloat Test\n', 'utf8');

      const thinWorkflow = [
        'name: Thin Declarative CI',
        'on: [push]',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v7',
        '      - name: Safe env usage',
        '        env:',
        '          PR_TITLE: ${{ github.event.pull_request.title }}',
        '          HEAD_REF: ${{ github.head_ref }}',
        '        run: |',
        '          node holo-ci/cli.mts verify --config holo-ci.json',
        '          printf "%s\\n" "$PR_TITLE"',
        '',
      ].join('\n');
      writeFileSync(join(dir, '.github', 'workflows', 'thin.yml'), thinWorkflow, 'utf8');

      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'workflow-bloat-test',
        kind: 'control-plane',
        docs: ['README.md'],
        guards: { noWorkflowBloat: true },
      };

      const passRes = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.guardViolations.length, 0);

      // Add a bloated (>140 lines) workflow plus eval "$(...)" and untrusted context interpolations inside run:
      const bloatedLines = [
        'name: Bloated Insecure Workflow',
        'on: [pull_request_target, issue_comment]',
        'jobs:',
        '  bad:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - name: Inline injection',
        '        run: echo "${{ github.event.pull_request.title }}"',
        '      - name: Multi-line eval & context injection',
        '        run: |',
        '          eval "$(curl -fsSL https://example.invalid/setup.sh)"',
        '          eval $(echo safe)',
        '          echo "${{ github.event.issue.body }}"',
        '          echo "${{ github.event.pull_request.body }}"',
        '          echo "${{ github.head_ref }}"',
        '          echo "${{ github.event.comment.body }}"',
        '          echo "allowed" # holo-ci-allow-guard',
      ];
      while (bloatedLines.length <= 145) {
        bloatedLines.push(`          # padding line ${bloatedLines.length + 1}`);
      }
      writeFileSync(join(dir, '.github', 'workflows', 'bad.yml'), `${bloatedLines.join('\n')}\n`, 'utf8');

      const failRes = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(failRes.ok, false);
      assert.ok(failRes.guardViolations.every((v) => v.guard === 'noWorkflowBloat'));
      // 1 line-count violation + 1 inline pull_request.title + 2 evals + 4 multiline untrusted context interpolations = 8
      assert.equal(failRes.guardViolations.length, 8);
      assert.match(failRes.guardViolations[0].snippet, /exceed|has \d+ lines \(max 140\)/i);

      // Custom maxWorkflowLines threshold
      const customThreshold = scanGuardViolations(dir, { noWorkflowBloat: true, maxWorkflowLines: 10 });
      assert.ok(customThreshold.some((v) => v.file === '.github/workflows/thin.yml' && /max 10/.test(v.snippet)));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces requireWorkflowHardening guard: passes hardened workflows & catches missing concurrency/timeout/retention or legacy actions', () => {
    const dir = makeTempDir('holo-ci-workflow-hardening-');
    try {
      mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
      writeFileSync(join(dir, 'README.md'), '# Hardening Test\n', 'utf8');

      // 1. Passing hardened workflows (standard, caller-only, reusable with inline and block upload-artifact)
      writeFileSync(
        join(dir, '.github', 'workflows', 'ci.yml'),
        [
          'name: Hardened CI',
          'on: [push]',
          'concurrency:',
          '  group: ${{ github.workflow }}-${{ github.ref }}',
          '  cancel-in-progress: true',
          'jobs:',
          '  test:',
          '    runs-on: ubuntu-latest',
          '    timeout-minutes: 20',
          '    steps:',
          '      - uses: actions/checkout@v7',
          '      - uses: actions/setup-node@v7',
          '      - uses: mlugg/setup-zig@v2',
          '      - uses: actions/upload-artifact@v7',
          '        with:',
          '          name: receipt',
          '          path: receipt.json',
          '          retention-days: 7',
          '      - uses: actions/upload-pages-artifact@v5',
          '        with: { path: docs }',
          '',
        ].join('\n'),
        'utf8',
      );

      writeFileSync(
        join(dir, '.github', 'workflows', 'caller.yml'),
        [
          'name: Caller Workflow',
          'on:',
          '  push:',
          '    branches: [main]',
          'concurrency:',
          '  group: ${{ github.workflow }}-${{ github.ref }}',
          '  cancel-in-progress: true',
          'jobs:',
          '  verify:',
          '    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-holo-ci.yml@v1',
          '',
        ].join('\n'),
        'utf8',
      );

      writeFileSync(
        join(dir, '.github', 'workflows', 'reusable.yml'),
        [
          'name: Reusable Workflow',
          'on:',
          '  workflow_call:',
          'jobs:',
          '  build:',
          '    runs-on: ubuntu-latest',
          '    timeout-minutes: 30',
          '    steps:',
          '      - uses: actions/download-artifact@v8',
          '      - uses: actions/cache@v6',
          '      - uses: actions/upload-artifact@v7',
          "        with: { name: 'out', path: 'dist/*', retention-days: 7 }",
          '',
        ].join('\n'),
        'utf8',
      );

      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'hardening-test',
        kind: 'control-plane',
        docs: ['README.md'],
        guards: { noWorkflowBloat: true, requireWorkflowHardening: true },
      };

      const passRes = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(passRes.ok, true, JSON.stringify(passRes.guardViolations));
      assert.equal(passRes.guardViolations.length, 0);

      // 2. Failing workflow hitting all 4 hardening violations
      writeFileSync(
        join(dir, '.github', 'workflows', 'unhardened.yml'),
        [
          'name: Unhardened',
          'on: [push]',
          'jobs:',
          '  build:',
          '    runs-on: ubuntu-latest',
          '    steps:',
          '      - uses: actions/checkout@v4',
          '      - uses: actions/setup-node@v4',
          '      - uses: goto-bus-stop/setup-zig@v2',
          '      - uses: actions/cache/restore@v4',
          '      - uses: actions/download-artifact@v4',
          '      - uses: actions/upload-artifact@v4',
          '        with:',
          '          name: bad-artifact',
          '          path: out.bin',
          '      - uses: actions/upload-artifact@v7',
          '        with: { name: missing-retention, path: out2.bin }',
          '',
        ].join('\n'),
        'utf8',
      );

      const failRes = runVerify(manifest, { cwd: dir, skipTests: true, skipGates: true });
      assert.equal(failRes.ok, false);
      const hardeningViolations = failRes.guardViolations.filter(
        (v) => v.guard === 'requireWorkflowHardening' && v.file === '.github/workflows/unhardened.yml',
      );
      const snippets = hardeningViolations.map((v) => v.snippet).join('\n');
      assert.match(snippets, /missing top-level concurrency/);
      assert.match(snippets, /runs-on without timeout-minutes/);
      assert.match(snippets, /actions\/checkout@v4/);
      assert.match(snippets, /actions\/setup-node@v4/);
      assert.match(snippets, /goto-bus-stop\/setup-zig@v2/);
      assert.match(snippets, /actions\/cache\/restore@v4/);
      assert.match(snippets, /actions\/download-artifact@v4/);
      assert.match(snippets, /actions\/upload-artifact@v4/);
      assert.equal(
        hardeningViolations.filter((v) => v.snippet.includes('missing retention-days')).length,
        2,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci sync', () => {
  it('compares SHA-256 syncPairs recursively and detects matched vs drifted files', () => {
    const dir = makeTempDir();
    try {
      mkdirSync(join(dir, 'src', 'nested'), { recursive: true });
      mkdirSync(join(dir, 'dst', 'nested'), { recursive: true });
      writeFileSync(join(dir, 'src', 'a.txt'), 'hello', 'utf8');
      writeFileSync(join(dir, 'src', 'nested', 'b.txt'), 'world', 'utf8');
      writeFileSync(join(dir, 'dst', 'a.txt'), 'hello', 'utf8');
      writeFileSync(join(dir, 'dst', 'nested', 'b.txt'), 'world', 'utf8');

      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'sync-test',
        kind: 'monorepo',
        syncPairs: [{ label: 'mirror', source: 'src', target: 'dst' }],
      };

      const clean = runSync(manifest, { cwd: dir });
      assert.equal(clean.ok, true);
      assert.equal(clean.pairs[0].matched.length, 2);

      writeFileSync(join(dir, 'dst', 'nested', 'b.txt'), 'drifted', 'utf8');
      const dirty = runSync(manifest, { cwd: dir });
      assert.equal(dirty.ok, false);
      assert.deepEqual(dirty.pairs[0].drifted, ['nested/b.txt']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci bump', () => {
  it('verifies pinned >= upstream and bumps package.json cleanly', () => {
    const dir = makeTempDir();
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: 'demo', version: '1.0.0' }, null, 2) + '\n',
        'utf8',
      );
      const manifestOk: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'bump-test',
        kind: 'native-fork',
        upstreamPins: [
          { name: 'zig', pinned: '0.14.1', upstream: '0.14.0' },
          { name: 'node', pinned: '24.2.0', upstream: '24.2.0' },
        ],
      };

      const dry = runBump(manifestOk, { cwd: dir, version: 'v1.5.0', dryRun: true });
      assert.equal(dry.ok, true);
      assert.equal(dry.packageBump?.updated, false);
      assert.equal(JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version, '1.0.0');

      const applied = runBump(manifestOk, { cwd: dir, version: 'v1.5.0' });
      assert.equal(applied.ok, true);
      assert.equal(applied.packageBump?.updated, true);
      assert.equal(applied.packageBump?.newVersion, '1.5.0');
      assert.equal(JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version, '1.5.0');

      const behind = runBump(
        {
          ...manifestOk,
          upstreamPins: [{ name: 'zig', pinned: '0.13.0', upstream: '0.14.1' }],
        },
        { cwd: dir },
      );
      assert.equal(behind.ok, false);
      assert.equal(behind.pins[0].status, 'pinned-behind');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fetchLatestUpstreamVersion normalizes GitHub release/tag formats and falls back to /tags', async () => {
    const mockTagsFetch = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/releases/latest')) {
        return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
      }
      if (url.includes('/tags?per_page=20')) {
        return new Response(
          JSON.stringify([
            { name: 'curl-8_23_0' },
            { name: 'VER-2-15-0' },
            { name: 'openssl-4.1.0' },
            { name: 'v1.6.59' },
          ]),
          { status: 200 },
        );
      }
      return new Response('unexpected', { status: 500 });
    }) as typeof fetch;

    const releaseFetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      assert.equal(headers.Authorization, 'Bearer test-tok');
      return new Response(JSON.stringify({ tag_name: 'openssl-4.1.0', draft: false, prerelease: false }), {
        status: 200,
      });
    }) as typeof fetch;

    const rel = await fetchLatestUpstreamVersion('openssl/openssl', 'test-tok', releaseFetch);
    assert.deepEqual(rel, { tag: 'openssl-4.1.0', version: '4.1.0' });

    const singleTagCases: Array<[string, string]> = [
      ['v1.2.3', '1.2.3'],
      ['openssl-4.1.0', '4.1.0'],
      ['VER-2-15-0', '2.15.0'],
      ['curl-8_23_0', '8.23.0'],
    ];
    for (const [tag, expectedVersion] of singleTagCases) {
      const tagOnlyFetch = (async (input: string | URL | Request) => {
        if (String(input).endsWith('/releases/latest')) {
          return new Response('', { status: 404 });
        }
        return new Response(JSON.stringify([{ name: tag }]), { status: 200 });
      }) as typeof fetch;
      const got = await fetchLatestUpstreamVersion('awesome-os/demo', 'tok', tagOnlyFetch);
      assert.deepEqual(got, { tag, version: expectedVersion });
    }

    const multiTag = await fetchLatestUpstreamVersion('curl/curl', 'tok', mockTagsFetch);
    assert.equal(multiTag?.version, '8.23.0');
  });

  it('closes upstream-bump -> v11 CAS loop: runBumpAsync bumps lagged pin and runPack materializes SHA-512 blob', async () => {
    const dir = makeTempDir('holo-ci-bump-cas-');
    try {
      const configPath = join(dir, 'holo-ci.json');
      const initialManifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'libpng-cas-loop',
        kind: 'native-fork',
        upstreamPins: [
          {
            name: 'libpng',
            pinned: '1.6.58',
            upstream: '1.6.58',
            upstreamRepo: 'pnggroup/libpng',
          },
        ],
        casRelease: {
          outDir: 'dist',
          include: ['assets'],
        },
      };
      writeFileSync(configPath, `${JSON.stringify(initialManifest, null, 2)}\n`, 'utf8');

      mkdirSync(join(dir, 'assets'), { recursive: true });
      const payload = Buffer.from('holo-v11-libpng-1.6.59-artifact\n', 'utf8');
      const expectedSha512 = createHash('sha512').update(payload).digest('hex');
      writeFileSync(join(dir, 'assets', 'libpng.bin'), payload);

      const mockFetch = (async (input: string | URL | Request) => {
        if (String(input).endsWith('/releases/latest')) {
          return new Response(JSON.stringify({ tag_name: 'v1.6.59', draft: false, prerelease: false }), {
            status: 200,
          });
        }
        return new Response('', { status: 404 });
      }) as typeof fetch;

      // 1. Without applyPins: detects unbumped drift (ok === false)
      const driftRes = await runBumpAsync(initialManifest, {
        cwd: dir,
        fetchUpstream: true,
        applyPins: false,
        fetchFn: mockFetch,
      });
      assert.equal(driftRes.ok, false);
      assert.equal(driftRes.bumpedCount, 1);
      assert.deepEqual(driftRes.bumpedPins, ['libpng']);
      assert.equal(driftRes.applied, false);
      assert.equal(driftRes.pins[0].status, 'pinned-behind');
      assert.equal(driftRes.pins[0].pinned, '1.6.58');
      assert.equal(driftRes.pins[0].upstream, '1.6.59');

      // 2. With applyPins: updates holo-ci.json and refreshes pin status to pinned-match
      const appliedRes = await runBumpAsync(initialManifest, {
        cwd: dir,
        fetchUpstream: true,
        applyPins: true,
        configPath: 'holo-ci.json',
        fetchFn: mockFetch,
      });
      assert.equal(appliedRes.ok, true);
      assert.equal(appliedRes.bumpedCount, 1);
      assert.deepEqual(appliedRes.bumpedPins, ['libpng']);
      assert.equal(appliedRes.applied, true);
      assert.equal(appliedRes.pins[0].status, 'pinned-match');
      assert.equal(appliedRes.pins[0].pinned, '1.6.59');
      assert.equal(appliedRes.pins[0].upstream, '1.6.59');

      const persisted = JSON.parse(readFileSync(configPath, 'utf8')) as HoloCiManifest;
      assert.equal(persisted.upstreamPins?.[0].pinned, '1.6.59');
      assert.equal(persisted.upstreamPins?.[0].upstream, '1.6.59');

      // 3. Materialize v11 CAS blob and verify bit-for-bit SHA-512
      const casDir = join(dir, 'cas-store');
      const packRes = runPack(persisted, { cwd: dir, casDir });
      assert.equal(packRes.ok, true);
      assert.equal(packRes.casRoot, casDir);
      assert.equal(packRes.casWrittenFiles, 1);

      const blobPath = join(casDir, 'v11', 'files', expectedSha512.slice(0, 2), expectedSha512);
      assert.equal(existsSync(blobPath), true);
      const blobBuf = readFileSync(blobPath);
      assert.deepEqual(blobBuf, payload);
      assert.equal(createHash('sha512').update(blobBuf).digest('hex'), expectedSha512);

      // Re-packing into the same casDir should deduplicate (0 new files written)
      const secondPack = runPack(persisted, { cwd: dir, casDir });
      assert.equal(secondPack.casWrittenFiles, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci pack', () => {
  it('writes deterministic holo-v11-manifest.json and SHA512SUMS.txt with byte-level dedup', () => {
    const dir = makeTempDir();
    try {
      mkdirSync(join(dir, 'assets', 'nested'), { recursive: true });
      const repeated = Buffer.from('A'.repeat(256), 'utf8');
      const unique = Buffer.from('B'.repeat(128), 'utf8');
      writeFileSync(join(dir, 'assets', 'blob1.bin'), repeated);
      writeFileSync(join(dir, 'assets', 'nested', 'blob2.bin'), repeated);
      writeFileSync(join(dir, 'assets', 'other.txt'), unique);

      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'pack-test',
        kind: 'app',
        casRelease: {
          outDir: 'dist',
          include: ['assets'],
        },
      };

      const res = runPack(manifest, { cwd: dir });
      assert.equal(res.ok, true);
      assert.equal(res.dedup.totalAssets, 3);
      assert.equal(res.dedup.uniqueSha512Blobs, 2);
      assert.equal(res.dedup.dedupedBlobs, 1);
      assert.equal(res.dedup.rawBytes, 640);
      assert.equal(res.dedup.uniqueBytes, 384);
      assert.equal(res.dedup.savedBytes, 256);

      const writtenManifest = JSON.parse(readFileSync(res.manifestPath, 'utf8')) as {
        schema: string;
        abiMagic: string;
        entries: Array<{ path: string }>;
      };
      assert.equal(writtenManifest.schema, HOLO_V11_MANIFEST_SCHEMA);
      assert.equal(writtenManifest.abiMagic, B8G_ABI_MAGIC_V3);
      assert.deepEqual(
        writtenManifest.entries.map((e) => e.path),
        ['assets/blob1.bin', 'assets/nested/blob2.bin', 'assets/other.txt'],
      );
      assert.equal(existsSync(res.sumsPath), true);

      const verified = verifyBundleManifest(dir, 'dist/SHA512SUMS.txt');
      assert.equal(verified.checked, 3);
      assert.deepEqual(verified.mismatches, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci telemetry', () => {
  it('emits holo-ci.receipt.v1 JSON/NDJSON and appends Markdown summary', () => {
    const dir = makeTempDir();
    try {
      const manifest: HoloCiManifest = {
        schema: HOLO_CI_SCHEMA,
        name: 'telemetry-test',
        kind: 'control-plane',
      };
      const receipt = buildReceipt({
        manifest,
        phase: 'verify',
        ok: true,
        durationMs: 42,
        verify: {
          ok: true,
          tests: [{ command: 'node --test', kind: 'test', exitCode: 0, durationMs: 20, ok: true, stdout: '', stderr: '' }],
          nativeGates: [],
          docs: [{ path: 'README.md', exists: true }],
          guardViolations: [],
        },
      });
      assert.equal(receipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(receipt.abiMagic, B8G_ABI_MAGIC_V3);

      const ndjsonPath = join(dir, 'receipts.ndjson');
      const summaryPath = join(dir, 'step-summary.md');
      const out = emitTelemetry(receipt, {
        cwd: dir,
        receiptPath: ndjsonPath,
        emitSummary: true,
        summaryPath,
      });
      assert.equal(out.summaryAppended, true);
      const line = JSON.parse(readFileSync(ndjsonPath, 'utf8').trim()) as { schema: string; abiMagic: string };
      assert.equal(line.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(line.abiMagic, B8G_ABI_MAGIC_V3);

      const md = readFileSync(summaryPath, 'utf8');
      assert.match(md, /Holo-CI Receipt/);
      assert.match(md, /0x33564742/);
      assert.match(md, /1\/1 passed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci maintain', () => {
  it('verifies clean-box HTTP 200, SHA-512, and Ed25519 signature via node:crypto', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const payload = Buffer.from('awesome-os-v11-clean-box-payload', 'utf8');
    const sha512 = createHash('sha512').update(payload).digest('hex');
    const sigB64 = sign(null, payload, privateKey).toString('base64');

    const mockFetch = async () =>
      new Response(payload, {
        status: 200,
        headers: { 'x-holo-signature-ed25519': sigB64 },
      });

    const manifest: HoloCiManifest = {
      schema: HOLO_CI_SCHEMA,
      name: 'maintain-test',
      kind: 'control-plane',
      endpoints: [
        {
          name: 'cas-bundle',
          url: 'https://awesome-os.example/cas-bundle.bin',
          expectedStatus: 200,
          sha512,
          publicKeyPem: pubPem,
        },
      ],
    };

    const okRes = await runMaintain(manifest, { fetchFn: mockFetch });
    assert.equal(okRes.ok, true);
    assert.equal(okRes.endpoints[0].status, 200);
    assert.equal(okRes.endpoints[0].sha512Verified, true);
    assert.equal(okRes.endpoints[0].ed25519Verified, true);

    const failFetch = async () => new Response('tampered', { status: 500 });
    const badRes = await runMaintain(manifest, { fetchFn: failFetch });
    assert.equal(badRes.ok, false);
    assert.equal(badRes.endpoints[0].ok, false);
  });
});

describe('holo-ci lock-compat', () => {
  it('synthesizes deterministic byte-sorted lockfileVersion 3 without modifying node_modules', () => {
    const dirA = makeTempDir('holo-ci-lock-a-');
    const dirB = makeTempDir('holo-ci-lock-b-');
    try {
      const setupRepo = (dir: string, reverseKeys: boolean): void => {
        mkdirSync(join(dir, 'workspaces', 'pkg-alpha'), { recursive: true });
        mkdirSync(join(dir, 'node_modules', '.sentinel'), { recursive: true });
        writeFileSync(join(dir, 'node_modules', '.sentinel', 'keep.txt'), 'untouched', 'utf8');

        const deps = reverseKeys
          ? { zod: '^3.25.0', '@types/node': '^24.0.0' }
          : { '@types/node': '^24.0.0', zod: '^3.25.0' };
        const devDeps = reverseKeys
          ? { typescript: '^6.0.2', esbuild: '^0.28.0' }
          : { esbuild: '^0.28.0', typescript: '^6.0.2' };

        writeFileSync(
          join(dir, 'package.json'),
          JSON.stringify(
            {
              name: 'hybrid-workspace',
              version: '1.2.3',
              workspaces: ['workspaces/*'],
              dependencies: deps,
              devDependencies: devDeps,
            },
            null,
            2,
          ),
          'utf8',
        );

        writeFileSync(
          join(dir, 'workspaces', 'pkg-alpha', 'package.json'),
          JSON.stringify(
            {
              name: '@hybrid/pkg-alpha',
              version: '0.4.0',
              dependencies: { hono: '^4.13.16' },
            },
            null,
            2,
          ),
          'utf8',
        );

        writeFileSync(
          join(dir, 'pnpm-lock.yaml'),
          [
            "lockfileVersion: '9.0'",
            'importers:',
            '  .:',
            '    dependencies:',
            "      '@types/node':",
            '        specifier: ^24.0.0',
            '        version: 24.5.1',
            '      zod:',
            '        specifier: ^3.25.0',
            '        version: 3.25.76',
            '    devDependencies:',
            '      esbuild:',
            '        specifier: ^0.28.0',
            '        version: 0.28.2',
            '      typescript:',
            '        specifier: ^6.0.2',
            '        version: 6.0.2',
            '  workspaces/pkg-alpha:',
            '    dependencies:',
            '      hono:',
            '        specifier: ^4.13.16',
            '        version: 4.13.16',
            'packages:',
            "  '@types/node@24.5.1':",
            '    resolution: {integrity: sha512-nodeTypesHash==}',
            '  hono@4.13.16:',
            '    resolution: {integrity: sha512-honoHash==}',
            '',
          ].join('\n'),
          'utf8',
        );

        writeFileSync(
          join(dir, 'max-version-lock.json'),
          JSON.stringify({
            schema: 'awesome-os.max-version-lock.v1',
            libraries: [{ name: 'esbuild', maxVersion: '0.28.9' }],
          }),
          'utf8',
        );
      };

      setupRepo(dirA, false);
      setupRepo(dirB, true);

      const resA = runLockCompat({ cwd: dirA });
      const resB = runLockCompat({ cwd: dirB });

      assert.equal(resA.ok, true);
      assert.equal(resA.written, true);
      assert.equal(resA.lockfileVersion, 3);
      assert.equal(resA.holoCasStore, 'v11');
      assert.equal(resA.zeroCopyNodeModules, true);
      assert.equal(resA.workspaceCount, 1);
      assert.equal(resA.resolvedFromMaxLock, 1);
      assert.equal(resA.resolvedFromPnpmLock, 4);
      assert.equal(resA.sha256, resB.sha256);

      const rawA = readFileSync(join(dirA, 'package-lock.json'), 'utf8');
      const rawB = readFileSync(join(dirB, 'package-lock.json'), 'utf8');
      assert.equal(rawA, rawB);

      const parsed = JSON.parse(rawA) as {
        lockfileVersion: number;
        holoCasStore: string;
        zeroCopyNodeModules: boolean;
        packages: Record<string, { version?: string; integrity?: string; resolved?: string; link?: boolean }>;
      };
      assert.equal(parsed.lockfileVersion, 3);
      assert.equal(parsed.holoCasStore, 'v11');
      assert.equal(parsed.zeroCopyNodeModules, true);
      assert.equal(parsed.packages['node_modules/@types/node'].version, '24.5.1');
      assert.equal(parsed.packages['node_modules/@types/node'].integrity, 'sha512-nodeTypesHash==');
      assert.equal(parsed.packages['node_modules/esbuild'].version, '0.28.9');
      assert.equal(parsed.packages['node_modules/hono'].version, '4.13.16');
      assert.equal(parsed.packages['node_modules/@hybrid/pkg-alpha'].resolved, 'workspaces/pkg-alpha');
      assert.equal(parsed.packages['node_modules/@hybrid/pkg-alpha'].link, true);

      // Verify byte-sorted keys in `packages`
      const keys = Object.keys(parsed.packages);
      const sorted = [...keys].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      assert.deepEqual(keys, sorted);

      // Verify zero node_modules mutation
      assert.equal(readFileSync(join(dirA, 'node_modules', '.sentinel', 'keep.txt'), 'utf8'), 'untouched');
      assert.equal(existsSync(join(dirA, 'node_modules', '.package-lock.json')), false);
    } finally {
      rmSync(dirA, { recursive: true, force: true });
      rmSync(dirB, { recursive: true, force: true });
    }
  });

  it('projects all 9 ecosystems via --ecosystem all into outDir without mutating host stores', () => {
    const dir = makeTempDir('holo-ci-lock-9eco-');
    try {
      mkdirSync(join(dir, 'node_modules', '.sentinel'), { recursive: true });
      writeFileSync(join(dir, 'node_modules', '.sentinel', 'keep.txt'), 'untouched', 'utf8');
      mkdirSync(join(dir, 'vendor', '.sentinel'), { recursive: true });
      writeFileSync(join(dir, 'vendor', '.sentinel', 'keep.txt'), 'untouched-vendor', 'utf8');
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: 'polyglot-demo', version: '3.1.0', dependencies: { zod: '^3.25.0' } }),
        'utf8',
      );
      writeFileSync(
        join(dir, 'Cargo.toml'),
        ['[package]', 'name = "polyglot-demo"', 'version = "0.1.0"', '[dependencies]', 'serde = "1.0.219"'].join('\n'),
        'utf8',
      );
      writeFileSync(join(dir, 'requirements.txt'), 'numpy==2.2.4\nfastapi>=0.115.0\n', 'utf8');
      mkdirSync(join(dir, 'services', 'api'), { recursive: true });
      writeFileSync(join(dir, 'go.mod'), 'module example.com/polyglot\n\ngo 1.24\n', 'utf8');
      writeFileSync(
        join(dir, 'max-version-lock.json'),
        JSON.stringify({
          schema: 'awesome-os.max-version-lock.v1',
          libraries: [
            { name: 'openssl', maxVersion: '4.1.0' },
            { name: 'zstd', maxVersion: '1.5.7' },
            { name: 'curl', maxVersion: '8.23.0' },
          ],
        }),
        'utf8',
      );

      const res = runLockCompat({ cwd: dir, ecosystem: 'all', outDir: 'dist/locks' });
      assert.equal(res.ok, true);
      assert.equal(res.ecosystem, 'all');
      assert.deepEqual(res.ecosystemsGenerated, [
        'npm',
        'cargo',
        'uv',
        'go',
        'vcpkg',
        'winget',
        'apt',
        'composer',
        'rubygems',
      ]);
      assert.equal(res.written, true);

      const outBase = join(dir, 'dist', 'locks');

      // 1. npm
      const npmLock = JSON.parse(readFileSync(join(outBase, 'package-lock.json'), 'utf8')) as {
        lockfileVersion: number;
      };
      assert.equal(npmLock.lockfileVersion, 3);

      // 2. cargo
      const cargoCfg = readFileSync(join(outBase, '.cargo', 'config.toml'), 'utf8');
      assert.match(cargoCfg, /\[source\.crates-io\]/);
      assert.match(cargoCfg, /replace-with = "holo-v11"/);
      const cargoCompat = JSON.parse(readFileSync(join(outBase, 'holo-cargo-compat.json'), 'utf8')) as {
        crates: Array<{ name: string; version: string }>;
      };
      assert.equal(cargoCompat.crates[0].name, 'serde');
      assert.equal(cargoCompat.crates[0].version, '1.0.219');

      // 3. uv
      const uvToml = readFileSync(join(outBase, 'uv.toml'), 'utf8');
      assert.match(uvToml, /link-mode = "hardlink"/);
      assert.match(uvToml, /cache-dir =/);
      const reqTxt = readFileSync(join(outBase, 'requirements.holo-v11.txt'), 'utf8');
      assert.match(reqTxt, /fastapi==0\.115\.0/);
      assert.match(reqTxt, /numpy==2\.2\.4/);

      // 4. go
      const goWork = readFileSync(join(outBase, 'go.work'), 'utf8');
      assert.match(goWork, /^go 1\.24$/m);
      assert.match(goWork, /GOPROXY=file:\/\/\/var\/lib\/b8g\/cas\/v11\/go-proxy,direct/);
      assert.match(goWork, /\t\./);

      // 5. vcpkg + pkg-config stubs including shared PHP/Ruby C libs
      const vcpkgCfg = JSON.parse(readFileSync(join(outBase, 'vcpkg-configuration.json'), 'utf8')) as {
        holoCasStore: string;
        pinnedLibraries: Record<string, { version: string; pkgConfig: string }>;
      };
      assert.equal(vcpkgCfg.holoCasStore, 'v11');
      for (const lib of [
        'openssl',
        'pixman',
        'cairo',
        'harfbuzz',
        'zstd',
        'libxml2',
        'oniguruma',
        'libxslt',
        'libgd',
        'libzip',
        'libgit2',
        'librdkafka',
        'libvips',
        'icu4c',
        'libsodium',
        'sqlite',
        'curl',
      ]) {
        assert.ok(vcpkgCfg.pinnedLibraries[lib], `missing vcpkg lib ${lib}`);
        const pcFile = join(outBase, vcpkgCfg.pinnedLibraries[lib].pkgConfig);
        assert.equal(existsSync(pcFile), true, `missing .pc stub for ${lib}`);
        assert.match(readFileSync(pcFile, 'utf8'), /X-Holo-CAS-Store: v11/);
      }
      assert.equal(vcpkgCfg.pinnedLibraries.openssl.version, '4.1.0');

      // 6. winget (zero-UAC HKCU portable ARP, 0 MSI installers)
      const wingetImport = JSON.parse(readFileSync(join(outBase, 'winget-import.holo-v11.json'), 'utf8')) as {
        msiInstallerCount: number;
        uacElevationRequired: boolean;
      };
      assert.equal(wingetImport.msiInstallerCount, 0);
      assert.equal(wingetImport.uacElevationRequired, false);
      const hkcuArp = JSON.parse(readFileSync(join(outBase, 'winget-hkcu-arp.holo-v11.json'), 'utf8')) as {
        hive: string;
        uacElevationRequired: boolean;
        msiInstallerCount: number;
        entries: Array<{ InstallerType: string; registryKey: string }>;
      };
      assert.equal(hkcuArp.hive, 'HKEY_CURRENT_USER');
      assert.equal(hkcuArp.uacElevationRequired, false);
      assert.equal(hkcuArp.msiInstallerCount, 0);
      assert.ok(hkcuArp.entries.every((e) => e.InstallerType === 'portable' && e.registryKey.startsWith('HKCU\\')));

      // 7. apt (Status: install ok installed virtual-provides gated by mandatory ELF soname)
      const dpkgStatus = readFileSync(join(outBase, 'dpkg-status.holo-v11'), 'utf8');
      assert.match(dpkgStatus, /Status: install ok installed/);
      assert.match(dpkgStatus, /Provides: .*holo-v11-openssl/);
      assert.match(dpkgStatus, /X-Holo-ELF-SONAME: libssl\.so\.3/);

      // 8. composer (clean fallback when composer.json / .wp-env.json are absent)
      const composerCompat = JSON.parse(readFileSync(join(outBase, 'composer.holo-v11.json'), 'utf8')) as {
        schema: string;
        abiMagic: string;
        config: { 'cache-dir': string; 'preferred-install': string; 'sort-packages': boolean };
      };
      assert.equal(composerCompat.schema, 'holo-v11.composer-compat.v1');
      assert.equal(composerCompat.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(composerCompat.config['cache-dir'], '/var/lib/b8g/cas/v11/composer');
      assert.equal(existsSync(join(outBase, 'php.holo-v11.ini')), true);
      assert.equal(existsSync(join(outBase, 'wp-env.holo-v11.json')), true);

      // 9. rubygems
      assert.equal(existsSync(join(outBase, '.bundle', 'config.holo-v11')), true);
      const rubygemsCompat = JSON.parse(readFileSync(join(outBase, 'holo-rubygems-compat.json'), 'utf8')) as {
        schema: string;
        abiMagic: string;
        rubyWasm: { runtime: string; wasiHost: string };
      };
      assert.equal(rubygemsCompat.schema, 'holo-v11.rubygems-compat.v1');
      assert.equal(rubygemsCompat.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(rubygemsCompat.rubyWasm.runtime, 'ruby.wasm');

      // Zero mutation of host node_modules, vendor, or root package-lock.json
      assert.equal(readFileSync(join(dir, 'node_modules', '.sentinel', 'keep.txt'), 'utf8'), 'untouched');
      assert.equal(readFileSync(join(dir, 'vendor', '.sentinel', 'keep.txt'), 'utf8'), 'untouched-vendor');
      assert.equal(existsSync(join(dir, 'package-lock.json')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('projects composer (PHP native + PHP-WASI @wp/env) without mutating vendor/', () => {
    const dir = makeTempDir('holo-ci-composer-');
    try {
      mkdirSync(join(dir, 'vendor', '.sentinel'), { recursive: true });
      writeFileSync(join(dir, 'vendor', '.sentinel', 'keep.txt'), 'untouched-vendor', 'utf8');
      writeFileSync(
        join(dir, 'composer.json'),
        JSON.stringify(
          {
            name: 'awesome-os/wp-studio',
            version: '2.4.0',
            require: { php: '^8.4', 'monolog/monolog': '^3.8' },
            'require-dev': { 'phpunit/phpunit': '^11.5' },
          },
          null,
          2,
        ),
        'utf8',
      );
      writeFileSync(
        join(dir, 'composer.lock'),
        JSON.stringify({
          packages: [{ name: 'monolog/monolog', version: '3.8.1', dist: { shasum: 'abc123' } }],
          'packages-dev': [{ name: 'phpunit/phpunit', version: '11.5.3' }],
        }),
        'utf8',
      );
      writeFileSync(
        join(dir, '.wp-env.json'),
        JSON.stringify({
          core: 'WordPress/WordPress#6.7',
          phpVersion: '8.4',
          plugins: ['.'],
        }),
        'utf8',
      );

      const res = runLockCompat({ cwd: dir, ecosystem: 'composer', outDir: 'dist/php' });
      assert.equal(res.ok, true);
      assert.deepEqual(res.ecosystemsGenerated, ['composer']);
      assert.equal(res.artifacts.length, 3);

      const outBase = join(dir, 'dist', 'php');
      const composerCfg = JSON.parse(readFileSync(join(outBase, 'composer.holo-v11.json'), 'utf8')) as {
        schema: string;
        abiMagic: string;
        zeroVendorMutation: boolean;
        name: string;
        version: string;
        config: { 'cache-dir': string; 'preferred-install': string; 'sort-packages': boolean };
        repositories: Array<{ type: string; url: string; options: { symlink: boolean } }>;
        packages: Array<{ name: string; version: string; dev: boolean; distShasum?: string }>;
      };
      assert.equal(composerCfg.schema, 'holo-v11.composer-compat.v1');
      assert.equal(composerCfg.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(composerCfg.zeroVendorMutation, true);
      assert.equal(composerCfg.name, 'awesome-os/wp-studio');
      assert.equal(composerCfg.config['cache-dir'], '/var/lib/b8g/cas/v11/composer');
      assert.equal(composerCfg.config['preferred-install'], 'dist');
      assert.equal(composerCfg.config['sort-packages'], true);
      assert.equal(composerCfg.repositories[0].options.symlink, true);
      assert.equal(composerCfg.packages.length, 2);
      assert.equal(composerCfg.packages[0].name, 'monolog/monolog');
      assert.equal(composerCfg.packages[0].version, '3.8.1');
      assert.equal(composerCfg.packages[0].distShasum, 'abc123');

      const phpIni = readFileSync(join(outBase, 'php.holo-v11.ini'), 'utf8');
      assert.match(phpIni, /extension_dir = "\/var\/lib\/b8g\/cas\/v11\/php\/ext"/);
      assert.match(phpIni, /v11-pin\.oniguruma = "6\.9\.10" ; libonig\.so\.5/);
      assert.match(phpIni, /v11-pin\.libsodium = "1\.0\.22" ; libsodium\.so\.23/);

      const wpEnv = JSON.parse(readFileSync(join(outBase, 'wp-env.holo-v11.json'), 'utf8')) as {
        runtime: string;
        dbEngine: string;
        casRoot: string;
        wasiHost: string;
        core: string;
        plugins: string[];
      };
      assert.equal(wpEnv.runtime, 'php-wasi');
      assert.equal(wpEnv.dbEngine, 'sqlite-wasi');
      assert.equal(wpEnv.casRoot, '/var/lib/b8g/cas/v11');
      assert.equal(wpEnv.wasiHost, 'holo-wasi-host-b8g.wasm');
      assert.equal(wpEnv.core, 'WordPress/WordPress#6.7');
      assert.deepEqual(wpEnv.plugins, ['.']);

      assert.equal(readFileSync(join(dir, 'vendor', '.sentinel', 'keep.txt'), 'utf8'), 'untouched-vendor');
      assert.equal(existsSync(join(dir, 'composer.holo-v11.json')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('projects rubygems (Ruby native + ruby.wasm WASI) without mutating host stores', () => {
    const dir = makeTempDir('holo-ci-rubygems-');
    try {
      writeFileSync(
        join(dir, 'Gemfile'),
        ["source 'https://rubygems.org'", "ruby '3.4.2'", "gem 'nokogiri', '~> 1.18'", "gem 'ffi', '~> 1.17'"].join(
          '\n',
        ),
        'utf8',
      );
      writeFileSync(
        join(dir, 'Gemfile.lock'),
        [
          'GEM',
          '  remote: https://rubygems.org/',
          '  specs:',
          '    ffi (1.17.1-x86_64-linux)',
          '    nokogiri (1.18.4)',
          '    sqlite3 (2.6.0)',
          '',
          'RUBY VERSION',
          '   ruby 3.4.2p28',
          '',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(
        join(dir, 'awesome-ruby.gemspec'),
        [
          'Gem::Specification.new do |spec|',
          '  spec.name = "awesome-ruby"',
          '  spec.version = "0.9.0"',
          '  spec.add_runtime_dependency "rdkafka", "~> 0.21"',
          'end',
        ].join('\n'),
        'utf8',
      );

      const res = runLockCompat({ cwd: dir, ecosystem: 'rubygems', outDir: 'dist/ruby' });
      assert.equal(res.ok, true);
      assert.deepEqual(res.ecosystemsGenerated, ['rubygems']);
      assert.equal(res.artifacts.length, 2);

      const outBase = join(dir, 'dist', 'ruby');
      const bundleCfg = readFileSync(join(outBase, '.bundle', 'config.holo-v11'), 'utf8');
      assert.match(bundleCfg, /BUNDLE_CACHE_PATH: "\/var\/lib\/b8g\/cas\/v11\/gems"/);
      assert.match(bundleCfg, /BUNDLE_LOCAL: "true"/);
      assert.match(bundleCfg, /BUNDLE_DEPLOYMENT: "true"/);
      assert.match(bundleCfg, /BUNDLE_BUILD__NOKOGIRI: "--use-system-libraries"/);
      assert.match(bundleCfg, /BUNDLE_BUILD__PSYCH: "--with-libyaml-dir=\/var\/lib\/b8g\/cas\/v11"/);
      assert.match(bundleCfg, /BUNDLE_BUILD__FFI: "--enable-system-libffi"/);
      assert.match(bundleCfg, /BUNDLE_BUILD__SQLITE3: "--enable-system-libraries"/);
      assert.match(bundleCfg, /BUNDLE_BUILD__OPENSSL: "--with-openssl-dir=\/var\/lib\/b8g\/cas\/v11"/);

      const compat = JSON.parse(readFileSync(join(outBase, 'holo-rubygems-compat.json'), 'utf8')) as {
        schema: string;
        abiMagic: string;
        name: string;
        version: string;
        zeroHostGemMutation: boolean;
        rubyWasm: { runtime: string; target: string; wasiHost: string; rubyVersion: string };
        nativeExtensionSonames: Record<string, { soname: string }>;
        gems: Array<{ name: string; version: string; soname?: string }>;
      };
      assert.equal(compat.schema, 'holo-v11.rubygems-compat.v1');
      assert.equal(compat.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(compat.name, 'awesome-ruby');
      assert.equal(compat.version, '0.9.0');
      assert.equal(compat.zeroHostGemMutation, true);
      assert.equal(compat.rubyWasm.runtime, 'ruby.wasm');
      assert.equal(compat.rubyWasm.target, 'wasm32-wasi');
      assert.equal(compat.rubyWasm.wasiHost, 'holo-wasi-host-b8g.wasm');
      assert.equal(compat.rubyWasm.rubyVersion, '3.4.2');
      assert.equal(compat.nativeExtensionSonames.nokogiri.soname, 'libxml2.so.2');
      assert.equal(compat.nativeExtensionSonames.sqlite3.soname, 'libsqlite3.so.0');
      assert.equal(compat.nativeExtensionSonames.rdkafka.soname, 'librdkafka.so.1');
      const nokogiriGem = compat.gems.find((g) => g.name === 'nokogiri');
      assert.equal(nokogiriGem?.version, '1.18.4');
      assert.equal(nokogiriGem?.soname, 'libxml2.so.2');

      assert.equal(existsSync(join(dir, '.bundle')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects apt lock-compat stanzas missing a valid mandatory ELF soname', () => {
    const dir = makeTempDir('holo-ci-apt-soname-');
    try {
      assert.throws(
        () =>
          runLockCompat({
            cwd: dir,
            ecosystem: 'apt',
            dryRun: true,
            aptStanzas: [{ package: 'libbroken', version: '1.0.0', soname: '' }],
          }),
        /mandatory ELF soname/i,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('uses synced 68/68 max-version defaults and auto-discovers sibling t2linux-baseline max-version-lock.json', () => {
    const root = makeTempDir('holo-ci-sibling-lock-');
    try {
      const repoA = join(root, 'repo-a');
      const nestedRepo = join(root, 'group', 'repo-b');
      const isolated = join(root, 'isolated');
      mkdirSync(repoA, { recursive: true });
      mkdirSync(nestedRepo, { recursive: true });
      mkdirSync(isolated, { recursive: true });

      // Without max-version-lock.json, fallback defaults must match all 20 synced 68/68 max versions
      const fallbackRes = runLockCompat({ cwd: isolated, ecosystem: 'vcpkg', outDir: 'out' });
      assert.equal(fallbackRes.ok, true);
      const vcpkgFallback = JSON.parse(readFileSync(join(isolated, 'out', 'vcpkg-configuration.json'), 'utf8')) as {
        pinnedLibraries: Record<string, { version: string }>;
      };
      const expectedDefaults: Record<string, string> = {
        cairo: '1.18.6',
        harfbuzz: '15.2.0',
        libxml2: '2.15.4',
        libxslt: '1.1.45',
        zstd: '1.6.0',
        zlib: '1.4',
        sqlite: '3.54.1',
        curl: '8.23.0',
        icu4c: '79.1',
        oniguruma: '6.9.10',
        libgit2: '1.9.7',
        librdkafka: '2.16.0',
        libvips: '8.18.7',
        freetype: '2.15.0',
        libpng: '1.6.59',
        pixman: '0.46.4',
        openssl: '4.1.0',
        libsodium: '1.0.22',
        libgd: '2.3.3',
        libzip: '1.12.1',
      };
      assert.equal(Object.keys(vcpkgFallback.pinnedLibraries).length, 20);
      for (const [lib, ver] of Object.entries(expectedDefaults)) {
        assert.equal(vcpkgFallback.pinnedLibraries[lib]?.version, ver, `mismatch for ${lib}`);
      }

      // Sibling ../t2linux-baseline/catalog/max-version-lock.json & ../../t2linux-baseline/catalog/max-version-lock.json
      const t2Catalog = join(root, 't2linux-baseline', 'catalog');
      mkdirSync(t2Catalog, { recursive: true });
      writeFileSync(
        join(t2Catalog, 'max-version-lock.json'),
        JSON.stringify({
          schema: 'awesome-os.max-version-lock.v1',
          libraries: [
            { name: 'openssl', v11Name: 'openssl', maxVersion: '4.1.9' },
            { name: 'zstd', v11Name: 'zstd', maxVersion: '1.6.9' },
          ],
        }),
        'utf8',
      );

      runLockCompat({ cwd: repoA, ecosystem: 'vcpkg', outDir: 'out-1' });
      const vcpkgOneUp = JSON.parse(readFileSync(join(repoA, 'out-1', 'vcpkg-configuration.json'), 'utf8')) as {
        pinnedLibraries: Record<string, { version: string }>;
      };
      assert.equal(vcpkgOneUp.pinnedLibraries.openssl.version, '4.1.9');
      assert.equal(vcpkgOneUp.pinnedLibraries.zstd.version, '1.6.9');

      runLockCompat({ cwd: nestedRepo, ecosystem: 'vcpkg', outDir: 'out-2' });
      const vcpkgTwoUp = JSON.parse(readFileSync(join(nestedRepo, 'out-2', 'vcpkg-configuration.json'), 'utf8')) as {
        pinnedLibraries: Record<string, { version: string }>;
      };
      assert.equal(vcpkgTwoUp.pinnedLibraries.openssl.version, '4.1.9');
      assert.equal(vcpkgTwoUp.pinnedLibraries.zstd.version, '1.6.9');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('holo-ci CLI', () => {
  it('prints help for --help and executes init + verify --json', () => {
    const cliPath = join(HERE, 'cli.mts');
    const helpRes = spawnSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });
    assert.equal(helpRes.status, 0);
    assert.match(helpRes.stdout, /verify/);
    assert.match(helpRes.stdout, /maintain/);
    assert.match(helpRes.stdout, /init/);
    assert.match(helpRes.stdout, /lock-compat/);
    assert.match(helpRes.stdout, /--ecosystem/);
    assert.match(helpRes.stdout, /--out-dir/);

    const dir = makeTempDir();
    try {
      writeFileSync(join(dir, 'README.md'), '# CLI Test\n', 'utf8');
      const initRes = spawnSync(
        process.execPath,
        [cliPath, 'init', '--cwd', dir, '--name', 'cli-demo', '--kind', 'app'],
        { encoding: 'utf8' },
      );
      assert.equal(initRes.status, 0, initRes.stderr);

      const verifyRes = spawnSync(
        process.execPath,
        [cliPath, 'verify', '--cwd', dir, '--config', 'holo-ci.json', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(verifyRes.status, 0, verifyRes.stderr);
      const parsed = JSON.parse(verifyRes.stdout) as {
        schema: string;
        abiMagic: string;
        phase: string;
        ok: boolean;
      };
      assert.equal(parsed.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(parsed.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(parsed.phase, 'verify');
      assert.equal(parsed.ok, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('executes lock-compat --dry-run --json without writing package-lock.json or touching node_modules', () => {
    const cliPath = join(HERE, 'cli.mts');
    const dir = makeTempDir('holo-ci-cli-lock-');
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({
          name: 'cli-lock-demo',
          version: '2.0.0',
          dependencies: { hono: '^4.13.16' },
        }),
        'utf8',
      );
      const res = spawnSync(
        process.execPath,
        [cliPath, 'lock-compat', '--cwd', dir, '--dry-run', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(res.status, 0, res.stderr);
      const receipt = JSON.parse(res.stdout) as {
        schema: string;
        abiMagic: string;
        phase: string;
        ok: boolean;
        lockCompat?: {
          lockfileVersion: number;
          holoCasStore: string;
          zeroCopyNodeModules: boolean;
          dryRun: boolean;
          written: boolean;
        };
      };
      assert.equal(receipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(receipt.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(receipt.phase, 'lock-compat');
      assert.equal(receipt.ok, true);
      assert.equal(receipt.lockCompat?.lockfileVersion, 3);
      assert.equal(receipt.lockCompat?.holoCasStore, 'v11');
      assert.equal(receipt.lockCompat?.zeroCopyNodeModules, true);
      assert.equal(receipt.lockCompat?.dryRun, true);
      assert.equal(receipt.lockCompat?.written, false);
      assert.equal(existsSync(join(dir, 'package-lock.json')), false);
      assert.equal(existsSync(join(dir, 'node_modules')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('executes lock-compat --ecosystem all --out-dir dist/eco --json via CLI and normalizes php/ruby/bundler aliases', () => {
    const cliPath = join(HERE, 'cli.mts');
    const dir = makeTempDir('holo-ci-cli-9eco-');
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: 'cli-9eco-demo', version: '1.0.0', dependencies: { zod: '^3.25.0' } }),
        'utf8',
      );
      const res = spawnSync(
        process.execPath,
        [cliPath, 'lock-compat', '--ecosystem', 'all', '--cwd', dir, '--out-dir', 'dist/eco', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(res.status, 0, res.stderr);
      const receipt = JSON.parse(res.stdout) as {
        schema: string;
        ok: boolean;
        lockCompat?: {
          ecosystem: string;
          ecosystemsGenerated: string[];
          artifacts: Array<{ ecosystem: string; relPath: string }>;
        };
      };
      assert.equal(receipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(receipt.ok, true);
      assert.equal(receipt.lockCompat?.ecosystem, 'all');
      assert.equal(receipt.lockCompat?.ecosystemsGenerated.length, 9);
      assert.ok((receipt.lockCompat?.artifacts.length ?? 0) >= 28);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'dpkg-status.holo-v11')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'go.work')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'composer.holo-v11.json')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'php.holo-v11.ini')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'wp-env.holo-v11.json')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', '.bundle', 'config.holo-v11')), true);
      assert.equal(existsSync(join(dir, 'dist', 'eco', 'holo-rubygems-compat.json')), true);

      // Verify CLI aliases: php -> composer, ruby -> rubygems, bundler -> rubygems
      for (const [alias, expectedEco] of [
        ['php', 'composer'],
        ['ruby', 'rubygems'],
        ['bundler', 'rubygems'],
      ]) {
        const aliasRes = spawnSync(
          process.execPath,
          [cliPath, 'lock-compat', '--ecosystem', alias, '--cwd', dir, '--dry-run', '--json'],
          { encoding: 'utf8' },
        );
        assert.equal(aliasRes.status, 0, aliasRes.stderr);
        const aliasReceipt = JSON.parse(aliasRes.stdout) as {
          ok: boolean;
          lockCompat?: { ecosystem: string; ecosystemsGenerated: string[] };
        };
        assert.equal(aliasReceipt.ok, true);
        assert.equal(aliasReceipt.lockCompat?.ecosystem, expectedEco);
        assert.deepEqual(aliasReceipt.lockCompat?.ecosystemsGenerated, [expectedEco]);
      }

      const badRes = spawnSync(
        process.execPath,
        [cliPath, 'lock-compat', '--ecosystem', 'bogus', '--cwd', dir],
        { encoding: 'utf8' },
      );
      assert.equal(badRes.status, 1);
      assert.match(badRes.stderr, /Unknown ecosystem/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('executes bump --apply-pins and pack --cas-dir via CLI with receipt fields', () => {
    const cliPath = join(HERE, 'cli.mts');
    const dir = makeTempDir('holo-ci-cli-bump-pack-');
    try {
      mkdirSync(join(dir, 'assets'), { recursive: true });
      const data = Buffer.from('cli-cas-v11-blob-content', 'utf8');
      const expectedSha512 = createHash('sha512').update(data).digest('hex');
      writeFileSync(join(dir, 'assets', 'artifact.bin'), data);
      writeFileSync(
        join(dir, 'holo-ci.json'),
        JSON.stringify(
          {
            schema: HOLO_CI_SCHEMA,
            name: 'cli-bump-pack',
            kind: 'app',
            upstreamPins: [{ name: 'libpng', pinned: '1.6.58', upstream: '1.6.59' }],
            casRelease: { outDir: 'dist', include: ['assets'] },
          },
          null,
          2,
        ),
        'utf8',
      );

      const bumpRes = spawnSync(
        process.execPath,
        [cliPath, 'bump', '--cwd', dir, '--apply-pins', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(bumpRes.status, 0, bumpRes.stderr);
      const bumpReceipt = JSON.parse(bumpRes.stdout) as {
        schema: string;
        ok: boolean;
        bump?: { bumpedCount?: number; bumpedPins?: string[]; applied?: boolean };
      };
      assert.equal(bumpReceipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(bumpReceipt.ok, true);
      assert.equal(bumpReceipt.bump?.bumpedCount, 1);
      assert.deepEqual(bumpReceipt.bump?.bumpedPins, ['libpng']);
      assert.equal(bumpReceipt.bump?.applied, true);

      const packRes = spawnSync(
        process.execPath,
        [cliPath, 'pack', '--cwd', dir, '--cas-dir', 'cas-out', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(packRes.status, 0, packRes.stderr);
      const packReceipt = JSON.parse(packRes.stdout) as {
        schema: string;
        ok: boolean;
        pack?: { casRoot?: string; casWrittenFiles?: number };
      };
      assert.equal(packReceipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(packReceipt.ok, true);
      assert.equal(packReceipt.pack?.casRoot, join(dir, 'cas-out'));
      assert.equal(packReceipt.pack?.casWrittenFiles, 1);
      assert.equal(
        existsSync(join(dir, 'cas-out', 'v11', 'files', expectedSha512.slice(0, 2), expectedSha512)),
        true,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('executes boundary-audit --json end-to-end (pass and fail)', () => {
    const cliPath = join(HERE, 'cli.mts');
    const dir = makeTempDir('holo-ci-cli-boundary-');
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      writeFileSync(join(dir, 'src', 'index.mts'), 'export const ok = true;\n', 'utf8');
      writeFileSync(
        join(dir, 'custom-boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 2,
          publicEntrypoints: ['src/index.mts'],
          forbiddenImports: ['intersections/sectium-browser'],
          maxParentTraversals: 2,
          scanSourceHttpIpc: true,
        }),
        'utf8',
      );

      const passRes = spawnSync(
        process.execPath,
        [cliPath, 'boundary-audit', '--cwd', dir, '--boundary', 'custom-boundary.json', '--min-score', '70', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(passRes.status, 0, passRes.stderr);
      const passReceipt = JSON.parse(passRes.stdout) as {
        schema: string;
        abiMagic: string;
        phase: string;
        ok: boolean;
        boundaryAudit?: {
          ok: boolean;
          score: number;
          manifestFound: boolean;
          scannedFiles: number;
          axes: Record<string, number>;
          violations: unknown[];
        };
      };
      assert.equal(passReceipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(passReceipt.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(passReceipt.phase, 'boundary-audit');
      assert.equal(passReceipt.ok, true);
      assert.equal(passReceipt.boundaryAudit?.ok, true);
      assert.equal(passReceipt.boundaryAudit?.manifestFound, true);
      assert.equal(passReceipt.boundaryAudit?.scannedFiles, 1);
      assert.equal(passReceipt.boundaryAudit?.axes.dependencyPurity, 20);
      assert.equal(passReceipt.boundaryAudit?.axes.encapsulation, 20);
      assert.equal(passReceipt.boundaryAudit?.axes.ipcCompliance, 20);
      assert.equal(passReceipt.boundaryAudit?.violations.length, 0);

      // Verify --min-score fails cleanly when threshold exceeds actual score
      const belowMinRes = spawnSync(
        process.execPath,
        [cliPath, 'boundary-audit', '--cwd', dir, '--boundary', 'custom-boundary.json', '--min-score', '95', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(belowMinRes.status, 1);
      const belowMinReceipt = JSON.parse(belowMinRes.stdout) as { ok: boolean; errors?: string[] };
      assert.equal(belowMinReceipt.ok, false);
      assert.match(belowMinReceipt.errors?.[0] ?? '', /below minimum required 95\/100/);

      // Inject a forbidden import and verify exit code 1 + violation in JSON receipt
      writeFileSync(
        join(dir, 'src', 'bad.mts'),
        "import { boot } from 'intersections/sectium-browser/internal.mts';\nexport { boot };\n",
        'utf8',
      );
      const failRes = spawnSync(
        process.execPath,
        [cliPath, 'boundary-audit', '--cwd', dir, '--boundary', 'custom-boundary.json', '--json'],
        { encoding: 'utf8' },
      );
      assert.equal(failRes.status, 1);
      const failReceipt = JSON.parse(failRes.stdout) as {
        ok: boolean;
        boundaryAudit?: {
          ok: boolean;
          score: number;
          violations: Array<{ rule: string; file: string }>;
        };
      };
      assert.equal(failReceipt.ok, false);
      assert.equal(failReceipt.boundaryAudit?.ok, false);
      assert.equal(failReceipt.boundaryAudit?.violations.length, 1);
      assert.equal(failReceipt.boundaryAudit?.violations[0].rule, 'forbiddenImport');
      assert.equal(failReceipt.boundaryAudit?.violations[0].file, 'src/bad.mts');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci boundary-audit', () => {
  it('passes clean workspace and scores 100/100 on maintenance-workflows with boundary.json', () => {
    const repoAudit = runBoundaryAudit({ cwd: REPO_ROOT, boundaryPath: 'boundary.json' });
    assert.equal(repoAudit.ok, true);
    assert.equal(repoAudit.manifestFound, true);
    assert.equal(repoAudit.score, 100);
    assert.deepEqual(repoAudit.axes, {
      dependencyPurity: 20,
      encapsulation: 20,
      ipcCompliance: 20,
      abiContract: 20,
      governance: 20,
    });
    assert.equal(repoAudit.violations.length, 0);

    const dir = makeTempDir('holo-ci-boundary-clean-');
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      writeFileSync(join(dir, 'src', 'app.mts'), "import { helper } from './helper.mts';\nexport { helper };\n", 'utf8');
      writeFileSync(join(dir, 'src', 'helper.mts'), 'export const helper = 1;\n', 'utf8');
      const fallbackAudit = runBoundaryAudit({ cwd: dir });
      assert.equal(fallbackAudit.ok, true);
      assert.equal(fallbackAudit.manifestFound, false);
      assert.equal(fallbackAudit.scannedFiles, 2);
      assert.equal(fallbackAudit.axes.dependencyPurity, 20);
      assert.equal(fallbackAudit.axes.encapsulation, 12);
      assert.equal(fallbackAudit.axes.ipcCompliance, 20);
      assert.equal(fallbackAudit.axes.abiContract, 10);
      assert.equal(fallbackAudit.axes.governance, 0);
      assert.equal(fallbackAudit.score, 62);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches forbiddenImports in JS/TS and C/C++ while honoring allowedImports', () => {
    const dir = makeTempDir('holo-ci-boundary-forbidden-');
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      mkdirSync(join(dir, '.github'), { recursive: true });
      writeFileSync(
        join(dir, 'LICENSE'),
        'Permission is hereby granted, free of charge\nTHE SOFTWARE IS PROVIDED "AS IS"\n',
        'utf8',
      );
      writeFileSync(join(dir, '.gitattributes'), '* text=auto eol=lf\n', 'utf8');
      writeFileSync(join(dir, '.github', 'CODEOWNERS'), '* @lemanschik\n', 'utf8');
      const manifest: HoloBoundaryManifest = {
        schema: HOLO_BOUNDARY_SCHEMA,
        plane: 2,
        publicEntrypoints: ['src/index.mts'],
        allowedImports: ['intersections/sectium-browser/public.h'],
        forbiddenImports: ['intersections/sectium-browser', '../../packages/'],
      };
      writeFileSync(join(dir, 'boundary.json'), JSON.stringify(manifest, null, 2), 'utf8');
      writeFileSync(
        join(dir, 'src', 'index.mts'),
        [
          "import { x } from 'intersections/sectium-browser/private.mts';",
          "import { y } from '../../packages/secret/index.mts';",
          'export { x, y };',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(
        join(dir, 'src', 'bridge.c'),
        [
          '#include "intersections/sectium-browser/public.h"',
          '#include "intersections/sectium-browser/private.h"',
        ].join('\n'),
        'utf8',
      );

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, false);
      assert.equal(res.violations.length, 3);
      assert.ok(res.violations.every((v) => v.rule === 'forbiddenImport'));
      assert.equal(res.axes.dependencyPurity, 5);
      assert.equal(res.score, 75);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches deep parent-traversal escapes (../../../../) and respects holo-ci-allow-guard', () => {
    const dir = makeTempDir('holo-ci-boundary-traversal-');
    try {
      mkdirSync(join(dir, 'src', 'nested', 'deep'), { recursive: true });
      writeFileSync(
        join(dir, 'src', 'nested', 'deep', 'escape.mts'),
        [
          "import { ok3 } from '../../../within-limit.mts';",
          "import { allow4 } from '../../../../allowlisted.mts'; // holo-ci-allow-guard",
          "import { bad4 } from '../../../../outside-boundary.mts';",
          'export { ok3, allow4, bad4 };',
        ].join('\n'),
        'utf8',
      );

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, false);
      assert.equal(res.violations.length, 1);
      assert.equal(res.violations[0].rule, 'parentTraversal');
      assert.equal(res.violations[0].line, 3);
      assert.equal(res.axes.dependencyPurity, 15);
      assert.equal(res.axes.encapsulation, 8);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches source-level B8G016 loopback HTTP IPC on .mts files, excludes tests, and respects holo-ci-allow-guard', () => {
    const dir = makeTempDir('holo-ci-boundary-ipc-');
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      mkdirSync(join(dir, 'node_modules', 'pkg'), { recursive: true });
      const badLocalhost = ['http', '://', 'localhost:3000/rpc'].join('');
      const badLoopback = ['http', '://', '127.0.0.1:9000'].join('');

      writeFileSync(
        join(dir, 'src', 'ipc.mts'),
        [
          `const allowed = '${badLocalhost}'; // holo-ci-allow-guard`,
          `export const illegalUrl = '${badLoopback}';`,
        ].join('\n'),
        'utf8',
      );
      // Test files and node_modules must be excluded from source scan
      writeFileSync(join(dir, 'src', 'ipc.test.mts'), `const testUrl = '${badLoopback}';\n`, 'utf8');
      writeFileSync(join(dir, 'node_modules', 'pkg', 'index.js'), `const depUrl = '${badLoopback}';\n`, 'utf8');

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, false);
      assert.equal(res.scannedFiles, 1);
      assert.equal(res.violations.length, 1);
      assert.equal(res.violations[0].rule, 'httpIpc');
      assert.equal(res.violations[0].file, 'src/ipc.mts');
      assert.equal(res.violations[0].line, 2);
      assert.equal(res.axes.ipcCompliance, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('validates abiGoldenFiles and formats boundaryAudit telemetry summary', () => {
    const dir = makeTempDir('holo-ci-boundary-abi-');
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      writeFileSync(join(dir, 'src', 'main.mts'), 'export const v = 1;\n', 'utf8');
      writeFileSync(join(dir, 'abi-golden.json'), JSON.stringify({ abiMagic: B8G_ABI_MAGIC_V3 }), 'utf8');
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 3,
          publicEntrypoints: ['src/main.mts'],
          abiGoldenFiles: ['abi-golden.json'],
        }),
        'utf8',
      );

      const passRes = runBoundaryAudit({ cwd: dir });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.axes.abiContract, 20);

      const receipt = buildReceipt({
        manifest: { schema: HOLO_CI_SCHEMA, name: 'abi-demo', kind: 'control-plane' },
        phase: 'boundary-audit',
        ok: passRes.ok,
        durationMs: 10,
        boundaryAudit: passRes,
      });
      const summaryPath = join(dir, 'summary.md');
      emitTelemetry(receipt, { cwd: dir, emitSummary: true, summaryPath });
      const md = readFileSync(summaryPath, 'utf8');
      assert.match(md, /Boundary Audit/);
      assert.match(md, /Boundary Axes/);
      assert.match(md, /80\/100/);

      // Corrupt golden file -> abiGolden violation and abiContract drops to 0
      writeFileSync(join(dir, 'abi-golden.json'), '{not-valid-json', 'utf8');
      const failRes = runBoundaryAudit({ cwd: dir });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.axes.abiContract, 0);
      assert.equal(failRes.violations[0].rule, 'abiGolden');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('skips default heavy directories (github-mirror, v8) and manifest excludeDirs', () => {
    const dir = makeTempDir('holo-ci-boundary-exclude-');
    try {
      const badLoopback = ['http', '://', '127.0.0.1:9100'].join('');
      mkdirSync(join(dir, 'src'), { recursive: true });
      mkdirSync(join(dir, 'github-mirror', 'repo'), { recursive: true });
      mkdirSync(join(dir, 'v8', 'src'), { recursive: true });
      mkdirSync(join(dir, 'custom-vendor', 'nested'), { recursive: true });

      writeFileSync(join(dir, 'src', 'clean.mts'), 'export const ok = true;\n', 'utf8');
      writeFileSync(
        join(dir, 'github-mirror', 'repo', 'mirror.mts'),
        `export const url = '${badLoopback}';\n`,
        'utf8',
      );
      writeFileSync(
        join(dir, 'v8', 'src', 'engine.cc'),
        `#include "intersections/sectium-browser/private.h"\n// ${badLoopback}\n`,
        'utf8',
      );
      writeFileSync(
        join(dir, 'custom-vendor', 'nested', 'vendor.mts'),
        `export const vUrl = '${badLoopback}';\n`,
        'utf8',
      );
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 1,
          excludeDirs: ['custom-vendor'],
          forbiddenImports: ['intersections/sectium-browser'],
          scanSourceHttpIpc: true,
        }),
        'utf8',
      );

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, true);
      assert.equal(res.scannedFiles, 1);
      assert.equal(res.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('scopes scanning strictly to includePaths subdirectories when specified', () => {
    const dir = makeTempDir('holo-ci-boundary-include-');
    try {
      const badLoopback = ['http', '://', '127.0.0.1:9200'].join('');
      mkdirSync(join(dir, 'sections', 'core'), { recursive: true });
      mkdirSync(join(dir, 'packages', 'sdk', 'dist'), { recursive: true });
      mkdirSync(join(dir, 'outside'), { recursive: true });

      writeFileSync(join(dir, 'sections', 'core', 'a.mts'), 'export const a = 1;\n', 'utf8');
      writeFileSync(join(dir, 'packages', 'sdk', 'b.mts'), 'export const b = 2;\n', 'utf8');
      writeFileSync(join(dir, 'packages', 'sdk', 'dist', 'bundle.js'), `const distUrl = '${badLoopback}';\n`, 'utf8');
      writeFileSync(join(dir, 'outside', 'ignored.mts'), `export const outUrl = '${badLoopback}';\n`, 'utf8');
      writeFileSync(join(dir, 'root-extra.mts'), `export const rootUrl = '${badLoopback}';\n`, 'utf8');
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 1,
          includePaths: ['sections', 'packages'],
          scanSourceHttpIpc: true,
        }),
        'utf8',
      );

      const scopedRes = runBoundaryAudit({ cwd: dir });
      assert.equal(scopedRes.ok, true);
      assert.equal(scopedRes.scannedFiles, 2);
      assert.equal(scopedRes.violations.length, 0);

      // Without includePaths, outside/ignored.mts and root-extra.mts are scanned and flagged
      const unscopedRes = runBoundaryAudit({
        cwd: dir,
        manifest: {
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 1,
          scanSourceHttpIpc: true,
        },
      });
      assert.equal(unscopedRes.ok, false);
      assert.equal(unscopedRes.scannedFiles, 4);
      assert.equal(unscopedRes.violations.length, 2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('uses segment-safe forbidden import matching, validates ABI header paths, and honors b8g-allow-http-ipc', () => {
    const dir = makeTempDir('holo-ci-boundary-upgrades-');
    try {
      const badLoopback = ['http', '://', '127.0.0.1:9444'].join('');
      mkdirSync(join(dir, 'sections', 'core'), { recursive: true });

      // Segment boundary check: "...from './sections/sectium-browser-helper'" must NOT match "sections/sectium-browser"
      // Also test prev-line & inline b8g-allow-http-ipc guards vs unguarded loopback URL
      writeFileSync(
        join(dir, 'sections', 'core', 'main.mts'),
        [
          "import { ok } from './sectium-browser-helper';",
          `// b8g-allow-http-ipc: intentional documented endpoint`,
          `export const docUrl1 = '${badLoopback}';`,
          `export const docUrl2 = '${badLoopback}'; // b8g-allow-http-ipc`,
          `export const badUrl = '${badLoopback}';`,
          'export const sum = ok;',
          '',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(join(dir, 'sections', 'core', 'sectium-browser-helper.mts'), 'export const ok = 1;\n', 'utf8');
      writeFileSync(
        join(dir, 'sections', 'core', 'abi-golden.json'),
        JSON.stringify({ schema: 'holo-abi-golden.v1', header: 'sections/core/missing_abi.h' }),
        'utf8',
      );
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 1,
          forbiddenImports: ['sectium-browser'],
          abiGoldenFiles: ['sections/core/abi-golden.json'],
          scanSourceHttpIpc: true,
        }),
        'utf8',
      );

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, false);
      assert.deepEqual(
        res.violations.map((v) => v.rule),
        ['httpIpc', 'abiGolden'],
      );
      assert.match(res.violations[1]!.message, /missing header/);

      // Projected co-located header (e.g. devtools/ide/game-engines/b8g-graphics/b8g_graphics_abi.h) passes cleanly
      mkdirSync(join(dir, 'ide', 'proj'), { recursive: true });
      writeFileSync(join(dir, 'ide', 'proj', 'unit_abi.h'), 'typedef struct { int x; } Unit;\n', 'utf8');
      writeFileSync(
        join(dir, 'ide', 'proj', 'abi-golden.json'),
        JSON.stringify({ schema: 'holo-abi-golden.v1', header: 'sections/proj/unit_abi.h' }),
        'utf8',
      );
      const projectedRes = runBoundaryAudit({
        cwd: dir,
        manifest: {
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 4,
          includePaths: ['ide'],
          abiGoldenFiles: ['ide/proj/abi-golden.json'],
          scanSourceHttpIpc: true,
        },
      });
      assert.equal(projectedRes.ok, true);
      assert.equal(projectedRes.axes.abiContract, 20);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces DAG cycles (Tarjan SCC) and layer inversions with allowlist & host exemption', () => {
    const dir = makeTempDir('holo-ci-boundary-dag-layers-');
    try {
      mkdirSync(join(dir, 'sections', 'a'), { recursive: true });
      mkdirSync(join(dir, 'sections', 'b'), { recursive: true });
      mkdirSync(join(dir, 'intersections', 'x'), { recursive: true });

      // Core cycle: sections/a <-> sections/b, plus upward inversion sections/a -> intersections/x
      writeFileSync(
        join(dir, 'sections', 'a', 'index.mts'),
        [
          "import { b } from '../b/index.mts';",
          "import type { OnlyType } from '../../intersections/x/index.mts';",
          "import { x } from '../../intersections/x/index.mts';",
          'export const a = b + x;',
          'export type T = OnlyType;',
          '',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(
        join(dir, 'sections', 'b', 'index.mts'),
        "import { a } from '../a/index.mts';\nexport const b = 1 + (a ? 0 : 0);\n",
        'utf8',
      );
      // Host file (.host.mts) must be exempt from DAG & layer checks
      writeFileSync(
        join(dir, 'sections', 'b', 'cli.host.mts'),
        "import { x } from '../../intersections/x/index.mts';\nexport const hostVal = x;\n",
        'utf8',
      );
      writeFileSync(
        join(dir, 'intersections', 'x', 'index.mts'),
        'export type OnlyType = string;\nexport const x = 2;\n',
        'utf8',
      );
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify({
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 4,
          enforceDag: true,
          enforceLayers: true,
          layerRules: [
            { prefix: 'sections/', rank: 1 },
            { prefix: 'intersections/', rank: 2 },
          ],
          scanSourceHttpIpc: true,
        }),
        'utf8',
      );

      const res = runBoundaryAudit({ cwd: dir });
      assert.equal(res.ok, false);
      assert.equal(
        res.violations.filter((v) => v.rule === 'layerInversion').length,
        1,
      );
      assert.equal(
        res.violations.filter((v) => v.rule === 'cyclicImport').length,
        1,
      );

      // Allowlisting the specific edges clears both violations cleanly
      const cleanRes = runBoundaryAudit({
        cwd: dir,
        manifest: {
          schema: HOLO_BOUNDARY_SCHEMA,
          plane: 4,
          enforceDag: true,
          enforceLayers: true,
          layerRules: [
            { prefix: 'sections/', rank: 1 },
            { prefix: 'intersections/', rank: 2 },
          ],
          allowedGeometryEdges: [
            'sections/a -> intersections/x',
            'sections/a -> sections/b',
            'sections/b -> sections/a',
          ],
          scanSourceHttpIpc: true,
        },
      });
      assert.equal(cleanRes.ok, true);
      assert.equal(cleanRes.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
