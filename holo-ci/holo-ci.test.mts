import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
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
});
