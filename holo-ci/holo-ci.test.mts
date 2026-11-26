import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runBump } from './bump.mts';
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

describe('holo-ci CLI', () => {
  it('prints help for --help and executes init + verify --json', () => {
    const cliPath = join(HERE, 'cli.mts');
    const helpRes = spawnSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });
    assert.equal(helpRes.status, 0);
    assert.match(helpRes.stdout, /verify/);
    assert.match(helpRes.stdout, /maintain/);
    assert.match(helpRes.stdout, /init/);

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
});
