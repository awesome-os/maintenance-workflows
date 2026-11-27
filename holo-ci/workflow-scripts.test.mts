import assert from 'node:assert/strict';
import type { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  buildDockerRunArgs,
  formatE2eSummaryMarkdown,
  parseDockerLoadedImage,
  resolveE2eImage,
  resolveImageSpec,
  runInContainer,
  verifySha512SumsContent,
  writeE2eSummary,
} from './e2e-runner.mts';
import {
  generateChecksums,
  publishGravityRelease,
  runGravityBuild,
  verifyCasManifest,
} from './gravity-bump-helper.mts';
import {
  computeGravityTelemetry,
  emitGravityTelemetry,
  parseProcMeminfoKb,
  reclaimRunnerDiskHeadroom,
  syncTelemetryRepo,
} from './telemetry-sync-helper.mts';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');

function makeTempDir(prefix = 'holo-wf-script-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('holo-ci/e2e-runner.mts', () => {
  it('resolves gpu and lite runner specs and parses docker load output', () => {
    const gpu = resolveImageSpec('ghcr.io/awesome-os/holo-e2e-runner:latest', 'gpu');
    assert.equal(gpu.targetImage, 'ghcr.io/awesome-os/holo-e2e-runner:latest');
    assert.equal(gpu.fallbackTarball, 'holo-e2e-runner-linux-amd64.oci.tar.gz');
    assert.equal(gpu.fallbackSums, 'SHA512SUMS-holo-e2e-runner.txt');

    const lite = resolveImageSpec('ghcr.io/awesome-os/holo-e2e-runner:latest', 'lite');
    assert.equal(lite.targetImage, 'ghcr.io/awesome-os/holo-e2e-lite:latest');
    assert.equal(lite.fallbackTarball, 'holo-e2e-lite-linux-amd64.oci.tar.gz');
    assert.equal(lite.fallbackSums, 'SHA512SUMS-holo-e2e-lite.txt');

    assert.equal(parseDockerLoadedImage('Loaded image: ghcr.io/awesome-os/holo-e2e-lite:latest\n'), 'ghcr.io/awesome-os/holo-e2e-lite:latest');
    assert.equal(parseDockerLoadedImage('Loaded image ID: sha256:deadbeef\n'), 'sha256:deadbeef');
  });

  it('falls back to sovereign OCI release tarball with SHA-512 verification and writes GITHUB_ENV', async () => {
    const dir = makeTempDir('holo-e2e-resolve-');
    try {
      const tarBytes = Buffer.from('fake-oci-tarball-payload', 'utf8');
      const tarHash = createHash('sha512').update(tarBytes).digest('hex');
      assert.equal(verifySha512SumsContent(`${tarHash}  holo-e2e-lite-linux-amd64.oci.tar.gz\n`, 'holo-e2e-lite-linux-amd64.oci.tar.gz', tarHash), true);
      assert.equal(verifySha512SumsContent(`${'0'.repeat(128)}  holo-e2e-lite-linux-amd64.oci.tar.gz\n`, 'holo-e2e-lite-linux-amd64.oci.tar.gz', tarHash), false);

      const envFile = join(dir, 'github.env');
      const ociWork = join(dir, 'oci-work');
      const calls: Array<{ cmd: string; args: string[]; shell: unknown }> = [];

      const mockExec = ((cmd: string, args: string[], opts?: { shell?: unknown }) => {
        calls.push({ cmd, args, shell: opts?.shell });
        if (args[0] === 'login') throw new Error('ghcr unavailable');
        if (args[0] === 'load') return 'Loaded image: ghcr.io/awesome-os/holo-e2e-lite:v11\n';
        return '';
      }) as unknown as typeof execFileSync;

      const mockFetch = (async (input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith('.tar.gz')) return new Response(tarBytes, { status: 200 });
        if (url.endsWith('.txt')) return new Response(`${tarHash}  holo-e2e-lite-linux-amd64.oci.tar.gz\n`, { status: 200 });
        return new Response('', { status: 404 });
      }) as typeof fetch;

      const res = await resolveE2eImage({
        runnerTier: 'lite',
        githubToken: 'tok',
        githubActor: 'bot',
        envFile,
        workDir: ociWork,
        execFn: mockExec,
        fetchFn: mockFetch,
      });

      assert.equal(res.resolvedImage, 'ghcr.io/awesome-os/holo-e2e-lite:v11');
      assert.equal(res.runnerTier, 'lite');
      assert.match(res.imageSource, /^release:v11-oci-latest/);
      assert.ok(calls.every((c) => c.shell === false));
      const envText = readFileSync(envFile, 'utf8');
      assert.match(envText, /RUNNER_IMAGE=ghcr\.io\/awesome-os\/holo-e2e-lite:v11/);
      assert.match(envText, /RUNNER_TIER=lite/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('builds docker run args, executes lite container-exec, and formats step summary', () => {
    const dir = makeTempDir('holo-e2e-exec-');
    try {
      const dockerArgs = buildDockerRunArgs({
        workspace: '/w',
        artifactsPath: 'holo-e2e-artifacts',
        workingDirectory: 'sub',
        configPath: 'holo-ci.json',
        runnerImage: 'ghcr.io/awesome-os/holo-e2e-lite:latest',
        runnerTier: 'lite',
        e2eCmd: 'echo ok',
        githubToken: 'tok',
        homeDir: '/home/runner',
      });
      assert.ok(dockerArgs.includes('/workspace/sub'));
      assert.ok(dockerArgs.includes('HOLO_E2E_ARTIFACTS=/workspace/holo-e2e-artifacts'));
      assert.ok(dockerArgs.includes('container-exec'));

      const artifactsDir = join(dir, 'artifacts');
      const invoked: Array<{ cmd: string; args: string[]; shell: unknown }> = [];
      const mockExec = ((cmd: string, args: string[], opts?: { shell?: unknown }) => {
        invoked.push({ cmd, args, shell: opts?.shell });
        return '';
      }) as unknown as typeof execFileSync;

      runInContainer({
        artifactsDir,
        configPath: 'holo-ci.json',
        runnerTier: 'lite',
        e2eCmd: 'echo hello',
        probePath: join(dir, 'missing-probe'),
        cliPath: '/workspace/.holo-ci-runtime/holo-ci/cli.mts',
        execFn: mockExec,
      });

      assert.equal(invoked.length, 2);
      assert.ok(invoked.every((c) => c.shell === false));
      assert.equal(invoked[0].args[1], 'verify');
      assert.equal(invoked[1].cmd, 'bash');

      const probe = JSON.parse(readFileSync(join(artifactsDir, 'offscreen-probe.json'), 'utf8')) as {
        tier: string;
        lavapipeIcd: string;
      };
      assert.equal(probe.tier, 'lite');
      assert.equal(probe.lavapipeIcd, 'skipped-lite');

      writeFileSync(join(artifactsDir, 'holo-e2e-receipt.ndjson'), `${JSON.stringify({ ok: true })}\n`, 'utf8');
      const summaryFile = join(dir, 'summary.md');
      assert.equal(writeE2eSummary({ artifactsDir, imageSource: 'ghcr:lite', summaryPath: summaryFile }), true);
      const md = formatE2eSummaryMarkdown(artifactsDir, 'ghcr:lite');
      assert.match(md, /Holo-E2E Offscreen Lavapipe \+ Zero-X11 Summary/);
      assert.match(md, /`pass`/);
      assert.equal(readFileSync(summaryFile, 'utf8'), md);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci/gravity-bump-helper.mts', () => {
  it('stages fast-lib and incremental-bin artifacts, validates CAS manifests, and publishes releases', () => {
    const dir = makeTempDir('holo-gravity-build-');
    try {
      const targetRel = join(dir, 'target', 'x86_64-unknown-linux-gnu', 'release');
      mkdirSync(targetRel, { recursive: true });
      const libPayload = Buffer.from('elf-shared-lib-bytes', 'utf8');
      const binPayload = Buffer.from('elf-bin-bytes', 'utf8');
      writeFileSync(join(targetRel, 'libdemo.so'), libPayload);
      writeFileSync(join(targetRel, 'demo-cli'), binPayload);

      const cargoCalls: Array<{ cmd: string; args: string[]; shell: unknown }> = [];
      const mockCargo = ((cmd: string, args: string[], opts?: { shell?: unknown }) => {
        cargoCalls.push({ cmd, args, shell: opts?.shell });
        return '';
      }) as unknown as typeof execFileSync;

      const libTelemetry = runGravityBuild({
        cwd: dir,
        role: 'fast-lib',
        kind: 'rust-lib-and-bin',
        crate: 'libdemo-ffi',
        assetPrefix: 'demo',
        os: 'ubuntu-latest',
        osTag: 'linux-x64',
        target: 'x86_64-unknown-linux-gnu',
        ext: 'so',
        cacheHit: true,
        execFn: mockCargo,
      });

      assert.equal(libTelemetry.schema, 'awesome-os.gravity-build-telemetry.v1');
      assert.equal(libTelemetry.abiMagic, '0x33564742');
      assert.equal(libTelemetry.artifact, 'demo-linux-x64.so');
      assert.equal(libTelemetry.cacheHit, true);
      assert.equal(existsSync(join(dir, 'dist', 'demo-linux-x64.so.sha512')), true);

      const binTelemetry = runGravityBuild({
        cwd: dir,
        role: 'incremental-bin',
        kind: 'rust-lib-and-bin',
        crate: 'demo-cli',
        assetPrefix: 'demo',
        os: 'ubuntu-latest',
        osTag: 'linux-x64',
        target: 'x86_64-unknown-linux-gnu',
        ext: '',
        cacheHit: false,
        execFn: mockCargo,
      });
      assert.equal(binTelemetry.artifact, 'demo-linux-x64');
      assert.ok(cargoCalls.every((c) => c.shell === false));

      const distDir = join(dir, 'dist');
      const casCheck = verifyCasManifest(distDir);
      assert.equal(casCheck.ok, true);
      assert.equal(casCheck.assetsChecked, 2);
      assert.equal(casCheck.telemetryChecked, 1);

      const sums = generateChecksums(distDir);
      assert.equal(existsSync(sums.sha256File), true);
      assert.equal(existsSync(sums.sha512File), true);

      const ghCalls: string[][] = [];
      const mockGh = ((_cmd: string, args: string[], opts?: { shell?: unknown }) => {
        assert.equal(opts?.shell, false);
        ghCalls.push(args);
        if (args[1] === 'view') throw new Error('not found');
        return '';
      }) as unknown as typeof execFileSync;

      publishGravityRelease({
        distDir,
        tag: 'v1.0.0',
        repo: 'awesome-os/demo',
        assetPrefix: 'demo',
        execFn: mockGh,
      });
      assert.equal(ghCalls.length, 2);
      assert.equal(ghCalls[0][1], 'view');
      assert.equal(ghCalls[1][1], 'create');

      // Corrupt staged asset -> verifyCasManifest must fail
      writeFileSync(join(distDir, 'demo-linux-x64.so'), 'tampered', 'utf8');
      const badCheck = verifyCasManifest(distDir);
      assert.equal(badCheck.ok, false);
      assert.match(badCheck.errors[0], /SHA-512 mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('holo-ci/telemetry-sync-helper.mts', () => {
  it('parses meminfo, writes runner metrics to GITHUB_OUTPUT, emits gravity telemetry, and syncs git cleanly', async () => {
    const dir = makeTempDir('holo-telemetry-sync-');
    try {
      const memInfoPath = join(dir, 'meminfo');
      writeFileSync(memInfoPath, 'MemTotal:       16384000 kB\nMemAvailable:   12288000 kB\n', 'utf8');
      const parsedMem = parseProcMeminfoKb(readFileSync(memInfoPath, 'utf8'));
      assert.equal(parsedMem.memTotalKb, 16384000);
      assert.equal(parsedMem.memAvailKb, 12288000);

      const ghOut = join(dir, 'github.output');
      const metrics = reclaimRunnerDiskHeadroom({
        githubOutputPath: ghOut,
        skipReclaim: true,
        memInfoPath,
      });
      assert.equal(metrics.memTotalKb, 16384000);
      assert.equal(metrics.memAvailKb, 12288000);
      assert.match(readFileSync(ghOut, 'utf8'), /cpu_cores=\d+/);

      mkdirSync(join(dir, 'index'), { recursive: true });
      mkdirSync(join(dir, 'catalog'), { recursive: true });
      const h1 = 'a'.repeat(128);
      const h2 = 'b'.repeat(128);
      writeFileSync(
        join(dir, 'index', 'cas-v11-global-manifest.json'),
        JSON.stringify({
          entries: [
            { repo: 'a', filename: 'f1.bin', sha512: h1, size: 1048576 },
            { repo: 'b', filename: 'f2.bin', sha512: h1, size: 1048576 },
            { repo: 'c', filename: 'f3.bin', sha512: h2, size: 524288 },
          ],
        }),
        'utf8',
      );
      writeFileSync(
        join(dir, 'catalog', 'live-upstream-tracker.json'),
        JSON.stringify({
          libraries: [
            { pkg: 'zlib', repo: 'madler/zlib', previousV11: '1.4', upstreamVersion: '1.4', bumped: false },
            { pkg: 'zstd', repo: 'facebook/zstd', previousV11: '1.5.7', upstreamVersion: '1.6.0', bumped: true },
          ],
        }),
        'utf8',
      );
      writeFileSync(join(dir, 'catalog', 'max-version-lock.json'), JSON.stringify({ summary: { total: 2 } }), 'utf8');

      const summaryPath = join(dir, 'step-summary.md');
      const mockFetch = (async () =>
        new Response(JSON.stringify({ resources: { core: { remaining: 4990, limit: 5000 } } }), {
          status: 200,
        })) as typeof fetch;

      const report = await emitGravityTelemetry({
        cwd: dir,
        targetOrg: 'awesome-os',
        bounceIndex: 1,
        maxBounces: 3,
        dampingFactor: 0.65,
        maxShardsPerDrop: 600,
        autoBounce: true,
        metrics,
        summaryPath,
        fetchFn: mockFetch,
      });

      assert.equal(report.schema, 'awesome-os.gravity-telemetry.v1');
      assert.equal(report.abiMagic, '0x33564742');
      assert.equal(report.damper.nextBounceReady, true);
      assert.equal(report.pinning.trackedUpstreamLibs, 2);
      assert.equal(report.pinning.atMaxCount, 1);
      assert.equal(report.pinning.driftedCount, 1);
      assert.equal(report.dedup.uniqueSha512Blobs, 2);
      assert.equal(report.dedup.dedupedBlobs, 1);
      assert.equal(report.dedup.dupV8Bytes, 0);
      assert.equal(report.dedup.b8gGhostRemnants, 0);
      assert.equal(report.runner.apiRateRemaining, 4990);
      assert.equal(existsSync(join(dir, 'gravity-telemetry.json')), true);
      assert.equal(existsSync(join(dir, 'gravity-telemetry.ndjson')), true);
      assert.match(readFileSync(summaryPath, 'utf8'), /Gravity Damper Telemetry/);

      // Test computeGravityTelemetry direct purity
      const computed = computeGravityTelemetry({
        org: 'awesome-os',
        bounceIndex: 0,
        maxBounces: 3,
        dampingFactor: 0.65,
        maxShardsPerDrop: 600,
        autoBounce: false,
        metrics,
        apiRateRemaining: 100,
        apiRateLimit: 5000,
        manifest: null,
        tracker: null,
        lock: null,
      });
      assert.equal(computed.report.dedup.totalAssets, 0);
      assert.equal(computed.ndjsonLines.length, 1);

      // Test syncTelemetryRepo with mocked git execFn
      const gitCalls: string[][] = [];
      const mockGit = ((_cmd: string, args: string[], opts?: { shell?: unknown }) => {
        assert.equal(opts?.shell, false);
        gitCalls.push(args);
        if (args[0] === 'status') return ' M gravity-telemetry.json\n';
        return '';
      }) as unknown as typeof execFileSync;

      const synced = syncTelemetryRepo({ repoDir: dir, push: true, execFn: mockGit });
      assert.deepEqual(synced, { committed: true, pushed: true });
      assert.deepEqual(
        gitCalls.map((a) => a[0]),
        ['status', 'add', 'commit', 'push'],
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('verifies all three helper scripts have node shebang and zero shell:true', () => {
    for (const scriptName of ['e2e-runner.mts', 'gravity-bump-helper.mts', 'telemetry-sync-helper.mts']) {
      const content = readFileSync(join(REPO_ROOT, 'holo-ci', scriptName), 'utf8');
      assert.ok(content.startsWith('#!/usr/bin/env node\n'), `${scriptName} missing shebang`);
      assert.equal(/shell\s*:\s*true/.test(content), false, `${scriptName} must not use shell: true`);
    }
  });
});
