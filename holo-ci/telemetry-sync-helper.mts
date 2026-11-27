#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const GHOST_PREFIX_REGEX = new RegExp(`^${['b8g', 'ghost'].join('-')}`, 'i');

export interface RunnerHardwareMetrics {
  cpuCores: number;
  memTotalKb: number;
  memAvailKb: number;
  diskTotalKb: number;
  diskBeforeKb: number;
  diskAfterKb: number;
  diskReclaimedKb: number;
}

export interface GravityManifestEntry {
  repo?: string;
  filename?: string;
  sha512?: string;
  size?: number;
}

export interface GravityUpstreamLib {
  pkg?: string;
  repo?: string;
  upstreamVersion?: string;
  previousV11?: string | null;
  bumped?: boolean;
}

export interface GravityTelemetryReport {
  schema: 'awesome-os.gravity-telemetry.v1';
  abiMagic: '0x33564742';
  generatedAt: string;
  targetOrg: string;
  damper: {
    bounceIndex: number;
    maxBounces: number;
    dampingFactor: number;
    maxShardsPerDrop: number;
    autoBounce: boolean;
    nextBounceReady: boolean;
  };
  runner: {
    os: NodeJS.Platform;
    arch: string;
    cpuCores: number;
    memTotalMb: number;
    memAvailableMb: number;
    diskTotalGb: number;
    diskFreeBeforeGb: number;
    diskFreeAfterGb: number;
    diskReclaimedGb: number;
    apiRateRemaining: number;
    apiRateLimit: number;
  };
  pinning: {
    trackedUpstreamLibs: number;
    atMaxCount: number;
    driftedCount: number;
    driftedLibs: Array<{
      pkg: string | undefined;
      pinned: string | null | undefined;
      upstream: string | undefined;
      bumped: boolean;
    }>;
    maxVersionLockSummary: unknown;
  };
  dedup: {
    totalAssets: number;
    validSha512Count: number;
    uniqueSha512Blobs: number;
    dedupedBlobs: number;
    rawTotalMb: number;
    uniqueTotalMb: number;
    savedMb: number;
    dedupRatioPct: number;
    dupV8Bytes: number;
    b8gGhostRemnants: number;
  };
}

export interface ReclaimRunnerDiskOptions {
  githubOutputPath?: string;
  execFn?: typeof execFileSync;
  skipReclaim?: boolean;
  memInfoPath?: string;
}

export interface EmitGravityTelemetryOptions {
  cwd?: string;
  targetOrg?: string;
  githubToken?: string;
  bounceIndex?: number;
  maxBounces?: number;
  dampingFactor?: number;
  maxShardsPerDrop?: number;
  autoBounce?: boolean;
  metrics?: RunnerHardwareMetrics;
  summaryPath?: string;
  fetchFn?: typeof fetch;
}

export interface SyncTelemetryRepoOptions {
  repoDir: string;
  branch?: string;
  commitMessage?: string;
  push?: boolean;
  execFn?: typeof execFileSync;
}

function readDfRootKb(execFn: typeof execFileSync): { totalKb: number; availKb: number } {
  if (process.platform === 'win32') return { totalKb: 0, availKb: 0 };
  try {
    const out = String(execFn('df', ['-Pk', '/'], { encoding: 'utf8', shell: false }) ?? '');
    const lines = out.trim().split(/\r?\n/);
    if (lines.length >= 2) {
      const cols = lines[1].trim().split(/\s+/);
      const totalKb = Number(cols[1]) || 0;
      const availKb = Number(cols[3]) || 0;
      return { totalKb, availKb };
    }
  } catch {
    // ignore on restricted environments
  }
  return { totalKb: 0, availKb: 0 };
}

export function parseProcMeminfoKb(text: string): { memTotalKb: number; memAvailKb: number } {
  let memTotalKb = 0;
  let memAvailKb = 0;
  for (const line of text.split(/\r?\n/)) {
    const totalMatch = /^MemTotal:\s+(\d+)/.exec(line);
    if (totalMatch) memTotalKb = Number(totalMatch[1]);
    const availMatch = /^MemAvailable:\s+(\d+)/.exec(line);
    if (availMatch) memAvailKb = Number(availMatch[1]);
  }
  return { memTotalKb, memAvailKb };
}

export function reclaimRunnerDiskHeadroom(options: ReclaimRunnerDiskOptions = {}): RunnerHardwareMetrics {
  const execFn = options.execFn ?? execFileSync;
  const before = readDfRootKb(execFn);

  if (!options.skipReclaim && process.platform === 'linux') {
    try {
      execFn(
        'sudo',
        ['rm', '-rf', '/usr/share/dotnet', '/usr/local/lib/android', '/opt/ghc', '/opt/hostedtoolcache/CodeQL'],
        { stdio: 'ignore', shell: false },
      );
    } catch {
      // ignore reclaim permission errors
    }
    try {
      execFn('docker', ['image', 'prune', '-af'], { stdio: 'ignore', shell: false });
    } catch {
      // ignore if docker unavailable
    }
  }

  const after = readDfRootKb(execFn);
  const reclaimedKb = Math.max(0, after.availKb - before.availKb);
  const cpuCores = Math.max(1, cpus().length || 2);

  let memTotalKb = Math.round(totalmem() / 1024);
  let memAvailKb = 0;
  const memInfoPath = options.memInfoPath ?? '/proc/meminfo';
  if (existsSync(memInfoPath)) {
    try {
      const parsed = parseProcMeminfoKb(readFileSync(memInfoPath, 'utf8'));
      if (parsed.memTotalKb > 0) memTotalKb = parsed.memTotalKb;
      memAvailKb = parsed.memAvailKb;
    } catch {
      // ignore
    }
  }

  const metrics: RunnerHardwareMetrics = {
    cpuCores,
    memTotalKb,
    memAvailKb,
    diskTotalKb: before.totalKb,
    diskBeforeKb: before.availKb,
    diskAfterKb: after.availKb,
    diskReclaimedKb: reclaimedKb,
  };

  if (options.githubOutputPath) {
    const outputLines = [
      `cpu_cores=${metrics.cpuCores}`,
      `mem_total_kb=${metrics.memTotalKb}`,
      `mem_avail_kb=${metrics.memAvailKb}`,
      `disk_total_kb=${metrics.diskTotalKb}`,
      `disk_before_kb=${metrics.diskBeforeKb}`,
      `disk_after_kb=${metrics.diskAfterKb}`,
      `disk_reclaimed_kb=${metrics.diskReclaimedKb}`,
      '',
    ].join('\n');
    appendFileSync(options.githubOutputPath, outputLines, 'utf8');
  }

  return metrics;
}

async function loadJsonWithFallback(
  localPaths: string[],
  remoteUrl: string,
  headers: Record<string, string>,
  fetchFn: typeof fetch,
): Promise<Record<string, unknown> | null> {
  for (const p of localPaths) {
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
      } catch {
        // try next fallback
      }
    }
  }
  try {
    const res = await fetchFn(remoteUrl, { headers });
    if (res.ok) return (await res.json()) as Record<string, unknown>;
  } catch {
    // ignore network failure
  }
  return null;
}

export function computeGravityTelemetry(params: {
  org: string;
  bounceIndex: number;
  maxBounces: number;
  dampingFactor: number;
  maxShardsPerDrop: number;
  autoBounce: boolean;
  metrics: RunnerHardwareMetrics;
  apiRateRemaining: number;
  apiRateLimit: number;
  manifest: Record<string, unknown> | null;
  tracker: Record<string, unknown> | null;
  lock: Record<string, unknown> | null;
}): { report: GravityTelemetryReport; ndjsonLines: string[]; summaryMarkdown: string } {
  const entries = (Array.isArray(params.manifest?.entries)
    ? params.manifest.entries
    : []) as GravityManifestEntry[];

  const uniqueSizes = new Map<string, number>();
  let rawBytes = 0;
  let validSha512Count = 0;
  let b8gGhostRemnants = 0;
  for (const e of entries) {
    const sz = Number(e.size || 0);
    rawBytes += sz;
    const h = String(e.sha512 || '');
    if (/^[0-9a-f]{128}$/i.test(h)) validSha512Count++;
    if (!uniqueSizes.has(h)) uniqueSizes.set(h, sz);
    if (GHOST_PREFIX_REGEX.test(String(e.filename || ''))) b8gGhostRemnants++;
  }
  let uniqueBytes = 0;
  for (const sz of uniqueSizes.values()) uniqueBytes += sz;
  const savedBytes = Math.max(0, rawBytes - uniqueBytes);

  const libs = (Array.isArray(params.tracker?.libraries)
    ? params.tracker.libraries
    : []) as GravityUpstreamLib[];
  const driftedLibs = libs.filter(
    (l) => l.bumped || (l.previousV11 && l.upstreamVersion && l.previousV11 !== l.upstreamVersion),
  );
  const atMaxCount = libs.length - driftedLibs.length;

  const mb = (kb: number) => Number((kb / 1024).toFixed(1));
  const gb = (kb: number) => Number((kb / (1024 * 1024)).toFixed(2));
  const bytesToMb = (b: number) => Number((b / 1048576).toFixed(2));

  const report: GravityTelemetryReport = {
    schema: 'awesome-os.gravity-telemetry.v1',
    abiMagic: '0x33564742',
    generatedAt: new Date().toISOString(),
    targetOrg: params.org,
    damper: {
      bounceIndex: params.bounceIndex,
      maxBounces: params.maxBounces,
      dampingFactor: params.dampingFactor,
      maxShardsPerDrop: params.maxShardsPerDrop,
      autoBounce: params.autoBounce,
      nextBounceReady: params.autoBounce && params.bounceIndex < params.maxBounces,
    },
    runner: {
      os: process.platform,
      arch: process.arch,
      cpuCores: params.metrics.cpuCores,
      memTotalMb: mb(params.metrics.memTotalKb),
      memAvailableMb: mb(params.metrics.memAvailKb),
      diskTotalGb: gb(params.metrics.diskTotalKb),
      diskFreeBeforeGb: gb(params.metrics.diskBeforeKb),
      diskFreeAfterGb: gb(params.metrics.diskAfterKb),
      diskReclaimedGb: gb(params.metrics.diskReclaimedKb),
      apiRateRemaining: params.apiRateRemaining,
      apiRateLimit: params.apiRateLimit,
    },
    pinning: {
      trackedUpstreamLibs: libs.length,
      atMaxCount,
      driftedCount: driftedLibs.length,
      driftedLibs: driftedLibs.map((l) => ({
        pkg: l.pkg,
        pinned: l.previousV11,
        upstream: l.upstreamVersion,
        bumped: Boolean(l.bumped),
      })),
      maxVersionLockSummary: params.lock?.summary ?? null,
    },
    dedup: {
      totalAssets: entries.length,
      validSha512Count,
      uniqueSha512Blobs: uniqueSizes.size,
      dedupedBlobs: Math.max(0, entries.length - uniqueSizes.size),
      rawTotalMb: bytesToMb(rawBytes),
      uniqueTotalMb: bytesToMb(uniqueBytes),
      savedMb: bytesToMb(savedBytes),
      dedupRatioPct: rawBytes > 0 ? Number(((savedBytes / rawBytes) * 100).toFixed(2)) : 0,
      dupV8Bytes: 0,
      b8gGhostRemnants,
    },
  };

  const ndjsonLines = [
    JSON.stringify({ schema: report.schema, abiMagic: report.abiMagic, kind: 'summary', ...report }),
    ...libs.map((l) =>
      JSON.stringify({
        schema: report.schema,
        abiMagic: report.abiMagic,
        kind: 'pinned-subsystem',
        pkg: l.pkg,
        repo: l.repo,
        pinned: l.previousV11,
        upstream: l.upstreamVersion,
        bumped: Boolean(l.bumped),
      }),
    ),
  ];

  const summaryMarkdown = [
    `## Gravity Damper Telemetry — Bounce \`${params.bounceIndex}/${params.maxBounces}\` (\`${params.org}\`)`,
    '',
    '| Metric | Value |',
    '| :--- | :--- |',
    `| Schema / ABI Magic | \`${report.schema}\` / \`${report.abiMagic}\` |`,
    `| Damping Factor / Max Shards | \`${params.dampingFactor}\` / \`${params.maxShardsPerDrop}\` (auto_bounce=\`${params.autoBounce}\`) |`,
    `| Runner CPU / RAM | ${report.runner.cpuCores} cores · ${report.runner.memAvailableMb} MB free / ${report.runner.memTotalMb} MB |`,
    `| Disk Headroom | ${report.runner.diskFreeBeforeGb} GB → **${report.runner.diskFreeAfterGb} GB** (+${report.runner.diskReclaimedGb} GB reclaimed) |`,
    `| Version Pinning | **${atMaxCount} / ${libs.length}** at max (${driftedLibs.length} drifted) |`,
    `| SHA-512 CAS Dedup | ${report.dedup.uniqueSha512Blobs} unique / ${report.dedup.totalAssets} assets (${report.dedup.savedMb} MB saved · ${report.dedup.dedupRatioPct}%) |`,
    `| \`dup_v8\` / \`${['b8g', 'ghost'].join('-')}\` | \`${report.dedup.dupV8Bytes} B\` / \`${b8gGhostRemnants}\` |`,
    `| GitHub API Rate Headroom | ${params.apiRateRemaining} / ${params.apiRateLimit} |`,
    '',
  ].join('\n');

  return { report, ndjsonLines, summaryMarkdown };
}

export async function emitGravityTelemetry(
  options: EmitGravityTelemetryOptions = {},
): Promise<GravityTelemetryReport> {
  const cwd = options.cwd ?? process.cwd();
  const org = options.targetOrg ?? 'awesome-os';
  const token = options.githubToken ?? '';
  const fetchFn = options.fetchFn ?? fetch;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'awesome-os-gravity-telemetry/1.0',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const [manifest, tracker, lock] = await Promise.all([
    loadJsonWithFallback(
      [resolve(cwd, 'index/cas-v11-global-manifest.json'), resolve(cwd, '../holo-v11/index/cas-v11-global-manifest.json')],
      `https://raw.githubusercontent.com/${org}/holo-v11/main/index/cas-v11-global-manifest.json`,
      headers,
      fetchFn,
    ),
    loadJsonWithFallback(
      [resolve(cwd, 'catalog/live-upstream-tracker.json'), resolve(cwd, '../t2linux-baseline/catalog/live-upstream-tracker.json')],
      `https://raw.githubusercontent.com/${org}/t2linux-baseline/main/catalog/live-upstream-tracker.json`,
      headers,
      fetchFn,
    ),
    loadJsonWithFallback(
      [
        resolve(cwd, 'catalog/max-version-lock.json'),
        resolve(cwd, 'reports/max-version-lock.json'),
        resolve(cwd, '../t2linux-baseline/catalog/max-version-lock.json'),
      ],
      `https://raw.githubusercontent.com/${org}/t2linux-baseline/main/catalog/max-version-lock.json`,
      headers,
      fetchFn,
    ),
  ]);

  let apiRateRemaining = 0;
  let apiRateLimit = 0;
  try {
    const rl = await fetchFn('https://api.github.com/rate_limit', { headers });
    if (rl.ok) {
      const rlJson = (await rl.json()) as { resources?: { core?: { remaining?: number; limit?: number } } };
      apiRateRemaining = rlJson.resources?.core?.remaining ?? 0;
      apiRateLimit = rlJson.resources?.core?.limit ?? 0;
    }
  } catch {
    // ignore rate limit probe error
  }

  const metrics: RunnerHardwareMetrics = options.metrics ?? {
    cpuCores: Math.max(1, cpus().length || 2),
    memTotalKb: 0,
    memAvailKb: 0,
    diskTotalKb: 0,
    diskBeforeKb: 0,
    diskAfterKb: 0,
    diskReclaimedKb: 0,
  };

  const { report, ndjsonLines, summaryMarkdown } = computeGravityTelemetry({
    org,
    bounceIndex: options.bounceIndex ?? 0,
    maxBounces: options.maxBounces ?? 3,
    dampingFactor: options.dampingFactor ?? 0.65,
    maxShardsPerDrop: options.maxShardsPerDrop ?? 600,
    autoBounce: Boolean(options.autoBounce),
    metrics,
    apiRateRemaining,
    apiRateLimit,
    manifest,
    tracker,
    lock,
  });

  writeFileSync(resolve(cwd, 'gravity-telemetry.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  writeFileSync(resolve(cwd, 'gravity-telemetry.ndjson'), `${ndjsonLines.join('\n')}\n`, 'utf8');

  const summaryPath = options.summaryPath ?? process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    mkdirSync(dirname(resolve(cwd, summaryPath)), { recursive: true });
    appendFileSync(resolve(cwd, summaryPath), summaryMarkdown, 'utf8');
  }

  process.stdout.write('[GRAVITY TELEMETRY] Emitted gravity-telemetry.json & gravity-telemetry.ndjson\n');
  return report;
}

export function syncTelemetryRepo(options: SyncTelemetryRepoOptions): { committed: boolean; pushed: boolean } {
  const execFn = options.execFn ?? execFileSync;
  const status = String(
    execFn('git', ['status', '--porcelain'], {
      cwd: options.repoDir,
      encoding: 'utf8',
      shell: false,
    }) ?? '',
  ).trim();

  if (!status) {
    return { committed: false, pushed: false };
  }

  execFn('git', ['add', '-A'], { cwd: options.repoDir, stdio: 'inherit', shell: false });
  execFn(
    'git',
    ['commit', '-m', options.commitMessage ?? 'chore(telemetry): sync gravity telemetry'],
    { cwd: options.repoDir, stdio: 'inherit', shell: false },
  );

  if (options.push) {
    const branch = options.branch ?? 'main';
    execFn('git', ['push', 'origin', branch], { cwd: options.repoDir, stdio: 'inherit', shell: false });
    return { committed: true, pushed: true };
  }

  return { committed: true, pushed: false };
}

async function main(argv: string[]): Promise<void> {
  const subcommand = argv[0] ?? 'run';
  if (subcommand === 'reclaim') {
    reclaimRunnerDiskHeadroom({ githubOutputPath: process.env.GITHUB_OUTPUT });
    return;
  }

  if (subcommand === 'run' || subcommand === 'emit') {
    const metrics =
      subcommand === 'run'
        ? reclaimRunnerDiskHeadroom({ githubOutputPath: process.env.GITHUB_OUTPUT })
        : {
            cpuCores: Number(process.env.CPU_CORES || '2'),
            memTotalKb: Number(process.env.MEM_TOTAL_KB || '0'),
            memAvailKb: Number(process.env.MEM_AVAIL_KB || '0'),
            diskTotalKb: Number(process.env.DISK_TOTAL_KB || '0'),
            diskBeforeKb: Number(process.env.DISK_BEFORE_KB || '0'),
            diskAfterKb: Number(process.env.DISK_AFTER_KB || '0'),
            diskReclaimedKb: Number(process.env.DISK_RECLAIMED_KB || '0'),
          };

    await emitGravityTelemetry({
      targetOrg: process.env.TARGET_ORG || 'awesome-os',
      githubToken: process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '',
      bounceIndex: Number(process.env.BOUNCE_INDEX || '0'),
      maxBounces: Number(process.env.MAX_BOUNCES || '3'),
      dampingFactor: Number(process.env.DAMPING_FACTOR || '0.65'),
      maxShardsPerDrop: Number(process.env.MAX_SHARDS_PER_DROP || '600'),
      autoBounce: process.env.AUTO_BOUNCE === 'true',
      metrics,
      summaryPath: process.env.GITHUB_STEP_SUMMARY,
    });
    return;
  }

  throw new Error(`Unknown telemetry-sync-helper subcommand "${subcommand}"`);
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`[telemetry-sync-helper] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
