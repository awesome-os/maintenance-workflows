import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createAuditStackRegistry,
  registerBuiltinHoloCiAudits,
  type AuditStackMode,
} from './audit-stack.mts';
import { runBoundaryAudit } from './boundary.mts';
import { runBumpAsync } from './bump.mts';
import { collectFleetForensics } from './fleet-forensics.mts';
import { runLockCompat, tryLoadHoloPmLockfileHelper } from './lock-compat.mts';
import { runMaintain } from './maintain.mts';
import { runPack } from './pack.mts';
import {
  HOLO_CI_SCHEMA,
  loadManifest,
  type HoloCiKind,
  type HoloCiLockCompatEcosystem,
  type HoloCiManifest,
  type HoloCiPhase,
  type HoloCiReceipt,
} from './schema.mts';
import { runSync } from './sync.mts';
import { buildReceipt, emitTelemetry } from './telemetry.mts';
import { runVerify } from './verify.mts';
import { hardenWorkflowsInDir, runFleetWorkflowHardening } from './wf-harden.mts';

export interface ParsedCliArgs {
  phase: HoloCiPhase;
  help: boolean;
  configPath: string;
  boundaryPath?: string;
  receiptPath?: string;
  emitSummary: boolean;
  summaryFile?: string;
  json: boolean;
  version?: string;
  packagePath?: string;
  dryRun: boolean;
  check: boolean;
  fix: boolean;
  fleetRoot?: string;
  timeoutMinutes?: number;
  retentionDays?: number;
  owner?: string;
  repos?: string[];
  hours?: number;
  slowSec?: number;
  fetchUpstream: boolean;
  applyPins: boolean;
  shadowCanary: boolean;
  casDir?: string;
  outDir?: string;
  outFile?: string;
  ecosystem?: HoloCiLockCompatEcosystem;
  cwd: string;
  minScore?: number;
  force: boolean;
  name?: string;
  kind?: HoloCiKind;
  maxLockPath?: string;
  repo?: string;
  mode?: AuditStackMode;
  telemetryOutPath?: string;
  concurrency?: number;
  onlyIds?: string[];
}

const VALID_PHASES = new Set<HoloCiPhase>([
  'verify',
  'sync',
  'bump',
  'pack',
  'telemetry',
  'maintain',
  'init',
  'lock-compat',
  'boundary-audit',
  'wf-harden',
  'audit-stack',
  'fleet-forensics',
]);

const VALID_ECOSYSTEMS = new Set<HoloCiLockCompatEcosystem>([
  'all',
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

const ECOSYSTEM_ALIASES: Record<string, HoloCiLockCompatEcosystem> = {
  php: 'composer',
  ruby: 'rubygems',
  bundler: 'rubygems',
};

export function getHelpText(): string {
  return [
    'holo-ci — Zero-dependency Awesome-OS CI/CD & CAS v11 runtime',
    '',
    'Usage:',
    '  node holo-ci/cli.mts <phase> [options]',
    '',
    'Phases:',
    '  verify       Run tests, nativeGates, doc checks, and zeroGhost/zeroCasV1/zeroHttpIpc/noBrokenBadges/noWorkflowBloat guards',
    '  sync         Compare recursive SHA-256 syncPairs and audit git working-tree status',
    '  bump         Check upstream semver pins (pinned >= upstream) and bump package.json (--version)',
    '  pack         Generate deterministic holo-v11-manifest.json & SHA512SUMS.txt with dedup stats',
    '  telemetry    Emit holo-ci.receipt.v1 JSON/NDJSON and optional GitHub Step Summary',
    '  maintain     Verify clean-box HTTP 200 endpoints, SHA-512 bundles, and Ed25519 signatures',
    '  init         Scaffold a starter holo-ci.json manifest in the target directory',
    '  lock-compat  Synthesize zero-copy CAS v11 lock/metadata projections (npm|cargo|uv|go|vcpkg|winget|apt|composer|rubygems|all)',
    '  boundary-audit  Run Chromium-style checkdeps & 0-100 architectural boundary audit (boundary.json)',
    '  wf-harden    Audit or deterministically autofix GitHub Actions workflows (--check | --fix | --fleet <mirrorRoot>)',
    '  audit-stack  Run pluggable programmatic audit stack (--mode fail-fast|exhaust) and emit b8g.audit-push.v1',
    '  fleet-forensics  Single-process GitHub Actions fleet forensics scanner (failed, cancelled, slow jobs)',
    '',
    'Options:',
    '  --config <path>        Path to holo-ci.json (default: holo-ci.json)',
    '  --boundary <path>      Path to boundary.json for `boundary-audit` (default: boundary.json)',
    '  --receipt <path>       Write holo-ci.receipt.v1 JSON or append NDJSON line',
    '  --emit-summary         Append Markdown summary to $GITHUB_STEP_SUMMARY (or --summary-file)',
    '  --summary-file <path>  Explicit Markdown summary path override',
    '  --json                 Print receipt JSON to stdout',
    '  --version <X.Y.Z>      Target semver for `bump`',
    '  --package <path>       Path to package.json for `bump` (default: package.json)',
    '  --fetch-upstream       Resolve latest upstream versions from GitHub for pins with upstreamRepo',
    '  --apply-pins           Update lagged upstreamPins in holo-ci.json during `bump`',
    '  --shadow-canary        Run verify/abi-golden/SHA-512 canary gate before applying pins during `bump`',
    '  --cas-dir <dir>        Materialize CAS v11 content-addressed blobs during `pack`',
    '  --dry-run              Preview `bump` or `lock-compat` without writing files',
    '  --check                Audit workflows without modifying files in `wf-harden` (default)',
    '  --fix                  Autofix workflows in-place in `wf-harden`',
    '  --fleet <mirrorRoot>   Audit or autofix all active repository mirrors under <mirrorRoot> in `wf-harden`',
    '  --timeout-minutes <n>  Default job timeout-minutes for `wf-harden`',
    '  --retention-days <n>   Default upload-artifact retention-days for `wf-harden`',
    '  --owner <org>          GitHub organization/owner for `fleet-forensics` (default: awesome-os)',
    '  --repos <a,b>          Comma-separated repo names for `fleet-forensics`',
    '  --hours <n>            Lookback window in hours for `fleet-forensics` (default: 4)',
    '  --slow-sec <n>         Slow job threshold in seconds for `fleet-forensics` (default: 300)',
    '  --repo <name>          Repository identifier for `audit-stack` (default: manifest name or cwd basename)',
    '  --mode <mode>          Execution mode for `audit-stack`: fail-fast|exhaust (default: fail-fast)',
    '  --telemetry-out <path> Append holo-rule-violation.v1 JSONL telemetry during `audit-stack`',
    '  --concurrency <n>      Max concurrent audits during `audit-stack`',
    '  --only <id1,id2>       Comma-separated audit IDs to run during `audit-stack`',
    '  --out <path>           Output dir (`pack`), lockfile (`lock-compat`), or b8g.audit-push.v1 JSON (`audit-stack`)',
    '  --out-dir <dir>        Output directory for `lock-compat` projections (or `pack`)',
    '  --ecosystem <name>     Target ecosystem for `lock-compat`: all|npm|cargo|uv|go|vcpkg|winget|apt|composer|rubygems (aliases: php, ruby, bundler) (default: npm)',
    '  --max-lock <path>      Optional max-version-lock.json override file for `lock-compat`',
    '  --cwd <dir>            Working directory override',
    '  --min-score <score>    Minimum boundary-audit score (0-100) required to pass',
    '  --name <name>          Project name for `init`',
    '  --kind <kind>          Project kind for `init` (monorepo|native-fork|control-plane|app)',
    '  --force                Overwrite existing holo-ci.json on `init`',
    '  -h, --help             Show this help text',
    '',
  ].join('\n');
}

export function parseCliArgs(argv: string[]): ParsedCliArgs {
  let phase: HoloCiPhase = 'verify';
  let phaseExplicit = false;
  let help = false;
  let configPath = 'holo-ci.json';
  let boundaryPath: string | undefined;
  let receiptPath: string | undefined;
  let emitSummary = false;
  let summaryFile: string | undefined;
  let json = false;
  let version: string | undefined;
  let packagePath: string | undefined;
  let dryRun = false;
  let check = true;
  let fix = false;
  let fleetRoot: string | undefined;
  let timeoutMinutes: number | undefined;
  let retentionDays: number | undefined;
  let owner: string | undefined;
  let repos: string[] | undefined;
  let hours: number | undefined;
  let slowSec: number | undefined;
  let fetchUpstream = false;
  let applyPins = false;
  let shadowCanary = false;
  let casDir: string | undefined;
  let outDir: string | undefined;
  let outFile: string | undefined;
  let ecosystem: HoloCiLockCompatEcosystem | undefined;
  let cwd = process.cwd();
  let minScore: number | undefined;
  let force = false;
  let name: string | undefined;
  let kind: HoloCiKind | undefined;
  let maxLockPath: string | undefined;
  let repo: string | undefined;
  let mode: AuditStackMode | undefined;
  let telemetryOutPath: string | undefined;
  let concurrency: number | undefined;
  let onlyIds: string[] | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--config' && argv[i + 1]) {
      configPath = argv[++i];
    } else if (arg === '--boundary' && argv[i + 1]) {
      boundaryPath = argv[++i];
    } else if (arg === '--receipt' && argv[i + 1]) {
      receiptPath = argv[++i];
    } else if (arg === '--emit-summary') {
      emitSummary = true;
    } else if (arg === '--summary-file' && argv[i + 1]) {
      summaryFile = argv[++i];
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--version' && argv[i + 1]) {
      version = argv[++i];
    } else if (arg === '--package' && argv[i + 1]) {
      packagePath = argv[++i];
    } else if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--check') {
      check = true;
      fix = false;
    } else if (arg === '--fix') {
      fix = true;
      check = false;
    } else if (arg === '--fleet' && argv[i + 1]) {
      fleetRoot = resolve(argv[++i]);
    } else if (arg === '--owner' && argv[i + 1]) {
      owner = argv[++i].trim();
    } else if (arg === '--repos' && argv[i + 1]) {
      repos = argv[++i]
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);
    } else if (arg === '--hours' && argv[i + 1]) {
      const rawHours = argv[++i];
      const parsedHours = Number(rawHours);
      if (!Number.isFinite(parsedHours) || parsedHours <= 0) {
        throw new Error(`Invalid --hours "${rawHours}" (expected positive number)`);
      }
      hours = parsedHours;
    } else if (arg === '--slow-sec' && argv[i + 1]) {
      const rawSlow = argv[++i];
      const parsedSlow = Number(rawSlow);
      if (!Number.isFinite(parsedSlow) || parsedSlow <= 0) {
        throw new Error(`Invalid --slow-sec "${rawSlow}" (expected positive number)`);
      }
      slowSec = parsedSlow;
    } else if (arg === '--timeout-minutes' && argv[i + 1]) {
      const rawTimeout = argv[++i];
      const parsedTimeout = Number(rawTimeout);
      if (!Number.isInteger(parsedTimeout) || parsedTimeout <= 0) {
        throw new Error(`Invalid --timeout-minutes "${rawTimeout}" (expected positive integer)`);
      }
      timeoutMinutes = parsedTimeout;
    } else if (arg === '--retention-days' && argv[i + 1]) {
      const rawRetention = argv[++i];
      const parsedRetention = Number(rawRetention);
      if (!Number.isInteger(parsedRetention) || parsedRetention <= 0) {
        throw new Error(`Invalid --retention-days "${rawRetention}" (expected positive integer)`);
      }
      retentionDays = parsedRetention;
    } else if (arg === '--fetch-upstream') {
      fetchUpstream = true;
    } else if (arg === '--apply-pins') {
      applyPins = true;
    } else if (arg === '--shadow-canary') {
      shadowCanary = true;
    } else if (arg === '--cas-dir' && argv[i + 1]) {
      casDir = argv[++i];
    } else if (arg === '--out' && argv[i + 1]) {
      outFile = argv[++i];
    } else if (arg === '--out-dir' && argv[i + 1]) {
      outDir = argv[++i];
    } else if (arg === '--ecosystem' && argv[i + 1]) {
      const rawInput = argv[++i];
      const normalized = (ECOSYSTEM_ALIASES[rawInput.toLowerCase()] ?? rawInput) as HoloCiLockCompatEcosystem;
      if (!VALID_ECOSYSTEMS.has(normalized)) {
        throw new Error(
          `Unknown ecosystem "${rawInput}". Expected one of: npm, cargo, uv, go, vcpkg, winget, apt, composer, rubygems, all (aliases: php, ruby, bundler).`,
        );
      }
      ecosystem = normalized;
    } else if (arg === '--max-lock' && argv[i + 1]) {
      maxLockPath = argv[++i];
    } else if (arg === '--cwd' && argv[i + 1]) {
      cwd = resolve(argv[++i]);
    } else if (arg === '--min-score' && argv[i + 1]) {
      const rawScore = argv[++i];
      const parsedScore = Number(rawScore);
      if (!Number.isFinite(parsedScore) || parsedScore < 0 || parsedScore > 100) {
        throw new Error(`Invalid --min-score "${rawScore}" (expected number between 0 and 100)`);
      }
      minScore = parsedScore;
    } else if (arg === '--force') {
      force = true;
    } else if (arg === '--name' && argv[i + 1]) {
      name = argv[++i];
    } else if (arg === '--kind' && argv[i + 1]) {
      kind = argv[++i] as HoloCiKind;
    } else if (arg === '--repo' && argv[i + 1]) {
      repo = argv[++i];
    } else if (arg === '--mode' && argv[i + 1]) {
      const rawMode = argv[++i];
      if (rawMode !== 'fail-fast' && rawMode !== 'exhaust') {
        throw new Error(`Invalid --mode "${rawMode}" (expected "fail-fast" or "exhaust")`);
      }
      mode = rawMode;
    } else if (arg === '--telemetry-out' && argv[i + 1]) {
      telemetryOutPath = argv[++i];
    } else if (arg === '--concurrency' && argv[i + 1]) {
      const rawConc = argv[++i];
      const parsedConc = Number(rawConc);
      if (!Number.isInteger(parsedConc) || parsedConc <= 0) {
        throw new Error(`Invalid --concurrency "${rawConc}" (expected positive integer)`);
      }
      concurrency = parsedConc;
    } else if (arg === '--only' && argv[i + 1]) {
      onlyIds = argv[++i]
        .split(',')
        .map((id) => id.trim())
        .filter((id) => id.length > 0);
    } else if (!arg.startsWith('-') && !phaseExplicit) {
      if (!VALID_PHASES.has(arg as HoloCiPhase)) {
        throw new Error(`Unknown phase "${arg}". Run with --help to see valid phases.`);
      }
      phase = arg as HoloCiPhase;
      phaseExplicit = true;
    } else {
      throw new Error(`Unknown or incomplete argument "${arg}"`);
    }
  }

  return {
    phase,
    help,
    configPath,
    ...(boundaryPath ? { boundaryPath } : {}),
    ...(receiptPath ? { receiptPath } : {}),
    emitSummary,
    ...(summaryFile ? { summaryFile } : {}),
    json,
    ...(version ? { version } : {}),
    ...(packagePath ? { packagePath } : {}),
    dryRun,
    check,
    fix,
    ...(fleetRoot ? { fleetRoot } : {}),
    ...(timeoutMinutes !== undefined ? { timeoutMinutes } : {}),
    ...(retentionDays !== undefined ? { retentionDays } : {}),
    ...(owner ? { owner } : {}),
    ...(repos ? { repos } : {}),
    ...(hours !== undefined ? { hours } : {}),
    ...(slowSec !== undefined ? { slowSec } : {}),
    fetchUpstream,
    applyPins,
    shadowCanary,
    ...(casDir ? { casDir } : {}),
    ...(outDir ? { outDir } : {}),
    ...(outFile ? { outFile } : {}),
    ...(ecosystem ? { ecosystem } : {}),
    cwd,
    ...(minScore !== undefined ? { minScore } : {}),
    force,
    ...(name ? { name } : {}),
    ...(kind ? { kind } : {}),
    ...(maxLockPath ? { maxLockPath } : {}),
    ...(repo ? { repo } : {}),
    ...(mode ? { mode } : {}),
    ...(telemetryOutPath ? { telemetryOutPath } : {}),
    ...(concurrency !== undefined ? { concurrency } : {}),
    ...(onlyIds ? { onlyIds } : {}),
  };
}

function initManifest(opts: ParsedCliArgs): HoloCiManifest {
  const target = resolve(opts.cwd, opts.configPath);
  if (existsSync(target) && !opts.force) {
    throw new Error(`${opts.configPath} already exists at ${target} (pass --force to overwrite)`);
  }

  let detectedName = opts.name;
  if (!detectedName) {
    const pkgPath = resolve(opts.cwd, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { name?: string };
        if (pkg.name) detectedName = pkg.name;
      } catch {
        // ignore invalid package.json during init
      }
    }
  }

  const manifest: HoloCiManifest = {
    schema: HOLO_CI_SCHEMA,
    name: detectedName ?? basename(opts.cwd),
    kind: opts.kind ?? 'app',
    tests: [],
    nativeGates: [],
    docs: ['README.md'],
    guards: {
      zeroGhost: true,
      zeroCasV1: true,
      zeroHttpIpc: true,
      noBrokenBadges: true,
    },
  };

  writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

export async function executeCli(argv: string[]): Promise<{ exitCode: number; receipt?: HoloCiReceipt }> {
  const opts = parseCliArgs(argv);
  if (opts.help) {
    process.stdout.write(getHelpText());
    return { exitCode: 0 };
  }

  const start = Date.now();
  let receipt: HoloCiReceipt;

  if (opts.phase === 'init') {
    const manifest = initManifest(opts);
    receipt = buildReceipt({
      manifest,
      phase: 'init',
      ok: true,
      durationMs: Date.now() - start,
    });
  } else if (opts.phase === 'lock-compat') {
    const ecosystem = opts.ecosystem ?? 'npm';
    const resolvedOutDir = opts.outDir ?? (ecosystem !== 'npm' ? opts.outFile : undefined);
    const resolvedOutFile = ecosystem === 'npm' ? opts.outFile : undefined;
    await tryLoadHoloPmLockfileHelper(opts.cwd);
    const lockCompat = runLockCompat({
      cwd: opts.cwd,
      ecosystem,
      outFile: resolvedOutFile,
      outDir: resolvedOutDir,
      dryRun: opts.dryRun,
      maxLockPath: opts.maxLockPath,
    });
    const configFullPath = resolve(opts.cwd, opts.configPath);
    const manifest: HoloCiManifest = existsSync(configFullPath)
      ? loadManifest(opts.configPath, opts.cwd)
      : {
          schema: HOLO_CI_SCHEMA,
          name: lockCompat.name,
          kind: opts.kind ?? 'app',
        };
    receipt = buildReceipt({
      manifest,
      phase: 'lock-compat',
      ok: lockCompat.ok,
      durationMs: Date.now() - start,
      lockCompat,
    });
  } else if (opts.phase === 'boundary-audit') {
    const boundaryAudit = runBoundaryAudit({
      cwd: opts.cwd,
      boundaryPath: opts.boundaryPath,
      configPath: opts.configPath,
    });
    const configFullPath = resolve(opts.cwd, opts.configPath);
    const manifest: HoloCiManifest = existsSync(configFullPath)
      ? loadManifest(opts.configPath, opts.cwd)
      : {
          schema: HOLO_CI_SCHEMA,
          name: opts.name ?? basename(opts.cwd),
          kind: opts.kind ?? 'app',
        };
    const minScoreOk = opts.minScore === undefined || boundaryAudit.score >= opts.minScore;
    const errors = minScoreOk
      ? undefined
      : [`Boundary audit score ${boundaryAudit.score}/100 is below minimum required ${opts.minScore}/100`];
    receipt = buildReceipt({
      manifest,
      phase: 'boundary-audit',
      ok: boundaryAudit.ok && minScoreOk,
      durationMs: Date.now() - start,
      boundaryAudit,
      ...(errors ? { errors } : {}),
    });
  } else if (opts.phase === 'wf-harden') {
    const configFullPath = resolve(opts.cwd, opts.configPath);
    const manifest: HoloCiManifest = existsSync(configFullPath)
      ? loadManifest(opts.configPath, opts.cwd)
      : {
          schema: HOLO_CI_SCHEMA,
          name: opts.name ?? basename(opts.fleetRoot ?? opts.cwd),
          kind: opts.kind ?? 'app',
        };
    if (opts.fleetRoot) {
      const wfHardenFleet = runFleetWorkflowHardening({
        mirrorRoot: opts.fleetRoot,
        check: opts.check,
        fix: opts.fix,
        defaultTimeoutMinutes: opts.timeoutMinutes,
        defaultRetentionDays: opts.retentionDays,
      });
      receipt = buildReceipt({
        manifest,
        phase: 'wf-harden',
        ok: wfHardenFleet.ok,
        durationMs: Date.now() - start,
        wfHardenFleet,
      });
    } else {
      const wfHarden = hardenWorkflowsInDir(opts.cwd, {
        fix: opts.fix,
        defaultTimeoutMinutes: opts.timeoutMinutes,
        defaultRetentionDays: opts.retentionDays,
      });
      receipt = buildReceipt({
        manifest,
        phase: 'wf-harden',
        ok: wfHarden.ok,
        durationMs: Date.now() - start,
        wfHarden,
      });
    }
  } else if (opts.phase === 'fleet-forensics') {
    const fleetForensics = await collectFleetForensics({
      owner: opts.owner,
      repos: opts.repos,
      hours: opts.hours,
      slowThresholdSec: opts.slowSec,
      concurrency: opts.concurrency,
    });
    const configFullPath = resolve(opts.cwd, opts.configPath);
    const manifest: HoloCiManifest = existsSync(configFullPath)
      ? loadManifest(opts.configPath, opts.cwd)
      : {
          schema: HOLO_CI_SCHEMA,
          name: opts.name ?? fleetForensics.owner,
          kind: opts.kind ?? 'control-plane',
        };
    receipt = buildReceipt({
      manifest,
      phase: 'fleet-forensics',
      ok: fleetForensics.ok,
      durationMs: Date.now() - start,
      fleetForensics,
    });
  } else if (opts.phase === 'audit-stack') {
    const configFullPath = resolve(opts.cwd, opts.configPath);
    const manifest: HoloCiManifest = existsSync(configFullPath)
      ? loadManifest(opts.configPath, opts.cwd)
      : {
          schema: HOLO_CI_SCHEMA,
          name: opts.repo ?? opts.name ?? basename(opts.cwd),
          kind: opts.kind ?? 'app',
        };
    const registry = registerBuiltinHoloCiAudits(createAuditStackRegistry());
    const auditStack = await registry.run({
      cwd: opts.cwd,
      repo: opts.repo ?? manifest.name,
      mode: opts.mode ?? 'fail-fast',
      ...(opts.onlyIds ? { onlyIds: opts.onlyIds } : {}),
      ...(opts.concurrency !== undefined ? { concurrency: opts.concurrency } : {}),
      ...(opts.telemetryOutPath ? { telemetryOutPath: opts.telemetryOutPath } : {}),
      ...(opts.outFile ? { pushOutPath: opts.outFile } : {}),
    });
    receipt = buildReceipt({
      manifest,
      phase: 'audit-stack',
      ok: auditStack.ok,
      durationMs: Date.now() - start,
      auditStack,
    });
  } else {
    const manifest = loadManifest(opts.configPath, opts.cwd);
    if (opts.phase === 'verify') {
      const verify = runVerify(manifest, { cwd: opts.cwd });
      receipt = buildReceipt({
        manifest,
        phase: 'verify',
        ok: verify.ok,
        durationMs: Date.now() - start,
        verify,
      });
    } else if (opts.phase === 'sync') {
      const sync = runSync(manifest, { cwd: opts.cwd });
      receipt = buildReceipt({
        manifest,
        phase: 'sync',
        ok: sync.ok,
        durationMs: Date.now() - start,
        sync,
      });
    } else if (opts.phase === 'bump') {
      const bump = await runBumpAsync(manifest, {
        cwd: opts.cwd,
        version: opts.version,
        packagePath: opts.packagePath,
        dryRun: opts.dryRun,
        fetchUpstream: opts.fetchUpstream,
        applyPins: opts.applyPins,
        shadowCanary: opts.shadowCanary,
        configPath: opts.configPath,
      });
      receipt = buildReceipt({
        manifest,
        phase: 'bump',
        ok: bump.ok,
        durationMs: Date.now() - start,
        bump,
      });
    } else if (opts.phase === 'pack') {
      const pack = runPack(manifest, {
        cwd: opts.cwd,
        outDir: opts.outDir ?? opts.outFile,
        casDir: opts.casDir,
      });
      receipt = buildReceipt({
        manifest,
        phase: 'pack',
        ok: pack.ok,
        durationMs: Date.now() - start,
        pack,
      });
    } else if (opts.phase === 'maintain') {
      const maintain = await runMaintain(manifest, { cwd: opts.cwd });
      receipt = buildReceipt({
        manifest,
        phase: 'maintain',
        ok: maintain.ok,
        durationMs: Date.now() - start,
        maintain,
      });
    } else {
      // telemetry phase: runs lightweight verify (skipping test commands) to record repo health
      const verify = runVerify(manifest, { cwd: opts.cwd, skipTests: true, skipGates: true });
      receipt = buildReceipt({
        manifest,
        phase: 'telemetry',
        ok: verify.ok,
        durationMs: Date.now() - start,
        verify,
      });
    }
  }

  if (opts.receiptPath || opts.emitSummary) {
    emitTelemetry(receipt, {
      cwd: opts.cwd,
      receiptPath: opts.receiptPath,
      emitSummary: opts.emitSummary,
      summaryPath: opts.summaryFile,
    });
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } else {
    const tag = receipt.ok ? 'PASS' : 'FAIL';
    process.stdout.write(
      `[holo-ci] ${receipt.name} (${receipt.phase}) -> ${tag} (${receipt.durationMs} ms)\n`,
    );
  }

  return { exitCode: receipt.ok ? 0 : 1, receipt };
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  executeCli(process.argv.slice(2))
    .then(({ exitCode }) => {
      process.exitCode = exitCode;
    })
    .catch((err) => {
      process.stderr.write(`[holo-ci] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    });
}
