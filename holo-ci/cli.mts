import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBump } from './bump.mts';
import { runLockCompat } from './lock-compat.mts';
import { runMaintain } from './maintain.mts';
import { runPack } from './pack.mts';
import {
  HOLO_CI_SCHEMA,
  loadManifest,
  type HoloCiKind,
  type HoloCiManifest,
  type HoloCiPhase,
  type HoloCiReceipt,
} from './schema.mts';
import { runSync } from './sync.mts';
import { buildReceipt, emitTelemetry } from './telemetry.mts';
import { runVerify } from './verify.mts';

export interface ParsedCliArgs {
  phase: HoloCiPhase;
  help: boolean;
  configPath: string;
  receiptPath?: string;
  emitSummary: boolean;
  summaryFile?: string;
  json: boolean;
  version?: string;
  packagePath?: string;
  dryRun: boolean;
  outDir?: string;
  cwd: string;
  force: boolean;
  name?: string;
  kind?: HoloCiKind;
  maxLockPath?: string;
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
]);

export function getHelpText(): string {
  return [
    'holo-ci — Zero-dependency Awesome-OS CI/CD & CAS v11 runtime',
    '',
    'Usage:',
    '  node holo-ci/cli.mts <phase> [options]',
    '',
    'Phases:',
    '  verify       Run tests, nativeGates, doc checks, and zeroGhost/zeroCasV1/zeroHttpIpc guards',
    '  sync         Compare recursive SHA-256 syncPairs and audit git working-tree status',
    '  bump         Check upstream semver pins (pinned >= upstream) and bump package.json (--version)',
    '  pack         Generate deterministic holo-v11-manifest.json & SHA512SUMS.txt with dedup stats',
    '  telemetry    Emit holo-ci.receipt.v1 JSON/NDJSON and optional GitHub Step Summary',
    '  maintain     Verify clean-box HTTP 200 endpoints, SHA-512 bundles, and Ed25519 signatures',
    '  init         Scaffold a starter holo-ci.json manifest in the target directory',
    '  lock-compat  Synthesize deterministic lockfileVersion: 3 package-lock.json without mutating node_modules',
    '',
    'Options:',
    '  --config <path>        Path to holo-ci.json (default: holo-ci.json)',
    '  --receipt <path>       Write holo-ci.receipt.v1 JSON or append NDJSON line',
    '  --emit-summary         Append Markdown summary to $GITHUB_STEP_SUMMARY (or --summary-file)',
    '  --summary-file <path>  Explicit Markdown summary path override',
    '  --json                 Print receipt JSON to stdout',
    '  --version <X.Y.Z>      Target semver for `bump`',
    '  --package <path>       Path to package.json for `bump` (default: package.json)',
    '  --dry-run              Preview `bump` or `lock-compat` without writing files',
    '  --out <path>           Output directory for `pack` or output lockfile for `lock-compat` (default: package-lock.json)',
    '  --max-lock <path>      Optional max-version-lock.json override file for `lock-compat`',
    '  --cwd <dir>            Working directory override',
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
  let receiptPath: string | undefined;
  let emitSummary = false;
  let summaryFile: string | undefined;
  let json = false;
  let version: string | undefined;
  let packagePath: string | undefined;
  let dryRun = false;
  let outDir: string | undefined;
  let cwd = process.cwd();
  let force = false;
  let name: string | undefined;
  let kind: HoloCiKind | undefined;
  let maxLockPath: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--config' && argv[i + 1]) {
      configPath = argv[++i];
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
    } else if (arg === '--out' && argv[i + 1]) {
      outDir = argv[++i];
    } else if (arg === '--max-lock' && argv[i + 1]) {
      maxLockPath = argv[++i];
    } else if (arg === '--cwd' && argv[i + 1]) {
      cwd = resolve(argv[++i]);
    } else if (arg === '--force') {
      force = true;
    } else if (arg === '--name' && argv[i + 1]) {
      name = argv[++i];
    } else if (arg === '--kind' && argv[i + 1]) {
      kind = argv[++i] as HoloCiKind;
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
    ...(receiptPath ? { receiptPath } : {}),
    emitSummary,
    ...(summaryFile ? { summaryFile } : {}),
    json,
    ...(version ? { version } : {}),
    ...(packagePath ? { packagePath } : {}),
    dryRun,
    ...(outDir ? { outDir } : {}),
    cwd,
    force,
    ...(name ? { name } : {}),
    ...(kind ? { kind } : {}),
    ...(maxLockPath ? { maxLockPath } : {}),
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
    const lockCompat = runLockCompat({
      cwd: opts.cwd,
      outFile: opts.outDir,
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
      const bump = runBump(manifest, {
        cwd: opts.cwd,
        version: opts.version,
        packagePath: opts.packagePath,
        dryRun: opts.dryRun,
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
        outDir: opts.outDir,
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
