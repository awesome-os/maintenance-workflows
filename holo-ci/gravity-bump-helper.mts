#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export type GravityBuildRole = 'fast-lib' | 'incremental-bin';

export interface GravityBuildTelemetry {
  schema: 'awesome-os.gravity-build-telemetry.v1';
  abiMagic: '0x33564742';
  generatedAt: string;
  kind: string;
  role: GravityBuildRole;
  crate: string;
  assetPrefix: string;
  os: string;
  osTag: string;
  target: string;
  cacheHit: boolean;
  buildDurationSec: number;
  totalDurationSec: number;
  diskBeforeMb: number;
  diskAfterMb: number;
  cpuCores: number;
  artifact: string;
  bytes: number;
  sha512: string;
}

export interface RunGravityBuildOptions {
  cwd?: string;
  role: GravityBuildRole;
  kind: string;
  crate: string;
  assetPrefix: string;
  os: string;
  osTag: string;
  target: string;
  ext: string;
  cacheHit?: boolean;
  execFn?: typeof execFileSync;
  env?: NodeJS.ProcessEnv;
}

export interface CasManifestCheckResult {
  ok: boolean;
  assetsChecked: number;
  telemetryChecked: number;
  errors: string[];
}

export interface PublishGravityReleaseOptions {
  distDir?: string;
  tag: string;
  repo: string;
  assetPrefix: string;
  execFn?: typeof execFileSync;
}

function getDiskFreeMb(cwd: string, execFn: typeof execFileSync): number {
  if (process.platform === 'win32') return 0;
  try {
    const out = String(execFn('df', ['-Pm', cwd], { encoding: 'utf8', shell: false }) ?? '');
    const lines = out.trim().split(/\r?\n/);
    if (lines.length >= 2) {
      const cols = lines[1].trim().split(/\s+/);
      const val = Number(cols[3]);
      if (Number.isFinite(val)) return val;
    }
  } catch {
    // ignore on restricted environments
  }
  return 0;
}

export function normalizeArtifactExt(ext: string): string {
  if (!ext) return '';
  return ext.startsWith('.') ? ext : `.${ext}`;
}

export function findBuiltArtifact(
  releaseDir: string,
  role: GravityBuildRole,
  crate: string,
  ext: string,
): string {
  const normExt = normalizeArtifactExt(ext);
  if (role === 'incremental-bin') {
    const binPath = join(releaseDir, `${crate}${normExt}`);
    if (!existsSync(binPath)) {
      throw new Error(`Built binary not found at ${binPath}`);
    }
    return binPath;
  }

  if (!existsSync(releaseDir)) {
    throw new Error(`Release directory not found: ${releaseDir}`);
  }
  const candidates = readdirSync(releaseDir, { withFileTypes: true })
    .filter((e) => e.isFile() && (!normExt || e.name.endsWith(normExt)))
    .map((e) => e.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  if (candidates.length === 0) {
    throw new Error(`No *${normExt} artifact found in ${releaseDir}`);
  }
  return join(releaseDir, candidates[0]);
}

export function runGravityBuild(options: RunGravityBuildOptions): GravityBuildTelemetry {
  const cwd = options.cwd ?? process.cwd();
  const execFn = options.execFn ?? execFileSync;
  const jobStartSec = Math.floor(Date.now() / 1000);
  const diskBeforeMb = getDiskFreeMb(cwd, execFn);
  const cpuCores = Math.max(1, cpus().length || 2);

  const cargoEnv: NodeJS.ProcessEnv = {
    ...(options.env ?? process.env),
    CARGO_INCREMENTAL: (options.env ?? process.env).CARGO_INCREMENTAL ?? '1',
    CARGO_PROFILE_RELEASE_LTO: (options.env ?? process.env).CARGO_PROFILE_RELEASE_LTO ?? 'thin',
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS: (options.env ?? process.env).CARGO_PROFILE_RELEASE_CODEGEN_UNITS ?? '16',
    CARGO_PROFILE_RELEASE_STRIP: (options.env ?? process.env).CARGO_PROFILE_RELEASE_STRIP ?? 'symbols',
  };

  const cargoArgs =
    options.role === 'fast-lib'
      ? ['build', '--release', '-p', options.crate, '--target', options.target]
      : ['build', '--release', '--bin', options.crate, '--target', options.target];

  const buildStartSec = Math.floor(Date.now() / 1000);
  execFn('cargo', cargoArgs, { cwd, stdio: 'inherit', env: cargoEnv, shell: false });
  const buildEndSec = Math.floor(Date.now() / 1000);

  const distDir = resolve(cwd, 'dist');
  mkdirSync(distDir, { recursive: true });

  const releaseDir = resolve(cwd, 'target', options.target, 'release');
  const builtPath = findBuiltArtifact(releaseDir, options.role, options.crate, options.ext);
  const normExt = normalizeArtifactExt(options.ext);
  const outName = `${options.assetPrefix}-${options.osTag}${normExt}`;
  const outPath = join(distDir, outName);

  copyFileSync(builtPath, outPath);
  const buf = readFileSync(outPath);
  const sha512 = createHash('sha512').update(buf).digest('hex');
  writeFileSync(`${outPath}.sha512`, `${sha512}  dist/${outName}\n`, 'utf8');

  const nowSec = Math.floor(Date.now() / 1000);
  const diskAfterMb = getDiskFreeMb(cwd, execFn);

  const telemetry: GravityBuildTelemetry = {
    schema: 'awesome-os.gravity-build-telemetry.v1',
    abiMagic: '0x33564742',
    generatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    kind: options.kind,
    role: options.role,
    crate: options.crate,
    assetPrefix: options.assetPrefix,
    os: options.os,
    osTag: options.osTag,
    target: options.target,
    cacheHit: Boolean(options.cacheHit),
    buildDurationSec: Math.max(0, buildEndSec - buildStartSec),
    totalDurationSec: Math.max(0, nowSec - jobStartSec),
    diskBeforeMb,
    diskAfterMb,
    cpuCores,
    artifact: outName,
    bytes: statSync(outPath).size,
    sha512,
  };

  writeFileSync(
    join(distDir, `gravity-build-telemetry-${options.osTag}.json`),
    `${JSON.stringify(telemetry, null, 2)}\n`,
    'utf8',
  );

  return telemetry;
}

export function generateChecksums(distDir: string): { sha256File: string; sha512File: string; files: string[] } {
  const entries = readdirSync(distDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name !== 'SHA256SUMS.txt' && e.name !== 'SHA512SUMS.txt')
    .map((e) => e.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const sha256Lines: string[] = [];
  const sha512Lines: string[] = [];

  for (const name of entries) {
    const buf = readFileSync(join(distDir, name));
    const h256 = createHash('sha256').update(buf).digest('hex');
    const h512 = createHash('sha512').update(buf).digest('hex');
    sha256Lines.push(`${h256}  ${name}`);
    sha512Lines.push(`${h512}  ${name}`);
  }

  const sha256File = join(distDir, 'SHA256SUMS.txt');
  const sha512File = join(distDir, 'SHA512SUMS.txt');
  writeFileSync(sha256File, sha256Lines.length > 0 ? `${sha256Lines.join('\n')}\n` : '', 'utf8');
  writeFileSync(sha512File, sha512Lines.length > 0 ? `${sha512Lines.join('\n')}\n` : '', 'utf8');

  return { sha256File, sha512File, files: [...entries, 'SHA256SUMS.txt', 'SHA512SUMS.txt'] };
}

export function verifyCasManifest(distDir: string): CasManifestCheckResult {
  const errors: string[] = [];
  let assetsChecked = 0;
  let telemetryChecked = 0;

  if (!existsSync(distDir)) {
    return { ok: false, assetsChecked: 0, telemetryChecked: 0, errors: [`Missing dist directory: ${distDir}`] };
  }

  const files = readdirSync(distDir, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => e.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  for (const name of files) {
    if (name.endsWith('.sha512')) {
      const targetName = name.slice(0, -'.sha512'.length);
      const targetPath = join(distDir, targetName);
      if (!existsSync(targetPath)) {
        errors.push(`Missing staged asset for checksum file ${name}`);
        continue;
      }
      const expected = readFileSync(join(distDir, name), 'utf8').trim().split(/\s+/)[0]?.toLowerCase() ?? '';
      const actual = createHash('sha512').update(readFileSync(targetPath)).digest('hex');
      if (!expected || expected !== actual) {
        errors.push(`SHA-512 mismatch for ${targetName}`);
      } else {
        assetsChecked++;
      }
    } else if (/^gravity-build-telemetry-.*\.json$/.test(name)) {
      try {
        const parsed = JSON.parse(readFileSync(join(distDir, name), 'utf8')) as Partial<GravityBuildTelemetry>;
        if (parsed.schema !== 'awesome-os.gravity-build-telemetry.v1' || parsed.abiMagic !== '0x33564742') {
          errors.push(`Invalid telemetry schema/abiMagic in ${name}`);
        } else {
          telemetryChecked++;
        }
      } catch (err) {
        errors.push(`Malformed telemetry JSON ${name}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  return { ok: errors.length === 0, assetsChecked, telemetryChecked, errors };
}

export function publishGravityRelease(options: PublishGravityReleaseOptions): void {
  const distDir = resolve(options.distDir ?? 'dist');
  const execFn = options.execFn ?? execFileSync;

  const { files } = generateChecksums(distDir);
  const casCheck = verifyCasManifest(distDir);
  if (!casCheck.ok) {
    throw new Error(`CAS manifest verification failed: ${casCheck.errors.join('; ')}`);
  }

  let releaseExists = false;
  try {
    execFn('gh', ['release', 'view', options.tag, '-R', options.repo], {
      cwd: distDir,
      stdio: 'ignore',
      shell: false,
    });
    releaseExists = true;
  } catch {
    releaseExists = false;
  }

  if (releaseExists) {
    execFn('gh', ['release', 'upload', options.tag, ...files, '--clobber', '-R', options.repo], {
      cwd: distDir,
      stdio: 'inherit',
      shell: false,
    });
  } else {
    execFn(
      'gh',
      [
        'release',
        'create',
        options.tag,
        ...files,
        '-R',
        options.repo,
        '--title',
        `${options.tag} — ${options.assetPrefix} (Damped Gravity CAS v11)`,
        '--notes',
        'Built incrementally via awesome-os/maintenance-workflows Damped Gravity CAS v11 pipeline (thin LTO + independent C-ABI lib stamping).',
      ],
      {
        cwd: distDir,
        stdio: 'inherit',
        shell: false,
      },
    );
  }
}

function main(argv: string[]): void {
  const subcommand = argv[0] ?? 'build';
  if (subcommand === 'build') {
    const role = (argv[1] || process.env.GRAVITY_ROLE || 'fast-lib') as GravityBuildRole;
    runGravityBuild({
      role,
      kind: process.env.GRAVITY_KIND || 'rust-lib-and-bin',
      crate: process.env.GRAVITY_CRATE || '',
      assetPrefix: process.env.GRAVITY_ASSET_PREFIX || '',
      os: process.env.GRAVITY_OS || '',
      osTag: process.env.GRAVITY_OS_TAG || '',
      target: process.env.GRAVITY_TARGET || '',
      ext: process.env.GRAVITY_EXT || '',
      cacheHit: process.env.GRAVITY_CACHE_HIT === 'true',
    });
    return;
  }

  if (subcommand === 'publish') {
    publishGravityRelease({
      distDir: process.env.GRAVITY_DIST_DIR || 'dist',
      tag: process.env.GITHUB_REF_NAME || '',
      repo: process.env.GITHUB_REPOSITORY || '',
      assetPrefix: process.env.GRAVITY_ASSET_PREFIX || '',
    });
    return;
  }

  throw new Error(`Unknown gravity-bump-helper subcommand "${basename(subcommand)}"`);
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`[gravity-bump-helper] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}
