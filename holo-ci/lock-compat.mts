import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_LOCKFILE_VERSION,
  type HoloCiLockCompatArtifact,
  type HoloCiLockCompatEcosystem,
  type HoloCiLockCompatPackageEntry,
  type HoloCiLockCompatResult,
  type HoloCiLockCompatSingleEcosystem,
  type HoloCiLockfileV3,
} from './schema.mts';

export interface HoloPmLockfileWriteResult {
  readonly written: boolean;
  readonly action: 'created' | 'upgraded' | 'kept-higher' | 'updated';
  readonly existingVersion: number;
  readonly resultingVersion: number;
}

export interface HoloPmLockfileHelper {
  readonly source: 'holo-pm' | 'inline-fallback';
  readLockfileVersion(filePath: string): number;
  writeOrUpgradeLockfile(
    filePath: string,
    content: string,
    nextVersion?: number,
  ): HoloPmLockfileWriteResult;
}

export function readLockfileVersion(filePath: string): number {
  if (!existsSync(filePath)) return 0;
  try {
    const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as { lockfileVersion?: unknown };
    if (
      parsed &&
      typeof parsed === 'object' &&
      typeof parsed.lockfileVersion === 'number' &&
      Number.isFinite(parsed.lockfileVersion) &&
      parsed.lockfileVersion >= 0
    ) {
      return parsed.lockfileVersion;
    }
    return 0;
  } catch {
    return 0;
  }
}

export function writeOrUpgradeLockfile(
  filePath: string,
  content: string,
  nextVersion: number = HOLO_LOCKFILE_VERSION,
): HoloPmLockfileWriteResult {
  const exists = existsSync(filePath);
  const existingVersion = exists ? readLockfileVersion(filePath) : 0;

  if (exists && existingVersion > nextVersion) {
    return {
      written: false,
      action: 'kept-higher',
      existingVersion,
      resultingVersion: existingVersion,
    };
  }

  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, content, 'utf8');

  const action: HoloPmLockfileWriteResult['action'] = !exists
    ? 'created'
    : existingVersion < nextVersion
      ? 'upgraded'
      : 'updated';

  return {
    written: true,
    action,
    existingVersion,
    resultingVersion: nextVersion,
  };
}

const INLINE_LOCKFILE_HELPER: HoloPmLockfileHelper = {
  source: 'inline-fallback',
  readLockfileVersion,
  writeOrUpgradeLockfile,
};

let cachedHoloPmHelper: HoloPmLockfileHelper | undefined;

function findHoloPmLockfileModule(cwd: string): string | undefined {
  let current = resolve(cwd);
  while (true) {
    const candidate = join(current, 'intersections', 'holo-compiler', 'lockfile.mts');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return undefined;
}

export async function tryLoadHoloPmLockfileHelper(cwd: string): Promise<HoloPmLockfileHelper> {
  const modulePath = findHoloPmLockfileModule(cwd);
  if (modulePath) {
    try {
      const mod = (await import(pathToFileURL(modulePath).href)) as {
        readLockfileVersion?: HoloPmLockfileHelper['readLockfileVersion'];
        writeOrUpgradeLockfile?: HoloPmLockfileHelper['writeOrUpgradeLockfile'];
      };
      if (typeof mod.readLockfileVersion === 'function' && typeof mod.writeOrUpgradeLockfile === 'function') {
        const helper: HoloPmLockfileHelper = {
          source: 'holo-pm',
          readLockfileVersion: mod.readLockfileVersion,
          writeOrUpgradeLockfile: mod.writeOrUpgradeLockfile,
        };
        cachedHoloPmHelper = helper;
        return helper;
      }
    } catch {
      // Fall back to zero-dependency inline helper
    }
  }
  return INLINE_LOCKFILE_HELPER;
}

export interface AptCompatStanzaInput {
  package: string;
  version: string;
  architecture?: string;
  soname?: string;
  provides?: string[];
  v11Sha512?: string;
  description?: string;
}

export interface LockCompatOptions {
  cwd?: string;
  ecosystem?: HoloCiLockCompatEcosystem;
  outFile?: string;
  outDir?: string;
  dryRun?: boolean;
  maxLockPath?: string;
  aptStanzas?: AptCompatStanzaInput[];
}

interface PackageJsonShape {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  workspaces?: string[] | { packages?: string[] };
}

interface PnpmResolvedEntry {
  version: string;
  integrity?: string;
}

interface MaxVersionLockFile {
  libraries?: Array<{
    name?: string;
    v11Name?: string | null;
    maxVersion?: string;
    v11Version?: string | null;
  }>;
  overrides?: Record<string, string>;
  packages?: Record<string, string>;
}

interface PinnedV11CppLib {
  readonly name: string;
  readonly pcName: string;
  readonly defaultVersion: string;
  readonly aptPackage: string;
  readonly aptProvides: string[];
  readonly soname: string;
  readonly wingetId: string;
  readonly libsFlag: string;
  readonly description: string;
}

const PINNED_V11_CPP_LIBS: readonly PinnedV11CppLib[] = [
  {
    name: 'cairo',
    pcName: 'cairo',
    defaultVersion: '1.18.6',
    aptPackage: 'libcairo2',
    aptProvides: ['holo-v11-cairo', 'libcairo-v11'],
    soname: 'libcairo.so.2',
    wingetId: 'AwesomeOS.V11.Cairo',
    libsFlag: '-lcairo',
    description: '2D graphics library (Holo v11 CAS)',
  },
  {
    name: 'curl',
    pcName: 'libcurl',
    defaultVersion: '8.23.0',
    aptPackage: 'libcurl4t64',
    aptProvides: ['libcurl4', 'holo-v11-curl'],
    soname: 'libcurl.so.4',
    wingetId: 'AwesomeOS.V11.Curl',
    libsFlag: '-lcurl',
    description: 'Multipass URL transfer library (Holo v11 CAS)',
  },
  {
    name: 'freetype',
    pcName: 'freetype2',
    defaultVersion: '2.15.0',
    aptPackage: 'libfreetype6',
    aptProvides: ['holo-v11-freetype', 'libfreetype-v11'],
    soname: 'libfreetype.so.6',
    wingetId: 'AwesomeOS.V11.FreeType',
    libsFlag: '-lfreetype',
    description: 'FreeType font rendering engine (Holo v11 CAS)',
  },
  {
    name: 'harfbuzz',
    pcName: 'harfbuzz',
    defaultVersion: '15.2.0',
    aptPackage: 'libharfbuzz0b',
    aptProvides: ['holo-v11-harfbuzz', 'libharfbuzz-v11'],
    soname: 'libharfbuzz.so.0',
    wingetId: 'AwesomeOS.V11.HarfBuzz',
    libsFlag: '-lharfbuzz',
    description: 'OpenType text shaping engine (Holo v11 CAS)',
  },
  {
    name: 'icu4c',
    pcName: 'icu-uc',
    defaultVersion: '79.1',
    aptPackage: 'libicu79',
    aptProvides: ['holo-v11-icu4c', 'libicu-v11'],
    soname: 'libicuuc.so.79',
    wingetId: 'AwesomeOS.V11.ICU4C',
    libsFlag: '-licuuc -licui18n -licudata',
    description: 'International Components for Unicode C/C++ library (Holo v11 CAS)',
  },
  {
    name: 'libgd',
    pcName: 'gdlib',
    defaultVersion: '2.3.3',
    aptPackage: 'libgd3',
    aptProvides: ['holo-v11-libgd', 'libgd-v11'],
    soname: 'libgd.so.3',
    wingetId: 'AwesomeOS.V11.LibGD',
    libsFlag: '-lgd',
    description: 'GD graphics library for dynamic image creation (Holo v11 CAS)',
  },
  {
    name: 'libgit2',
    pcName: 'libgit2',
    defaultVersion: '1.9.7',
    aptPackage: 'libgit2-1.9',
    aptProvides: ['holo-v11-libgit2', 'libgit2-v11'],
    soname: 'libgit2.so.1.9',
    wingetId: 'AwesomeOS.V11.LibGit2',
    libsFlag: '-lgit2',
    description: 'Portable pure-C Git core implementation (Holo v11 CAS)',
  },
  {
    name: 'libpng',
    pcName: 'libpng16',
    defaultVersion: '1.6.59',
    aptPackage: 'libpng16-16t64',
    aptProvides: ['libpng16-16', 'holo-v11-libpng'],
    soname: 'libpng16.so.16',
    wingetId: 'AwesomeOS.V11.LibPNG',
    libsFlag: '-lpng16',
    description: 'Official PNG reference library (Holo v11 CAS)',
  },
  {
    name: 'librdkafka',
    pcName: 'rdkafka',
    defaultVersion: '2.16.0',
    aptPackage: 'librdkafka1',
    aptProvides: ['holo-v11-librdkafka', 'librdkafka-v11'],
    soname: 'librdkafka.so.1',
    wingetId: 'AwesomeOS.V11.LibRdKafka',
    libsFlag: '-lrdkafka',
    description: 'Apache Kafka C/C++ client library (Holo v11 CAS)',
  },
  {
    name: 'libsodium',
    pcName: 'libsodium',
    defaultVersion: '1.0.22',
    aptPackage: 'libsodium23',
    aptProvides: ['holo-v11-libsodium', 'libsodium-v11'],
    soname: 'libsodium.so.23',
    wingetId: 'AwesomeOS.V11.LibSodium',
    libsFlag: '-lsodium',
    description: 'Modern portable cryptography library (Holo v11 CAS)',
  },
  {
    name: 'libvips',
    pcName: 'vips',
    defaultVersion: '8.18.7',
    aptPackage: 'libvips42',
    aptProvides: ['holo-v11-libvips', 'libvips-v11'],
    soname: 'libvips.so.42',
    wingetId: 'AwesomeOS.V11.LibVips',
    libsFlag: '-lvips',
    description: 'Demand-driven image processing library (Holo v11 CAS)',
  },
  {
    name: 'libxml2',
    pcName: 'libxml-2.0',
    defaultVersion: '2.15.4',
    aptPackage: 'libxml2',
    aptProvides: ['holo-v11-libxml2', 'libxml2-v11'],
    soname: 'libxml2.so.2',
    wingetId: 'AwesomeOS.V11.LibXML2',
    libsFlag: '-lxml2',
    description: 'GNOME XML library (Holo v11 CAS)',
  },
  {
    name: 'libxslt',
    pcName: 'libxslt',
    defaultVersion: '1.1.45',
    aptPackage: 'libxslt1.1',
    aptProvides: ['holo-v11-libxslt', 'libxslt-v11'],
    soname: 'libxslt.so.1',
    wingetId: 'AwesomeOS.V11.LibXSLT',
    libsFlag: '-lxslt',
    description: 'XSLT C library developed for GNOME (Holo v11 CAS)',
  },
  {
    name: 'libzip',
    pcName: 'libzip',
    defaultVersion: '1.12.1',
    aptPackage: 'libzip5',
    aptProvides: ['holo-v11-libzip', 'libzip-v11'],
    soname: 'libzip.so.5',
    wingetId: 'AwesomeOS.V11.LibZip',
    libsFlag: '-lzip',
    description: 'C library for reading, creating, and modifying zip archives (Holo v11 CAS)',
  },
  {
    name: 'oniguruma',
    pcName: 'oniguruma',
    defaultVersion: '6.9.10',
    aptPackage: 'libonig5',
    aptProvides: ['holo-v11-oniguruma', 'libonig-v11'],
    soname: 'libonig.so.5',
    wingetId: 'AwesomeOS.V11.Oniguruma',
    libsFlag: '-lonig',
    description: 'Modern regular expressions library (Holo v11 CAS)',
  },
  {
    name: 'openssl',
    pcName: 'openssl',
    defaultVersion: '4.1.0',
    aptPackage: 'libssl3t64',
    aptProvides: ['libssl3', 'holo-v11-openssl'],
    soname: 'libssl.so.3',
    wingetId: 'AwesomeOS.V11.OpenSSL',
    libsFlag: '-lssl -lcrypto',
    description: 'Secure Sockets Layer and cryptography libraries (Holo v11 CAS)',
  },
  {
    name: 'pixman',
    pcName: 'pixman-1',
    defaultVersion: '0.46.4',
    aptPackage: 'libpixman-1-0',
    aptProvides: ['holo-v11-pixman', 'libpixman-v11'],
    soname: 'libpixman-1.so.0',
    wingetId: 'AwesomeOS.V11.Pixman',
    libsFlag: '-lpixman-1',
    description: 'Pixel-manipulation library for X and cairo (Holo v11 CAS)',
  },
  {
    name: 'sqlite',
    pcName: 'sqlite3',
    defaultVersion: '3.54.1',
    aptPackage: 'libsqlite3-0',
    aptProvides: ['holo-v11-sqlite', 'libsqlite3-v11'],
    soname: 'libsqlite3.so.0',
    wingetId: 'AwesomeOS.V11.SQLite',
    libsFlag: '-lsqlite3',
    description: 'Self-contained serverless SQL database engine (Holo v11 CAS)',
  },
  {
    name: 'zlib',
    pcName: 'zlib',
    defaultVersion: '1.4',
    aptPackage: 'zlib1g',
    aptProvides: ['holo-v11-zlib', 'zlib-v11'],
    soname: 'libz.so.1',
    wingetId: 'AwesomeOS.V11.Zlib',
    libsFlag: '-lz',
    description: 'General-purpose lossless data-compression library (Holo v11 CAS)',
  },
  {
    name: 'zstd',
    pcName: 'libzstd',
    defaultVersion: '1.6.0',
    aptPackage: 'libzstd1',
    aptProvides: ['holo-v11-zstd', 'libzstd-v11'],
    soname: 'libzstd.so.1',
    wingetId: 'AwesomeOS.V11.Zstd',
    libsFlag: '-lzstd',
    description: 'Fast lossless compression algorithm (Holo v11 CAS)',
  },
];

const ALL_ECOSYSTEMS: readonly HoloCiLockCompatSingleEcosystem[] = [
  'npm',
  'cargo',
  'uv',
  'go',
  'vcpkg',
  'winget',
  'apt',
  'composer',
  'rubygems',
];

const ELF_SONAME_RE = /^[A-Za-z0-9_+.-]+\.so(?:\.[0-9]+)*$/;

function byteCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sha256Text(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function sha512Text(text: string): string {
  return createHash('sha512').update(text, 'utf8').digest('hex');
}

function sortStringRecord(rec: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!rec) return undefined;
  const keys = Object.keys(rec).sort(byteCompare);
  if (keys.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const key of keys) {
    out[key] = rec[key];
  }
  return out;
}

function unquoteYamlKey(raw: string): string {
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function normalizePnpmVersion(rawVersion: string): string {
  const cleaned = unquoteYamlKey(rawVersion);
  if (cleaned.startsWith('link:') || cleaned.startsWith('workspace:')) {
    return cleaned;
  }
  const parenIdx = cleaned.indexOf('(');
  const withoutPeers = parenIdx === -1 ? cleaned : cleaned.slice(0, parenIdx);
  const atIdx = withoutPeers.lastIndexOf('@');
  if (atIdx > 0) {
    return withoutPeers.slice(atIdx + 1);
  }
  return withoutPeers;
}

function parsePackageSpecKey(rawKey: string): { name: string; version: string } | null {
  const key = unquoteYamlKey(rawKey).replace(/^\//, '');
  const parenIdx = key.indexOf('(');
  const base = parenIdx === -1 ? key : key.slice(0, parenIdx);
  const atIdx = base.lastIndexOf('@');
  if (atIdx <= 0) return null;
  const name = base.slice(0, atIdx);
  const version = base.slice(atIdx + 1);
  if (!name || !version) return null;
  return { name, version };
}

export function parsePnpmLock(pnpmLockText: string): {
  resolved: Map<string, PnpmResolvedEntry>;
  integrityByPkgVersion: Map<string, string>;
} {
  const resolved = new Map<string, PnpmResolvedEntry>();
  const integrityByPkgVersion = new Map<string, string>();
  const lines = pnpmLockText.split(/\r?\n/);

  let topSection = '';
  let currentImporterDep: string | null = null;
  let currentPkgKey: { name: string; version: string } | null = null;

  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;

    const topMatch = /^([A-Za-z0-9_-]+):(?:\s*(.*))?$/.exec(line);
    if (topMatch) {
      topSection = topMatch[1];
      currentImporterDep = null;
      currentPkgKey = null;
      continue;
    }

    if (topSection === 'importers') {
      const sectionMatch = /^\s{4}(dependencies|devDependencies|optionalDependencies):\s*$/.exec(line);
      if (sectionMatch) {
        currentImporterDep = null;
        continue;
      }
      const depMatch = /^\s{6}([^:]+):\s*$/.exec(line);
      if (depMatch) {
        currentImporterDep = unquoteYamlKey(depMatch[1]);
        continue;
      }
      const verMatch = /^\s{8}version:\s*(.+)$/.exec(line);
      if (verMatch && currentImporterDep) {
        const version = normalizePnpmVersion(verMatch[1]);
        if (!version.startsWith('link:') && !version.startsWith('workspace:')) {
          resolved.set(currentImporterDep, { version });
        }
        continue;
      }
    } else if (topSection === 'packages') {
      const pkgHeaderMatch = /^\s{2}([^:]+):\s*$/.exec(line);
      if (pkgHeaderMatch) {
        currentPkgKey = parsePackageSpecKey(pkgHeaderMatch[1]);
        continue;
      }
      if (currentPkgKey) {
        const integrityMatch = /integrity:\s*(sha\d+-[A-Za-z0-9+/=]+)/.exec(line);
        if (integrityMatch) {
          const mapKey = `${currentPkgKey.name}@${currentPkgKey.version}`;
          integrityByPkgVersion.set(mapKey, integrityMatch[1]);
          const existing = resolved.get(currentPkgKey.name);
          if (existing && existing.version === currentPkgKey.version) {
            existing.integrity = integrityMatch[1];
          } else if (!existing) {
            resolved.set(currentPkgKey.name, {
              version: currentPkgKey.version,
              integrity: integrityMatch[1],
            });
          }
        }
      }
    }
  }

  for (const [pkgName, entry] of resolved.entries()) {
    if (!entry.integrity) {
      const integrity = integrityByPkgVersion.get(`${pkgName}@${entry.version}`);
      if (integrity) {
        entry.integrity = integrity;
      }
    }
  }

  return { resolved, integrityByPkgVersion };
}

function loadMaxVersionOverrides(cwd: string, maxLockPath?: string): Map<string, string> {
  const overrides = new Map<string, string>();
  const candidates = maxLockPath
    ? [resolve(cwd, maxLockPath)]
    : [
        resolve(cwd, 'max-version-lock.json'),
        resolve(cwd, 'catalog', 'max-version-lock.json'),
        resolve(cwd, 'reports', 'max-version-lock.json'),
        resolve(cwd, '../t2linux-baseline/catalog/max-version-lock.json'),
        resolve(cwd, '../../t2linux-baseline/catalog/max-version-lock.json'),
      ];

  const found = candidates.find((p) => existsSync(p));
  if (!found) return overrides;

  const parsed = JSON.parse(readFileSync(found, 'utf8')) as MaxVersionLockFile;
  if (Array.isArray(parsed.libraries)) {
    for (const lib of parsed.libraries) {
      const ver = lib.maxVersion ?? lib.v11Version ?? undefined;
      if (!ver) continue;
      if (lib.name) overrides.set(lib.name, ver);
      if (lib.v11Name) overrides.set(lib.v11Name, ver);
    }
  }
  if (parsed.overrides && typeof parsed.overrides === 'object') {
    for (const [k, v] of Object.entries(parsed.overrides)) {
      if (typeof v === 'string' && v.trim().length > 0) overrides.set(k, v.trim());
    }
  }
  if (parsed.packages && typeof parsed.packages === 'object') {
    for (const [k, v] of Object.entries(parsed.packages)) {
      if (typeof v === 'string' && v.trim().length > 0) overrides.set(k, v.trim());
    }
  }
  return overrides;
}

function normalizeDeclaredVersion(range: string): string {
  const trimmed = range.trim();
  if (trimmed.startsWith('npm:')) {
    const atIdx = trimmed.lastIndexOf('@');
    if (atIdx > 4) {
      return trimmed.slice(atIdx + 1).replace(/^[~^>=<\s]+/, '') || '0.0.0';
    }
  }
  const stripped = trimmed.replace(/^[~^>=<\s]+/, '');
  if (!stripped || stripped === '*' || stripped === 'latest' || stripped.startsWith('workspace:')) {
    return '0.0.0';
  }
  return stripped.split(/\s+/)[0] ?? stripped;
}

function resolveWorkspaceDirs(cwd: string, workspacesField: PackageJsonShape['workspaces']): string[] {
  const rawPatterns = Array.isArray(workspacesField)
    ? workspacesField
    : workspacesField && Array.isArray(workspacesField.packages)
      ? workspacesField.packages
      : [];

  const dirs = new Set<string>();
  for (const rawPattern of rawPatterns) {
    const pattern = rawPattern.replace(/\\/g, '/').replace(/\/+$/, '');
    if (!pattern || pattern.startsWith('!')) continue;
    if (pattern.endsWith('/*')) {
      const parentRel = pattern.slice(0, -2);
      const parentAbs = resolve(cwd, parentRel);
      if (!existsSync(parentAbs) || !statSync(parentAbs).isDirectory()) continue;
      const entries = readdirSync(parentAbs, { withFileTypes: true }).sort((a, b) =>
        byteCompare(a.name, b.name),
      );
      for (const entry of entries) {
        if (!entry.isDirectory() || entry.name === 'node_modules') continue;
        const pkgPath = join(parentAbs, entry.name, 'package.json');
        if (existsSync(pkgPath)) {
          dirs.add(join(parentAbs, entry.name));
        }
      }
    } else if (!pattern.includes('*')) {
      const abs = resolve(cwd, pattern);
      if (existsSync(join(abs, 'package.json'))) {
        dirs.add(abs);
      }
    }
  }
  return Array.from(dirs).sort((a, b) => byteCompare(relative(cwd, a), relative(cwd, b)));
}

function emitProjectionFile(
  artifacts: HoloCiLockCompatArtifact[],
  ecosystem: HoloCiLockCompatSingleEcosystem,
  baseOutDir: string,
  targetPath: string,
  content: string,
  dryRun: boolean,
  lockfileVersion?: number,
): HoloCiLockCompatArtifact {
  let written = !dryRun;
  if (!dryRun) {
    if (lockfileVersion !== undefined) {
      const helper = cachedHoloPmHelper ?? INLINE_LOCKFILE_HELPER;
      const writeRes = helper.writeOrUpgradeLockfile(targetPath, content, lockfileVersion);
      written = writeRes.written;
    } else {
      mkdirSync(dirname(targetPath), { recursive: true });
      writeFileSync(targetPath, content, 'utf8');
    }
  }
  const relPath = relative(baseOutDir, targetPath).replace(/\\/g, '/');
  const artifact: HoloCiLockCompatArtifact = {
    ecosystem,
    path: targetPath,
    relPath: relPath || basename(targetPath),
    bytes: Buffer.byteLength(content, 'utf8'),
    sha256: sha256Text(content),
    written,
  };
  artifacts.push(artifact);
  return artifact;
}

function synthesizeNpmLock(
  cwd: string,
  baseOutDir: string,
  explicitOutFile: string | undefined,
  requirePackageJson: boolean,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): {
  rootName: string;
  rootVersion: string;
  outFile: string;
  packageCount: number;
  workspaceCount: number;
  resolvedFromPnpmLock: number;
  resolvedFromMaxLock: number;
  sha256: string;
  lockfile: HoloCiLockfileV3;
} {
  const pkgPath = resolve(cwd, 'package.json');
  const hasPkgJson = existsSync(pkgPath);
  if (requirePackageJson && !hasPkgJson) {
    throw new Error(`package.json not found at ${pkgPath}`);
  }

  const rootPkg: PackageJsonShape = hasPkgJson
    ? (JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJsonShape)
    : { name: basename(cwd), version: '0.0.0' };
  const rootName = rootPkg.name?.trim() || basename(cwd);
  const rootVersion = rootPkg.version?.trim() || '0.0.0';

  const pnpmLockPath = resolve(cwd, 'pnpm-lock.yaml');
  const pnpmParsed = existsSync(pnpmLockPath)
    ? parsePnpmLock(readFileSync(pnpmLockPath, 'utf8'))
    : { resolved: new Map<string, PnpmResolvedEntry>(), integrityByPkgVersion: new Map<string, string>() };

  const workspaceGlobs = Array.isArray(rootPkg.workspaces)
    ? [...rootPkg.workspaces]
    : rootPkg.workspaces && Array.isArray(rootPkg.workspaces.packages)
      ? [...rootPkg.workspaces.packages]
      : undefined;

  const rootDeps = sortStringRecord(rootPkg.dependencies);
  const rootDevDeps = sortStringRecord(rootPkg.devDependencies);

  const packagesUnsorted = new Map<string, HoloCiLockCompatPackageEntry>();
  packagesUnsorted.set('', {
    ...(rootName ? { name: rootName } : {}),
    ...(rootVersion ? { version: rootVersion } : {}),
    ...(workspaceGlobs && workspaceGlobs.length > 0 ? { workspaces: workspaceGlobs } : {}),
    ...(rootDeps ? { dependencies: rootDeps } : {}),
    ...(rootDevDeps ? { devDependencies: rootDevDeps } : {}),
  });

  let resolvedFromPnpmLock = 0;
  let resolvedFromMaxLock = 0;
  const workspaceNames = new Set<string>();

  const registerDependency = (depName: string, declaredRange: string, isDev: boolean): void => {
    if (workspaceNames.has(depName)) return;
    const nodeModulesKey = `node_modules/${depName}`;
    const existing = packagesUnsorted.get(nodeModulesKey);
    if (existing && !isDev && existing.dev) {
      delete existing.dev;
    }
    if (existing) return;

    const maxVer = maxLockOverrides.get(depName);
    const pnpmEntry = pnpmParsed.resolved.get(depName);

    let resolvedVersion = normalizeDeclaredVersion(declaredRange);
    let integrity: string | undefined;

    if (maxVer) {
      resolvedVersion = maxVer;
      resolvedFromMaxLock++;
      integrity = pnpmParsed.integrityByPkgVersion.get(`${depName}@${maxVer}`);
    } else if (pnpmEntry) {
      resolvedVersion = pnpmEntry.version;
      integrity = pnpmEntry.integrity;
      resolvedFromPnpmLock++;
    }

    packagesUnsorted.set(nodeModulesKey, {
      version: resolvedVersion,
      ...(integrity ? { integrity } : {}),
      ...(isDev ? { dev: true } : {}),
      holoCasStore: 'v11',
      zeroCopyNodeModules: true,
    });
  };

  const workspaceDirs = hasPkgJson ? resolveWorkspaceDirs(cwd, rootPkg.workspaces) : [];
  for (const wsDir of workspaceDirs) {
    const wsRel = relative(cwd, wsDir).replace(/\\/g, '/');
    const wsPkg = JSON.parse(readFileSync(join(wsDir, 'package.json'), 'utf8')) as PackageJsonShape;
    const wsName = wsPkg.name?.trim() || basename(wsDir);
    const wsVersion = wsPkg.version?.trim() || '0.0.0';
    const wsDeps = sortStringRecord(wsPkg.dependencies);
    const wsDevDeps = sortStringRecord(wsPkg.devDependencies);
    workspaceNames.add(wsName);

    packagesUnsorted.set(wsRel, {
      name: wsName,
      version: wsVersion,
      ...(wsDeps ? { dependencies: wsDeps } : {}),
      ...(wsDevDeps ? { devDependencies: wsDevDeps } : {}),
    });
    packagesUnsorted.set(`node_modules/${wsName}`, {
      resolved: wsRel,
      link: true,
    });

    if (wsDeps) {
      for (const [depName, range] of Object.entries(wsDeps)) {
        registerDependency(depName, range, false);
      }
    }
    if (wsDevDeps) {
      for (const [depName, range] of Object.entries(wsDevDeps)) {
        registerDependency(depName, range, true);
      }
    }
  }

  if (rootDeps) {
    for (const [depName, range] of Object.entries(rootDeps)) {
      registerDependency(depName, range, false);
    }
  }
  if (rootDevDeps) {
    for (const [depName, range] of Object.entries(rootDevDeps)) {
      registerDependency(depName, range, true);
    }
  }

  const sortedPackages: Record<string, HoloCiLockCompatPackageEntry> = {};
  for (const key of Array.from(packagesUnsorted.keys()).sort(byteCompare)) {
    const entry = packagesUnsorted.get(key);
    if (entry) sortedPackages[key] = entry;
  }

  const lockfile: HoloCiLockfileV3 = {
    name: rootName,
    version: rootVersion,
    lockfileVersion: HOLO_LOCKFILE_VERSION,
    requires: true,
    holoCasStore: 'v11',
    zeroCopyNodeModules: true,
    packages: sortedPackages,
  };

  const serialized = `${JSON.stringify(lockfile, null, 2)}\n`;
  const outFile = explicitOutFile ? resolve(cwd, explicitOutFile) : resolve(baseOutDir, 'package-lock.json');
  const artifact = emitProjectionFile(
    artifacts,
    'npm',
    baseOutDir,
    outFile,
    serialized,
    dryRun,
    HOLO_LOCKFILE_VERSION,
  );

  return {
    rootName,
    rootVersion,
    outFile,
    packageCount: Object.keys(sortedPackages).length,
    workspaceCount: workspaceDirs.length,
    resolvedFromPnpmLock,
    resolvedFromMaxLock,
    sha256: artifact.sha256,
    lockfile,
  };
}

function parseCargoDeps(cwd: string, maxLockOverrides: Map<string, string>): Array<{ name: string; version: string }> {
  const crates = new Map<string, string>();
  const cargoTomlPath = resolve(cwd, 'Cargo.toml');
  if (existsSync(cargoTomlPath)) {
    const lines = readFileSync(cargoTomlPath, 'utf8').split(/\r?\n/);
    let inDeps = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      if (trimmed.startsWith('[')) {
        inDeps = /^\[(?:dev-|build-)?dependencies\]$/i.test(trimmed);
        continue;
      }
      if (!inDeps) continue;
      const simple = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/.exec(trimmed);
      if (simple) {
        crates.set(simple[1], simple[2].replace(/^[~^=<>]+/, '') || '0.0.0');
        continue;
      }
      const inlineTable = /^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/.exec(trimmed);
      if (inlineTable) {
        crates.set(inlineTable[1], inlineTable[2].replace(/^[~^=<>]+/, '') || '0.0.0');
      }
    }
  }
  for (const [name, version] of crates.entries()) {
    const overrideVer = maxLockOverrides.get(name);
    if (overrideVer) crates.set(name, overrideVer);
  }
  return Array.from(crates.entries())
    .sort((a, b) => byteCompare(a[0], b[0]))
    .map(([name, version]) => ({ name, version }));
}

function synthesizeCargoCompat(
  cwd: string,
  baseOutDir: string,
  rootName: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const crates = parseCargoDeps(cwd, maxLockOverrides);
  const configToml = [
    '# Generated by holo-ci lock-compat (v11 CAS zero-copy projection)',
    '[source.crates-io]',
    'replace-with = "holo-v11"',
    '',
    '[source.holo-v11]',
    'directory = ".holo-v11/cargo-vendor"',
    '',
    '[net]',
    'offline = true',
    '',
  ].join('\n');

  const compatJson = `${JSON.stringify(
    {
      schema: 'holo-v11.cargo-compat.v1',
      abiMagic: B8G_ABI_MAGIC_V3,
      name: rootName,
      holoCasStore: 'v11',
      source: 'crates-io',
      replaceWith: 'holo-v11',
      vendorDir: '.holo-v11/cargo-vendor',
      zeroHostCargoMutation: true,
      crates: crates.map((c) => ({
        name: c.name,
        version: c.version,
        holoCasStore: 'v11',
        casSha512: sha512Text(`cargo:${c.name}@${c.version}`),
      })),
    },
    null,
    2,
  )}\n`;

  emitProjectionFile(
    artifacts,
    'cargo',
    baseOutDir,
    resolve(baseOutDir, '.cargo', 'config.toml'),
    configToml,
    dryRun,
  );
  emitProjectionFile(
    artifacts,
    'cargo',
    baseOutDir,
    resolve(baseOutDir, 'holo-cargo-compat.json'),
    compatJson,
    dryRun,
  );
  return crates.length;
}

function parsePythonRequirements(cwd: string, maxLockOverrides: Map<string, string>): Array<{ name: string; version: string }> {
  const pkgs = new Map<string, string>();
  const reqPath = resolve(cwd, 'requirements.txt');
  if (existsSync(reqPath)) {
    for (const rawLine of readFileSync(reqPath, 'utf8').split(/\r?\n/)) {
      const line = rawLine.split('#')[0]?.trim() ?? '';
      if (!line || line.startsWith('-')) continue;
      const m = /^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=)?\s*([A-Za-z0-9_.*+-]+)?/.exec(line);
      if (m) {
        const name = m[1].toLowerCase();
        const ver = m[2] && m[2] !== '*' ? m[2] : '0.0.0';
        pkgs.set(name, maxLockOverrides.get(name) ?? ver);
      }
    }
  }
  const pyprojectPath = resolve(cwd, 'pyproject.toml');
  if (existsSync(pyprojectPath)) {
    const text = readFileSync(pyprojectPath, 'utf8');
    const depsBlock = /dependencies\s*=\s*\[([\s\S]*?)\]/.exec(text);
    if (depsBlock) {
      const entries = depsBlock[1].matchAll(/["']([A-Za-z0-9_.-]+)(?:\s*(?:==|>=|~=|<=)\s*([^"'\s,;]+))?[^"']*["']/g);
      for (const m of entries) {
        const name = m[1].toLowerCase();
        if (!pkgs.has(name)) {
          pkgs.set(name, maxLockOverrides.get(name) ?? (m[2] || '0.0.0'));
        }
      }
    }
  }
  return Array.from(pkgs.entries())
    .sort((a, b) => byteCompare(a[0], b[0]))
    .map(([name, version]) => ({ name, version }));
}

function synthesizeUvCompat(
  cwd: string,
  baseOutDir: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const pkgs = parsePythonRequirements(cwd, maxLockOverrides);
  const uvToml = [
    '# Generated by holo-ci lock-compat (v11 CAS zero-copy projection)',
    'link-mode = "hardlink"',
    'cache-dir = ".holo-v11/uv-cache"',
    'offline = true',
    'compile-bytecode = false',
    '',
  ].join('\n');

  const reqLines = [
    '# Generated by holo-ci lock-compat (holo-cas: v11, zero-copy hardlink)',
    ...pkgs.map((p) => `${p.name}==${p.version} # holo-cas: v11`),
    '',
  ].join('\n');

  emitProjectionFile(artifacts, 'uv', baseOutDir, resolve(baseOutDir, 'uv.toml'), uvToml, dryRun);
  emitProjectionFile(
    artifacts,
    'uv',
    baseOutDir,
    resolve(baseOutDir, 'requirements.holo-v11.txt'),
    reqLines,
    dryRun,
  );
  return pkgs.length;
}

function discoverGoModuleDirs(cwd: string): string[] {
  const dirs: string[] = [];
  if (existsSync(resolve(cwd, 'go.mod'))) {
    dirs.push('.');
  }
  const entries = readdirSync(cwd, { withFileTypes: true }).sort((a, b) => byteCompare(a.name, b.name));
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    if (existsSync(join(cwd, entry.name, 'go.mod'))) {
      dirs.push(`./${entry.name}`);
    }
  }
  return dirs.sort(byteCompare);
}

function synthesizeGoCompat(
  cwd: string,
  baseOutDir: string,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const modDirs = discoverGoModuleDirs(cwd);
  const lines = [
    '// Generated by holo-ci lock-compat (v11 CAS zero-copy projection)',
    `// abiMagic: ${B8G_ABI_MAGIC_V3}`,
    '// holoCasStore: v11',
    '// GOPROXY=file:///var/lib/b8g/cas/v11/go-proxy,direct',
    '// GOSUMDB=off',
    '',
    'go 1.24',
  ];
  if (modDirs.length > 0) {
    lines.push('', 'use (');
    for (const d of modDirs) {
      lines.push(`\t${d}`);
    }
    lines.push(')');
  }
  lines.push('');

  emitProjectionFile(artifacts, 'go', baseOutDir, resolve(baseOutDir, 'go.work'), lines.join('\n'), dryRun);
  return modDirs.length;
}

function resolvePinnedCppLibs(maxLockOverrides: Map<string, string>): Array<PinnedV11CppLib & { version: string }> {
  return [...PINNED_V11_CPP_LIBS]
    .sort((a, b) => byteCompare(a.name, b.name))
    .map((lib) => ({
      ...lib,
      version: maxLockOverrides.get(lib.name) ?? lib.defaultVersion,
    }));
}

function synthesizeVcpkgCompat(
  baseOutDir: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const libs = resolvePinnedCppLibs(maxLockOverrides);
  const pinnedLibraries: Record<string, { version: string; pkgConfig: string; soname: string; holoCasStore: 'v11' }> = {};
  for (const lib of libs) {
    pinnedLibraries[lib.name] = {
      version: lib.version,
      pkgConfig: `pkgconfig/${lib.pcName}.pc`,
      soname: lib.soname,
      holoCasStore: 'v11',
    };
  }

  const vcpkgConfig = `${JSON.stringify(
    {
      $schema: 'https://raw.githubusercontent.com/microsoft/vcpkg-tool/main/docs/vcpkg-configuration.schema.json',
      holoCasStore: 'v11',
      abiMagic: B8G_ABI_MAGIC_V3,
      'default-registry': {
        kind: 'filesystem',
        path: '.holo-v11/vcpkg-registry',
        baseline: 'holo-v11-cas',
      },
      'overlay-ports': ['.holo-v11/vcpkg-ports'],
      'overlay-triplets': ['.holo-v11/vcpkg-triplets'],
      pinnedLibraries,
    },
    null,
    2,
  )}\n`;

  emitProjectionFile(
    artifacts,
    'vcpkg',
    baseOutDir,
    resolve(baseOutDir, 'vcpkg-configuration.json'),
    vcpkgConfig,
    dryRun,
  );

  for (const lib of libs) {
    const pcText = [
      'prefix=/var/lib/b8g/cas/v11/sysroot',
      'exec_prefix=${prefix}',
      'libdir=${exec_prefix}/lib',
      'includedir=${prefix}/include',
      '',
      `Name: ${lib.name}`,
      `Description: ${lib.description}`,
      `Version: ${lib.version}`,
      `Libs: -L\${libdir} ${lib.libsFlag}`,
      'Cflags: -I${includedir}',
      'X-Holo-CAS-Store: v11',
      `X-Holo-V11-Lib: ${lib.name}`,
      `X-Holo-ELF-SONAME: ${lib.soname}`,
      '',
    ].join('\n');
    emitProjectionFile(
      artifacts,
      'vcpkg',
      baseOutDir,
      resolve(baseOutDir, 'pkgconfig', `${lib.pcName}.pc`),
      pcText,
      dryRun,
    );
  }
  return libs.length;
}

function synthesizeWingetCompat(
  baseOutDir: string,
  rootName: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const libs = resolvePinnedCppLibs(maxLockOverrides);
  const wingetImport = `${JSON.stringify(
    {
      $schema: 'https://aka.ms/winget-packages.schema.2.0.json',
      WinGetVersion: '1.9.0',
      holoCasStore: 'v11',
      abiMagic: B8G_ABI_MAGIC_V3,
      msiInstallerCount: 0,
      uacElevationRequired: false,
      Sources: [
        {
          SourceDetails: {
            Name: 'holo-v11-cas',
            Type: 'Microsoft.PreIndexed.Package',
            Argument: 'cas://v11/winget',
          },
          Packages: libs.map((lib) => ({
            PackageIdentifier: lib.wingetId,
            Version: lib.version,
            InstallerType: 'portable',
            Scope: 'user',
            HoloCasStore: 'v11',
          })),
        },
      ],
    },
    null,
    2,
  )}\n`;

  const hkcuArpManifest = `${JSON.stringify(
    {
      schema: 'holo-v11.hkcu-arp.v1',
      abiMagic: B8G_ABI_MAGIC_V3,
      workspace: rootName,
      hive: 'HKEY_CURRENT_USER',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      uacElevationRequired: false,
      msiInstallerCount: 0,
      holoCasStore: 'v11',
      entries: libs.map((lib) => {
        const digest = sha512Text(`winget:${lib.wingetId}@${lib.version}`);
        return {
          registryKey: `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${lib.wingetId}`,
          DisplayName: `${lib.name} (Holo v11 Portable)`,
          DisplayVersion: lib.version,
          Publisher: 'Awesome-OS Holo v11',
          InstallLocation: `%LOCALAPPDATA%\\HoloV11\\cas\\v11\\files\\${digest.slice(0, 2)}\\${digest}`,
          UninstallString: `holo-pm uninstall ${lib.wingetId}`,
          InstallerType: 'portable',
          NoModify: 1,
          NoRepair: 1,
          HoloCasStore: 'v11',
        };
      }),
    },
    null,
    2,
  )}\n`;

  emitProjectionFile(
    artifacts,
    'winget',
    baseOutDir,
    resolve(baseOutDir, 'winget-import.holo-v11.json'),
    wingetImport,
    dryRun,
  );
  emitProjectionFile(
    artifacts,
    'winget',
    baseOutDir,
    resolve(baseOutDir, 'winget-hkcu-arp.holo-v11.json'),
    hkcuArpManifest,
    dryRun,
  );
  return libs.length;
}

function buildAptStanzaText(input: AptCompatStanzaInput): string {
  const pkgName = input.package.trim();
  if (!pkgName) {
    throw new Error('apt stanza requires a non-empty package name');
  }
  const soname = input.soname?.trim() ?? '';
  if (!soname || !ELF_SONAME_RE.test(soname)) {
    throw new Error(`apt stanza "${pkgName}" requires a valid mandatory ELF soname (got "${soname}")`);
  }
  const arch = input.architecture?.trim() || 'amd64';
  const version = input.version.trim() || '0.0.0';
  const provides = [...(input.provides ?? [])].sort(byteCompare);
  const sha512 =
    input.v11Sha512 && /^[0-9a-f]{128}$/i.test(input.v11Sha512)
      ? input.v11Sha512.toLowerCase()
      : sha512Text(`apt:${pkgName}:${version}:${arch}:${soname}`);

  const lines = [
    `Package: ${pkgName}`,
    'Status: install ok installed',
    'Priority: optional',
    'Section: libs',
    `Architecture: ${arch}`,
    `Version: ${version}`,
  ];
  if (provides.length > 0) {
    lines.push(`Provides: ${provides.join(', ')}`);
  }
  lines.push(
    'X-Holo-CAS-Store: v11',
    `X-Holo-V11-SHA512: ${sha512}`,
    `X-Holo-ELF-SONAME: ${soname}`,
    `Description: ${input.description || `${pkgName} virtual-provides stanza (${soname})`}`,
  );
  return lines.join('\n');
}

function synthesizeAptCompat(
  baseOutDir: string,
  maxLockOverrides: Map<string, string>,
  customStanzas: AptCompatStanzaInput[] | undefined,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const stanzas: AptCompatStanzaInput[] = customStanzas
    ? [...customStanzas]
    : resolvePinnedCppLibs(maxLockOverrides).map((lib) => ({
        package: lib.aptPackage,
        version: `${lib.version}-holov11`,
        architecture: 'amd64',
        soname: lib.soname,
        provides: lib.aptProvides,
        description: lib.description,
      }));

  stanzas.sort((a, b) => byteCompare(a.package, b.package));
  const rendered = stanzas.map((stanza) => buildAptStanzaText(stanza));
  const content = rendered.length > 0 ? `${rendered.join('\n\n')}\n` : '';

  emitProjectionFile(
    artifacts,
    'apt',
    baseOutDir,
    resolve(baseOutDir, 'dpkg-status.holo-v11'),
    content,
    dryRun,
  );
  return stanzas.length;
}

interface ComposerJsonShape {
  name?: string;
  version?: string;
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
}

interface ComposerLockEntry {
  name?: string;
  version?: string;
  dist?: { url?: string; type?: string; shasum?: string };
}

interface ComposerLockShape {
  packages?: ComposerLockEntry[];
  'packages-dev'?: ComposerLockEntry[];
}

interface WpEnvJsonShape {
  core?: string | null;
  phpVersion?: string;
  plugins?: string[];
  themes?: string[];
  mappings?: Record<string, string>;
  config?: Record<string, unknown>;
  env?: Record<string, unknown>;
  [key: string]: unknown;
}

function normalizeComposerPackageName(rawName: string): string {
  if (rawName.includes('/')) return rawName.toLowerCase();
  const slug = rawName
    .replace(/^@/, '')
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return `awesome-os/${slug || 'workspace'}`;
}

function synthesizeComposerCompat(
  cwd: string,
  baseOutDir: string,
  rootName: string,
  rootVersion: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const composerJsonPath = resolve(cwd, 'composer.json');
  const composerLockPath = resolve(cwd, 'composer.lock');
  const wpEnvPath = resolve(cwd, '.wp-env.json');

  const composerJson: ComposerJsonShape = existsSync(composerJsonPath)
    ? (JSON.parse(readFileSync(composerJsonPath, 'utf8')) as ComposerJsonShape)
    : {};
  const composerLock: ComposerLockShape = existsSync(composerLockPath)
    ? (JSON.parse(readFileSync(composerLockPath, 'utf8')) as ComposerLockShape)
    : {};
  const userWpEnv: WpEnvJsonShape = existsSync(wpEnvPath)
    ? (JSON.parse(readFileSync(wpEnvPath, 'utf8')) as WpEnvJsonShape)
    : {};

  const pkgName = normalizeComposerPackageName(composerJson.name?.trim() || rootName);
  const pkgVersion = composerJson.version?.trim() || rootVersion || '0.0.0';
  const requireMap = sortStringRecord(composerJson.require) ?? {};
  const requireDevMap = sortStringRecord(composerJson['require-dev']) ?? {};

  const lockedPackages = new Map<string, { name: string; version: string; dev: boolean; shasum?: string }>();
  for (const entry of composerLock.packages ?? []) {
    if (!entry.name) continue;
    const ver = maxLockOverrides.get(entry.name) ?? entry.version?.replace(/^v/i, '') ?? '0.0.0';
    lockedPackages.set(entry.name, {
      name: entry.name,
      version: ver,
      dev: false,
      ...(entry.dist?.shasum ? { shasum: entry.dist.shasum } : {}),
    });
  }
  for (const entry of composerLock['packages-dev'] ?? []) {
    if (!entry.name || lockedPackages.has(entry.name)) continue;
    const ver = maxLockOverrides.get(entry.name) ?? entry.version?.replace(/^v/i, '') ?? '0.0.0';
    lockedPackages.set(entry.name, {
      name: entry.name,
      version: ver,
      dev: true,
      ...(entry.dist?.shasum ? { shasum: entry.dist.shasum } : {}),
    });
  }

  const registerDeclared = (map: Record<string, string>, dev: boolean): void => {
    for (const [depName, constraint] of Object.entries(map)) {
      if (depName === 'php' || depName.startsWith('ext-') || depName.startsWith('lib-')) continue;
      if (lockedPackages.has(depName)) continue;
      const ver = maxLockOverrides.get(depName) ?? normalizeDeclaredVersion(constraint);
      lockedPackages.set(depName, { name: depName, version: ver, dev });
    }
  };
  registerDeclared(requireMap, false);
  registerDeclared(requireDevMap, true);

  const resolvedPackages = Array.from(lockedPackages.values())
    .sort((a, b) => byteCompare(a.name, b.name))
    .map((p) => ({
      name: p.name,
      version: p.version,
      dev: p.dev,
      holoCasStore: 'v11',
      casSha512: sha512Text(`composer:${p.name}@${p.version}`),
      ...(p.shasum ? { distShasum: p.shasum } : {}),
    }));

  const composerHoloJson = `${JSON.stringify(
    {
      schema: 'holo-v11.composer-compat.v1',
      abiMagic: B8G_ABI_MAGIC_V3,
      holoCasStore: 'v11',
      zeroVendorMutation: true,
      name: pkgName,
      version: pkgVersion,
      config: {
        'cache-dir': '/var/lib/b8g/cas/v11/composer',
        'preferred-install': 'dist',
        'sort-packages': true,
      },
      repositories: [
        {
          type: 'path',
          url: '/var/lib/b8g/cas/v11/composer/*',
          options: {
            symlink: true,
          },
        },
      ],
      require: requireMap,
      'require-dev': requireDevMap,
      packages: resolvedPackages,
    },
    null,
    2,
  )}\n`;

  const cppLibs = resolvePinnedCppLibs(maxLockOverrides);
  const phpIniLines = [
    '; Generated by holo-ci lock-compat (v11 CAS zero-copy projection)',
    `; abiMagic: ${B8G_ABI_MAGIC_V3}`,
    '; holoCasStore: v11',
    '[PHP]',
    'extension_dir = "/var/lib/b8g/cas/v11/php/ext"',
    'zend.assertions = -1',
    'opcache.enable = 1',
    'opcache.enable_cli = 1',
    'curl.cainfo = "/var/lib/b8g/cas/v11/ssl/cacert.pem"',
    'openssl.cafile = "/var/lib/b8g/cas/v11/ssl/cacert.pem"',
    'sqlite3.defensive = 1',
    '',
    '; Mapped v11 shared native C library pins',
    ...cppLibs.map((lib) => `; v11-pin.${lib.name} = "${lib.version}" ; ${lib.soname}`),
    '',
    'extension = curl',
    'extension = gd',
    'extension = intl',
    'extension = mbstring',
    'extension = openssl',
    'extension = pdo_sqlite',
    'extension = sodium',
    'extension = xsl',
    'extension = zip',
    '',
  ].join('\n');

  const phpVersionRaw =
    typeof userWpEnv.phpVersion === 'string' && userWpEnv.phpVersion.trim().length > 0
      ? userWpEnv.phpVersion.trim()
      : '8.4';

  const wpEnvHoloJson = `${JSON.stringify(
    {
      schema: 'holo-v11.wp-env.v1',
      abiMagic: B8G_ABI_MAGIC_V3,
      holoCasStore: 'v11',
      name: pkgName,
      ...userWpEnv,
      phpVersion: phpVersionRaw,
      runtime: 'php-wasi',
      dbEngine: 'sqlite-wasi',
      casRoot: '/var/lib/b8g/cas/v11',
      wasiHost: 'holo-wasi-host-b8g.wasm',
    },
    null,
    2,
  )}\n`;

  emitProjectionFile(
    artifacts,
    'composer',
    baseOutDir,
    resolve(baseOutDir, 'composer.holo-v11.json'),
    composerHoloJson,
    dryRun,
  );
  emitProjectionFile(
    artifacts,
    'composer',
    baseOutDir,
    resolve(baseOutDir, 'php.holo-v11.ini'),
    phpIniLines,
    dryRun,
  );
  emitProjectionFile(
    artifacts,
    'composer',
    baseOutDir,
    resolve(baseOutDir, 'wp-env.holo-v11.json'),
    wpEnvHoloJson,
    dryRun,
  );

  return resolvedPackages.length > 0 ? resolvedPackages.length : 1;
}

interface ParsedGemEntry {
  name: string;
  version: string;
  source: 'Gemfile' | 'Gemfile.lock' | 'gemspec';
}

function parseRubyEcosystemFiles(
  cwd: string,
  maxLockOverrides: Map<string, string>,
): {
  gemspecName?: string;
  gemspecVersion?: string;
  rubyVersion: string;
  gems: ParsedGemEntry[];
} {
  const gemMap = new Map<string, ParsedGemEntry>();
  let gemspecName: string | undefined;
  let gemspecVersion: string | undefined;
  let rubyVersion = '3.4.2';

  const dirEntries = existsSync(cwd)
    ? readdirSync(cwd, { withFileTypes: true }).sort((a, b) => byteCompare(a.name, b.name))
    : [];
  const gemspecFiles = dirEntries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.gemspec'))
    .map((entry) => join(cwd, entry.name));

  for (const specPath of gemspecFiles) {
    const text = readFileSync(specPath, 'utf8');
    const nameMatch = /^\s*[A-Za-z_][A-Za-z0-9_]*\.name\s*=\s*["']([^"']+)["']/m.exec(text);
    if (nameMatch && !gemspecName) gemspecName = nameMatch[1];
    const verMatch = /^\s*[A-Za-z_][A-Za-z0-9_]*\.version\s*=\s*["']([^"']+)["']/m.exec(text);
    if (verMatch && !gemspecVersion) gemspecVersion = verMatch[1];
    const depMatches = text.matchAll(
      /add_(?:runtime_|development_)?dependency\s*\(?\s*["']([A-Za-z0-9_.-]+)["'](?:\s*,\s*["']([^"']+)["'])?/g,
    );
    for (const m of depMatches) {
      const name = m[1];
      const ver = maxLockOverrides.get(name) ?? (m[2] ? normalizeDeclaredVersion(m[2]) : '0.0.0');
      gemMap.set(name, { name, version: ver, source: 'gemspec' });
    }
  }

  const gemfilePath = resolve(cwd, 'Gemfile');
  if (existsSync(gemfilePath)) {
    const lines = readFileSync(gemfilePath, 'utf8').split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.split('#')[0]?.trim() ?? '';
      if (!line) continue;
      const rubyMatch = /^ruby\s+["']([^"']+)["']/.exec(line);
      if (rubyMatch) {
        rubyVersion = rubyMatch[1];
        continue;
      }
      const gemMatch = /^gem\s+["']([A-Za-z0-9_.-]+)["'](?:\s*,\s*["']([^"']+)["'])?/.exec(line);
      if (gemMatch) {
        const name = gemMatch[1];
        const ver = maxLockOverrides.get(name) ?? (gemMatch[2] ? normalizeDeclaredVersion(gemMatch[2]) : '0.0.0');
        gemMap.set(name, { name, version: ver, source: 'Gemfile' });
      }
    }
  }

  const gemfileLockPath = resolve(cwd, 'Gemfile.lock');
  if (existsSync(gemfileLockPath)) {
    const lines = readFileSync(gemfileLockPath, 'utf8').split(/\r?\n/);
    let section = '';
    let inSpecs = false;
    for (const line of lines) {
      if (/^[A-Z][A-Z ]+$/.test(line.trim())) {
        section = line.trim();
        inSpecs = false;
        continue;
      }
      if (section === 'GEM' && line.trim() === 'specs:') {
        inSpecs = true;
        continue;
      }
      if (section === 'GEM' && inSpecs) {
        const specMatch = /^ {4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)$/.exec(line);
        if (specMatch) {
          const name = specMatch[1];
          const rawVer = specMatch[2].split('-')[0] ?? specMatch[2];
          const ver = maxLockOverrides.get(name) ?? rawVer;
          gemMap.set(name, { name, version: ver, source: 'Gemfile.lock' });
        }
      } else if (section === 'RUBY VERSION') {
        const rvMatch = /ruby\s+([0-9]+\.[0-9]+\.[0-9]+)/.exec(line);
        if (rvMatch) rubyVersion = rvMatch[1];
      }
    }
  }

  const gems = Array.from(gemMap.values()).sort((a, b) => byteCompare(a.name, b.name));
  return {
    ...(gemspecName ? { gemspecName } : {}),
    ...(gemspecVersion ? { gemspecVersion } : {}),
    rubyVersion,
    gems,
  };
}

function synthesizeRubygemsCompat(
  cwd: string,
  baseOutDir: string,
  rootName: string,
  rootVersion: string,
  maxLockOverrides: Map<string, string>,
  dryRun: boolean,
  artifacts: HoloCiLockCompatArtifact[],
): number {
  const parsed = parseRubyEcosystemFiles(cwd, maxLockOverrides);
  const cppLibs = resolvePinnedCppLibs(maxLockOverrides);
  const libByName = new Map(cppLibs.map((lib) => [lib.name, lib]));

  const sonameEntries: Array<[string, { soname: string; libraries: string[]; versions: Record<string, string>; holoCasStore: 'v11'; libxsltSoname?: string }]> = [
    [
      'curb',
      {
        soname: libByName.get('curl')?.soname ?? 'libcurl.so.4',
        libraries: ['curl'],
        versions: { curl: libByName.get('curl')?.version ?? '8.23.0' },
        holoCasStore: 'v11',
      },
    ],
    [
      'ffi',
      {
        soname: 'libffi.so.8',
        libraries: ['libffi'],
        versions: { libffi: maxLockOverrides.get('libffi') ?? '3.4.7' },
        holoCasStore: 'v11',
      },
    ],
    [
      'nokogiri',
      {
        soname: libByName.get('libxml2')?.soname ?? 'libxml2.so.2',
        libxsltSoname: libByName.get('libxslt')?.soname ?? 'libxslt.so.1',
        libraries: ['libxml2', 'libxslt'],
        versions: {
          libxml2: libByName.get('libxml2')?.version ?? '2.15.4',
          libxslt: libByName.get('libxslt')?.version ?? '1.1.45',
        },
        holoCasStore: 'v11',
      },
    ],
    [
      'openssl',
      {
        soname: libByName.get('openssl')?.soname ?? 'libssl.so.3',
        libraries: ['openssl'],
        versions: { openssl: libByName.get('openssl')?.version ?? '4.1.0' },
        holoCasStore: 'v11',
      },
    ],
    [
      'psych',
      {
        soname: 'libyaml-0.so.2',
        libraries: ['libyaml'],
        versions: { libyaml: maxLockOverrides.get('libyaml') ?? '0.2.5' },
        holoCasStore: 'v11',
      },
    ],
    [
      'rbnacl',
      {
        soname: libByName.get('libsodium')?.soname ?? 'libsodium.so.23',
        libraries: ['libsodium'],
        versions: { libsodium: libByName.get('libsodium')?.version ?? '1.0.22' },
        holoCasStore: 'v11',
      },
    ],
    [
      'rdkafka',
      {
        soname: libByName.get('librdkafka')?.soname ?? 'librdkafka.so.1',
        libraries: ['librdkafka'],
        versions: { librdkafka: libByName.get('librdkafka')?.version ?? '2.16.0' },
        holoCasStore: 'v11',
      },
    ],
    [
      'ruby-vips',
      {
        soname: libByName.get('libvips')?.soname ?? 'libvips.so.42',
        libraries: ['libvips'],
        versions: { libvips: libByName.get('libvips')?.version ?? '8.18.7' },
        holoCasStore: 'v11',
      },
    ],
    [
      'rugged',
      {
        soname: libByName.get('libgit2')?.soname ?? 'libgit2.so.1.9',
        libraries: ['libgit2'],
        versions: { libgit2: libByName.get('libgit2')?.version ?? '1.9.7' },
        holoCasStore: 'v11',
      },
    ],
    [
      'sqlite3',
      {
        soname: libByName.get('sqlite')?.soname ?? 'libsqlite3.so.0',
        libraries: ['sqlite'],
        versions: { sqlite: libByName.get('sqlite')?.version ?? '3.54.1' },
        holoCasStore: 'v11',
      },
    ],
  ];

  const nativeExtensionSonames: Record<string, (typeof sonameEntries)[number][1]> = {};
  for (const [gemName, info] of sonameEntries.sort((a, b) => byteCompare(a[0], b[0]))) {
    nativeExtensionSonames[gemName] = info;
  }

  const bundleConfig = [
    '---',
    '# Generated by holo-ci lock-compat (v11 CAS zero-copy projection)',
    'BUNDLE_CACHE_PATH: "/var/lib/b8g/cas/v11/gems"',
    'BUNDLE_LOCAL: "true"',
    'BUNDLE_DEPLOYMENT: "true"',
    'BUNDLE_BUILD__NOKOGIRI: "--use-system-libraries"',
    'BUNDLE_BUILD__PSYCH: "--with-libyaml-dir=/var/lib/b8g/cas/v11"',
    'BUNDLE_BUILD__FFI: "--enable-system-libffi"',
    'BUNDLE_BUILD__SQLITE3: "--enable-system-libraries"',
    'BUNDLE_BUILD__OPENSSL: "--with-openssl-dir=/var/lib/b8g/cas/v11"',
    '',
  ].join('\n');

  const compatJson = `${JSON.stringify(
    {
      schema: 'holo-v11.rubygems-compat.v1',
      abiMagic: B8G_ABI_MAGIC_V3,
      name: parsed.gemspecName ?? rootName,
      version: parsed.gemspecVersion ?? rootVersion,
      holoCasStore: 'v11',
      zeroHostGemMutation: true,
      bundleCachePath: '/var/lib/b8g/cas/v11/gems',
      rubyWasm: {
        runtime: 'ruby.wasm',
        target: 'wasm32-wasi',
        wasiHost: 'holo-wasi-host-b8g.wasm',
        casRoot: '/var/lib/b8g/cas/v11',
        rubyVersion: parsed.rubyVersion,
      },
      nativeExtensionSonames,
      gems: parsed.gems.map((g) => ({
        name: g.name,
        version: g.version,
        source: g.source,
        holoCasStore: 'v11',
        casSha512: sha512Text(`rubygems:${g.name}@${g.version}`),
        ...(nativeExtensionSonames[g.name] ? { soname: nativeExtensionSonames[g.name].soname } : {}),
      })),
    },
    null,
    2,
  )}\n`;

  emitProjectionFile(
    artifacts,
    'rubygems',
    baseOutDir,
    resolve(baseOutDir, '.bundle', 'config.holo-v11'),
    bundleConfig,
    dryRun,
  );
  emitProjectionFile(
    artifacts,
    'rubygems',
    baseOutDir,
    resolve(baseOutDir, 'holo-rubygems-compat.json'),
    compatJson,
    dryRun,
  );

  return parsed.gems.length > 0 ? parsed.gems.length : Object.keys(nativeExtensionSonames).length;
}

export function runLockCompat(opts: LockCompatOptions = {}): HoloCiLockCompatResult {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const ecosystem: HoloCiLockCompatEcosystem = opts.ecosystem ?? 'npm';
  const dryRun = Boolean(opts.dryRun);
  const baseOutDir = resolve(cwd, opts.outDir ?? '.');
  const maxLockOverrides = loadMaxVersionOverrides(cwd, opts.maxLockPath);

  const pkgPath = resolve(cwd, 'package.json');
  const fallbackName = basename(cwd);
  let rootName = fallbackName;
  let rootVersion = '0.0.0';
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJsonShape;
    rootName = pkg.name?.trim() || fallbackName;
    rootVersion = pkg.version?.trim() || '0.0.0';
  }

  const targetEcosystems: HoloCiLockCompatSingleEcosystem[] =
    ecosystem === 'all' ? [...ALL_ECOSYSTEMS] : [ecosystem];

  const artifacts: HoloCiLockCompatArtifact[] = [];
  let outFile = resolve(baseOutDir, 'package-lock.json');
  let packageCount = 0;
  let workspaceCount = 0;
  let resolvedFromPnpmLock = 0;
  let resolvedFromMaxLock = 0;
  let npmLockfile: HoloCiLockfileV3 | undefined;

  for (const target of targetEcosystems) {
    if (target === 'npm') {
      const npmOut = synthesizeNpmLock(
        cwd,
        baseOutDir,
        ecosystem === 'npm' ? opts.outFile : undefined,
        ecosystem === 'npm',
        maxLockOverrides,
        dryRun,
        artifacts,
      );
      rootName = npmOut.rootName;
      rootVersion = npmOut.rootVersion;
      outFile = npmOut.outFile;
      packageCount += npmOut.packageCount;
      workspaceCount = npmOut.workspaceCount;
      resolvedFromPnpmLock = npmOut.resolvedFromPnpmLock;
      resolvedFromMaxLock = npmOut.resolvedFromMaxLock;
      npmLockfile = npmOut.lockfile;
    } else if (target === 'cargo') {
      packageCount += synthesizeCargoCompat(cwd, baseOutDir, rootName, maxLockOverrides, dryRun, artifacts);
    } else if (target === 'uv') {
      packageCount += synthesizeUvCompat(cwd, baseOutDir, maxLockOverrides, dryRun, artifacts);
    } else if (target === 'go') {
      packageCount += synthesizeGoCompat(cwd, baseOutDir, dryRun, artifacts);
    } else if (target === 'vcpkg') {
      packageCount += synthesizeVcpkgCompat(baseOutDir, maxLockOverrides, dryRun, artifacts);
    } else if (target === 'winget') {
      packageCount += synthesizeWingetCompat(baseOutDir, rootName, maxLockOverrides, dryRun, artifacts);
    } else if (target === 'apt') {
      packageCount += synthesizeAptCompat(baseOutDir, maxLockOverrides, opts.aptStanzas, dryRun, artifacts);
    } else if (target === 'composer') {
      packageCount += synthesizeComposerCompat(
        cwd,
        baseOutDir,
        rootName,
        rootVersion,
        maxLockOverrides,
        dryRun,
        artifacts,
      );
    } else if (target === 'rubygems') {
      packageCount += synthesizeRubygemsCompat(
        cwd,
        baseOutDir,
        rootName,
        rootVersion,
        maxLockOverrides,
        dryRun,
        artifacts,
      );
    }
  }

  if (ecosystem !== 'npm' && artifacts.length > 0 && !npmLockfile) {
    outFile = artifacts[0].path;
  }

  const compositeDigestInput = artifacts.map((a) => `${a.ecosystem}:${a.relPath}:${a.sha256}`).join('\n');
  const overallSha256 =
    ecosystem === 'npm' && artifacts.length === 1 ? artifacts[0].sha256 : sha256Text(compositeDigestInput);

  return {
    ok: true,
    ecosystem,
    ecosystemsGenerated: targetEcosystems,
    name: rootName,
    version: rootVersion,
    outFile,
    outDir: baseOutDir,
    dryRun,
    written: !dryRun,
    lockfileVersion: npmLockfile?.lockfileVersion ?? HOLO_LOCKFILE_VERSION,
    holoCasStore: 'v11',
    zeroCopyNodeModules: true,
    packageCount,
    workspaceCount,
    resolvedFromPnpmLock,
    resolvedFromMaxLock,
    sha256: overallSha256,
    artifacts,
    ...(npmLockfile ? { lockfile: npmLockfile } : {}),
  };
}
