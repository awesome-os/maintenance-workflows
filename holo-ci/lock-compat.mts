import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import type {
  HoloCiLockCompatPackageEntry,
  HoloCiLockCompatResult,
  HoloCiLockfileV3,
} from './schema.mts';

export interface LockCompatOptions {
  cwd?: string;
  outFile?: string;
  dryRun?: boolean;
  maxLockPath?: string;
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

function byteCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
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
  // Strip peer suffix like `2.1.5(hono@4.13.16)` or `10.13.0(supports-color@7.2.0)`
  const parenIdx = cleaned.indexOf('(');
  const withoutPeers = parenIdx === -1 ? cleaned : cleaned.slice(0, parenIdx);
  // Handle npm alias like `typescript@7.0.2`
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

  // Second pass to backfill integrity hashes discovered after importers section
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

export function runLockCompat(opts: LockCompatOptions = {}): HoloCiLockCompatResult {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const pkgPath = resolve(cwd, 'package.json');
  if (!existsSync(pkgPath)) {
    throw new Error(`package.json not found at ${pkgPath}`);
  }

  const rootPkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJsonShape;
  const rootName = rootPkg.name?.trim() || basename(cwd);
  const rootVersion = rootPkg.version?.trim() || '0.0.0';

  const pnpmLockPath = resolve(cwd, 'pnpm-lock.yaml');
  const pnpmParsed = existsSync(pnpmLockPath)
    ? parsePnpmLock(readFileSync(pnpmLockPath, 'utf8'))
    : { resolved: new Map<string, PnpmResolvedEntry>(), integrityByPkgVersion: new Map<string, string>() };

  const maxLockOverrides = loadMaxVersionOverrides(cwd, opts.maxLockPath);

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

  // Register workspace packages first so workspace references link cleanly without touching node_modules
  const workspaceDirs = resolveWorkspaceDirs(cwd, rootPkg.workspaces);
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

  // Deterministic byte-sorted `packages` map
  const sortedPackages: Record<string, HoloCiLockCompatPackageEntry> = {};
  for (const key of Array.from(packagesUnsorted.keys()).sort(byteCompare)) {
    const entry = packagesUnsorted.get(key);
    if (entry) sortedPackages[key] = entry;
  }

  const lockfile: HoloCiLockfileV3 = {
    name: rootName,
    version: rootVersion,
    lockfileVersion: 3,
    requires: true,
    holoCasStore: 'v11',
    zeroCopyNodeModules: true,
    packages: sortedPackages,
  };

  const serialized = `${JSON.stringify(lockfile, null, 2)}\n`;
  const sha256 = createHash('sha256').update(serialized, 'utf8').digest('hex');
  const outFile = resolve(cwd, opts.outFile ?? 'package-lock.json');
  const dryRun = Boolean(opts.dryRun);

  if (!dryRun) {
    mkdirSync(dirname(outFile), { recursive: true });
    writeFileSync(outFile, serialized, 'utf8');
  }

  return {
    ok: true,
    name: rootName,
    version: rootVersion,
    outFile,
    dryRun,
    written: !dryRun,
    lockfileVersion: 3,
    holoCasStore: 'v11',
    zeroCopyNodeModules: true,
    packageCount: Object.keys(sortedPackages).length,
    workspaceCount: workspaceDirs.length,
    resolvedFromPnpmLock,
    resolvedFromMaxLock,
    sha256,
    lockfile,
  };
}
