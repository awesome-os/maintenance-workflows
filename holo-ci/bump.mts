import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  compareSemver,
  type HoloCiBumpResult,
  type HoloCiManifest,
  type HoloCiPackageBumpResult,
  type HoloCiPinCheckResult,
  type HoloCiUpstreamPin,
} from './schema.mts';

export function checkUpstreamPins(pins: HoloCiUpstreamPin[]): HoloCiPinCheckResult[] {
  return pins.map((pin) => {
    const cmp = compareSemver(pin.pinned, pin.upstream);
    const status = cmp === 0 ? 'pinned-match' : cmp > 0 ? 'pinned-ahead' : 'pinned-behind';
    return {
      name: pin.name,
      pinned: pin.pinned,
      upstream: pin.upstream,
      ok: cmp >= 0,
      status,
    };
  });
}

export function bumpPackageJson(
  packagePath: string,
  newVersion: string,
  dryRun = false,
): HoloCiPackageBumpResult {
  const normalized = newVersion.trim().replace(/^v/i, '');
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(normalized)) {
    throw new Error(`Invalid target version "${newVersion}" (expected semver X.Y.Z)`);
  }
  if (!existsSync(packagePath)) {
    throw new Error(`package.json not found at ${packagePath}`);
  }
  const parsed = JSON.parse(readFileSync(packagePath, 'utf8')) as Record<string, unknown>;
  const previousVersion = typeof parsed.version === 'string' ? parsed.version : '0.0.0';
  const changed = previousVersion !== normalized;

  if (!dryRun && changed) {
    parsed.version = normalized;
    writeFileSync(packagePath, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
  }

  return {
    path: packagePath,
    previousVersion,
    newVersion: normalized,
    updated: !dryRun && changed,
    dryRun,
  };
}

export function normalizeUpstreamTagVersion(tag: string): string | null {
  const trimmed = tag.trim();
  if (!trimmed) return null;

  // Match standard dot-separated semver suffix (e.g., v1.2.3, openssl-4.1.0, node-v24.2.0, v1.2.3-rc.1)
  const dotMatch = /(?:^|[^0-9])v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z.-]+)?)$/.exec(
    trimmed,
  );
  if (dotMatch) {
    const candidate = dotMatch[1];
    try {
      compareSemver(candidate, candidate);
      return candidate;
    } catch {
      return null;
    }
  }

  // Match separator-based tags (e.g., VER-2-15-0, curl-8_23_0)
  const sepMatch = /(?:^|[^0-9])v?(\d+)[_-](\d+)(?:[_-](\d+))?$/.exec(trimmed);
  if (sepMatch) {
    const candidate = `${sepMatch[1]}.${sepMatch[2]}.${sepMatch[3] ?? '0'}`;
    try {
      compareSemver(candidate, candidate);
      return candidate;
    } catch {
      return null;
    }
  }

  return null;
}

export async function fetchLatestUpstreamVersion(
  repo: string,
  token?: string,
  fetchFn: typeof fetch = fetch,
): Promise<{ tag: string; version: string } | null> {
  const cleanRepo = repo.trim().replace(/^\/+|\/+$/g, '');
  if (!cleanRepo || !cleanRepo.includes('/')) return null;

  const authToken = token ?? process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'holo-ci/1.0',
  };
  if (authToken && authToken.trim().length > 0) {
    headers.Authorization = `Bearer ${authToken.trim()}`;
  }

  try {
    const releaseRes = await fetchFn(`https://api.github.com/repos/${cleanRepo}/releases/latest`, {
      headers,
    });
    if (releaseRes.ok) {
      const data = (await releaseRes.json()) as { tag_name?: unknown; draft?: unknown; prerelease?: unknown };
      if (typeof data.tag_name === 'string' && !data.draft && !data.prerelease) {
        const version = normalizeUpstreamTagVersion(data.tag_name);
        if (version) {
          return { tag: data.tag_name, version };
        }
      }
    }
  } catch {
    // Fall back to /tags below
  }

  try {
    const tagsRes = await fetchFn(`https://api.github.com/repos/${cleanRepo}/tags?per_page=20`, {
      headers,
    });
    if (!tagsRes.ok) return null;
    const tags = (await tagsRes.json()) as Array<{ name?: unknown }>;
    if (!Array.isArray(tags)) return null;

    const candidates: Array<{ tag: string; version: string }> = [];
    for (const entry of tags) {
      if (typeof entry?.name !== 'string') continue;
      const version = normalizeUpstreamTagVersion(entry.name);
      if (version) {
        candidates.push({ tag: entry.name, version });
      }
    }
    if (candidates.length === 0) return null;

    // Prefer stable (non-prerelease) highest semver; fall back to highest semver overall
    const stable = candidates.filter((c) => !c.version.includes('-'));
    const pool = stable.length > 0 ? stable : candidates;
    pool.sort((a, b) => compareSemver(b.version, a.version));
    return pool[0];
  } catch {
    return null;
  }
}

export function runBump(
  manifest: HoloCiManifest,
  options: { cwd?: string; version?: string; packagePath?: string; dryRun?: boolean } = {},
): HoloCiBumpResult {
  const cwd = options.cwd ?? process.cwd();
  const pins = checkUpstreamPins(manifest.upstreamPins ?? []);
  let packageBump: HoloCiPackageBumpResult | undefined;

  if (options.version) {
    const pkgFull = resolve(cwd, options.packagePath ?? 'package.json');
    packageBump = bumpPackageJson(pkgFull, options.version, Boolean(options.dryRun));
  }

  const ok = pins.every((p) => p.ok);
  return {
    ok,
    pins,
    ...(packageBump ? { packageBump } : {}),
  };
}

export async function runBumpAsync(
  manifest: HoloCiManifest,
  options: {
    cwd?: string;
    version?: string;
    packagePath?: string;
    dryRun?: boolean;
    fetchUpstream?: boolean;
    applyPins?: boolean;
    configPath?: string;
    token?: string;
    fetchFn?: typeof fetch;
  } = {},
): Promise<HoloCiBumpResult> {
  const cwd = options.cwd ?? process.cwd();
  const workingPins: HoloCiUpstreamPin[] = (manifest.upstreamPins ?? []).map((p) => ({ ...p }));

  if (options.fetchUpstream) {
    await Promise.all(
      workingPins.map(async (pin) => {
        if (!pin.upstreamRepo) return;
        const latest = await fetchLatestUpstreamVersion(pin.upstreamRepo, options.token, options.fetchFn);
        if (latest) {
          pin.upstream = latest.version;
        }
      }),
    );
  }

  const initialChecks = checkUpstreamPins(workingPins);
  const laggedNames = new Set(initialChecks.filter((p) => p.status === 'pinned-behind').map((p) => p.name));
  const bumpedPins = Array.from(laggedNames);
  const bumpedCount = bumpedPins.length;

  let applied = false;
  if (options.applyPins && !options.dryRun && bumpedCount > 0) {
    for (const pin of workingPins) {
      if (laggedNames.has(pin.name)) {
        pin.pinned = pin.upstream;
      }
    }

    const configFull = resolve(cwd, options.configPath ?? 'holo-ci.json');
    if (existsSync(configFull)) {
      const parsed = JSON.parse(readFileSync(configFull, 'utf8')) as Record<string, unknown>;
      if (Array.isArray(parsed.upstreamPins)) {
        const byName = new Map(workingPins.map((p) => [p.name, p]));
        parsed.upstreamPins = parsed.upstreamPins.map((rawPin) => {
          if (!rawPin || typeof rawPin !== 'object') return rawPin;
          const record = rawPin as Record<string, unknown>;
          const name = typeof record.name === 'string' ? record.name : '';
          const updated = byName.get(name);
          if (!updated) return rawPin;
          return {
            ...record,
            pinned: updated.pinned,
            upstream: updated.upstream,
          };
        });
        writeFileSync(configFull, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
      }
    }
    applied = true;
  }

  const pins = checkUpstreamPins(workingPins);
  let packageBump: HoloCiPackageBumpResult | undefined;
  if (options.version) {
    const pkgFull = resolve(cwd, options.packagePath ?? 'package.json');
    packageBump = bumpPackageJson(pkgFull, options.version, Boolean(options.dryRun));
  }

  const ok = pins.every((p) => p.ok);
  return {
    ok,
    pins,
    ...(packageBump ? { packageBump } : {}),
    bumpedCount,
    bumpedPins,
    applied,
  };
}
