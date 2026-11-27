import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runBoundaryAudit } from './boundary.mts';
import {
  B8G_ABI_MAGIC_V3,
  compareSemver,
  type HoloCiBumpResult,
  type HoloCiManifest,
  type HoloCiPackageBumpResult,
  type HoloCiPinCheckResult,
  type HoloCiShadowCanaryDiff,
  type HoloCiShadowCanaryResult,
  type HoloCiUpstreamPin,
} from './schema.mts';
import { runVerify } from './verify.mts';

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

function verifyAbiGoldenGate(
  cwd: string,
  configPath: string | undefined,
  diffs: HoloCiShadowCanaryDiff[],
): boolean {
  const boundaryFull = resolve(cwd, 'boundary.json');
  if (existsSync(boundaryFull)) {
    const audit = runBoundaryAudit({ cwd, boundaryPath: 'boundary.json', configPath });
    const abiViolations = audit.violations.filter(
      (v) => v.rule === 'abiGolden' || v.rule === 'boundaryManifest',
    );
    for (const v of abiViolations) {
      diffs.push({
        gate: 'abi-golden',
        target: v.file,
        expected: 'valid ABI golden contract',
        actual: v.snippet,
        message: v.message,
      });
    }
    return abiViolations.length === 0;
  }

  const standaloneGolden = resolve(cwd, 'abi-golden.json');
  if (!existsSync(standaloneGolden)) return true;

  try {
    const parsed: unknown = JSON.parse(readFileSync(standaloneGolden, 'utf8'));
    if (!parsed || typeof parsed !== 'object') {
      diffs.push({
        gate: 'abi-golden',
        target: 'abi-golden.json',
        expected: 'JSON object',
        actual: typeof parsed,
        message: 'abi-golden.json must contain a JSON object',
      });
      return false;
    }
    const obj = parsed as { abiMagic?: unknown; header?: unknown };
    if (typeof obj.abiMagic === 'string' && obj.abiMagic !== B8G_ABI_MAGIC_V3) {
      diffs.push({
        gate: 'abi-golden',
        target: 'abi-golden.json',
        expected: B8G_ABI_MAGIC_V3,
        actual: obj.abiMagic,
        message: `ABI magic mismatch in abi-golden.json (expected ${B8G_ABI_MAGIC_V3}, got ${obj.abiMagic})`,
      });
      return false;
    }
    if (typeof obj.header === 'string' && obj.header.trim().length > 0) {
      const headerRel = obj.header.trim();
      if (!existsSync(resolve(cwd, headerRel))) {
        diffs.push({
          gate: 'abi-golden',
          target: 'abi-golden.json',
          expected: `existing header ${headerRel}`,
          actual: 'missing',
          message: `abi-golden.json references missing header "${headerRel}"`,
        });
        return false;
      }
    }
    return true;
  } catch (err) {
    diffs.push({
      gate: 'abi-golden',
      target: 'abi-golden.json',
      expected: 'valid JSON',
      actual: 'parse error',
      message: `Failed to parse abi-golden.json: ${err instanceof Error ? err.message : String(err)}`,
    });
    return false;
  }
}

function verifySha512Gate(
  cwd: string,
  manifest: HoloCiManifest,
  diffs: HoloCiShadowCanaryDiff[],
): { ok: boolean; checked: number } {
  const configuredSums = manifest.casRelease?.sumsPath;
  const sumsRel = configuredSums ?? 'SHA512SUMS.txt';
  const sumsFull = resolve(cwd, sumsRel);

  if (!existsSync(sumsFull)) {
    if (configuredSums) {
      diffs.push({
        gate: 'sha512',
        target: sumsRel,
        expected: 'existing SHA512SUMS file',
        actual: 'missing',
        message: `Configured sumsPath "${sumsRel}" does not exist`,
      });
      return { ok: false, checked: 0 };
    }
    return { ok: true, checked: 0 };
  }

  const lines = readFileSync(sumsFull, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));

  let checked = 0;
  let allOk = true;
  for (const line of lines) {
    const match = /^([0-9a-fA-F]{128})\s+\*?(.+)$/.exec(line);
    if (!match) {
      allOk = false;
      diffs.push({
        gate: 'sha512',
        target: sumsRel,
        expected: '<128-hex-sha512>  <path>',
        actual: line,
        message: `Malformed SHA-512 checksum entry in "${sumsRel}"`,
      });
      continue;
    }

    const expectedHash = match[1].toLowerCase();
    const relTarget = match[2].trim();
    const fullTarget = resolve(cwd, relTarget);
    checked++;

    if (!existsSync(fullTarget)) {
      allOk = false;
      diffs.push({
        gate: 'sha512',
        target: relTarget,
        expected: expectedHash,
        actual: 'missing',
        message: `SHA-512 target "${relTarget}" listed in "${sumsRel}" does not exist`,
      });
      continue;
    }

    const actualHash = createHash('sha512').update(readFileSync(fullTarget)).digest('hex');
    if (actualHash !== expectedHash) {
      allOk = false;
      diffs.push({
        gate: 'sha512',
        target: relTarget,
        expected: expectedHash,
        actual: actualHash,
        message: `SHA-512 mismatch for "${relTarget}"`,
      });
    }
  }

  return { ok: allOk, checked };
}

export function runShadowCanaryGate(
  manifest: HoloCiManifest,
  options: { cwd?: string; configPath?: string } = {},
): HoloCiShadowCanaryResult {
  const cwd = options.cwd ?? process.cwd();
  const diffs: HoloCiShadowCanaryDiff[] = [];

  const verifyRes = runVerify(manifest, { cwd });
  for (const t of verifyRes.tests) {
    if (!t.ok) {
      diffs.push({
        gate: 'verify',
        target: t.command,
        expected: 'exitCode=0',
        actual: `exitCode=${t.exitCode}`,
        message: `Test command failed: ${t.command}`,
      });
    }
  }
  for (const g of verifyRes.nativeGates) {
    if (!g.ok) {
      diffs.push({
        gate: 'verify',
        target: g.command,
        expected: 'exitCode=0',
        actual: `exitCode=${g.exitCode}`,
        message: `Native gate failed: ${g.command}`,
      });
    }
  }
  for (const d of verifyRes.docs) {
    if (!d.exists) {
      diffs.push({
        gate: 'verify',
        target: d.path,
        expected: 'existing doc',
        actual: 'missing',
        message: `Required documentation missing: ${d.path}`,
      });
    }
  }
  for (const v of verifyRes.guardViolations) {
    diffs.push({
      gate: 'verify',
      target: v.file,
      expected: `guard(${v.guard}) clean`,
      actual: v.snippet,
      message: v.message,
    });
  }

  const abiGoldenOk = verifyAbiGoldenGate(cwd, options.configPath, diffs);
  const sha512Res = verifySha512Gate(cwd, manifest, diffs);
  const ok = verifyRes.ok && abiGoldenOk && sha512Res.ok;

  return {
    enabled: true,
    ok,
    held: !ok,
    verifyOk: verifyRes.ok,
    abiGoldenOk,
    sha512Ok: sha512Res.ok,
    sha512Checked: sha512Res.checked,
    diffs,
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
    shadowCanary?: boolean;
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

  let shadowCanary: HoloCiShadowCanaryResult | undefined;
  if (options.shadowCanary) {
    shadowCanary = runShadowCanaryGate(manifest, {
      cwd,
      configPath: options.configPath,
    });
    if (!shadowCanary.ok) {
      return {
        ok: false,
        pins: initialChecks,
        bumpedCount,
        bumpedPins,
        applied: false,
        shadowCanary,
      };
    }
  }

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

  const ok = pins.every((p) => p.ok) && (shadowCanary?.ok ?? true);
  return {
    ok,
    pins,
    ...(packageBump ? { packageBump } : {}),
    bumpedCount,
    bumpedPins,
    applied,
    ...(shadowCanary ? { shadowCanary } : {}),
  };
}
