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
