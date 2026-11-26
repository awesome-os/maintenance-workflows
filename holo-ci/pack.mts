import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_V11_MANIFEST_SCHEMA,
  type HoloCiManifest,
  type HoloCiPackDedupStats,
  type HoloCiPackEntry,
  type HoloCiPackResult,
} from './schema.mts';

const DEFAULT_PACK_EXCLUDES = new Set([
  '.git',
  'node_modules',
  '.awesome-oci',
  '.holo-ci-runtime',
  'holo-v11-manifest.json',
  'SHA512SUMS.txt',
  'holo-ci-receipt.ndjson',
]);

function hashSha512File(filePath: string): { sha512: string; size: number } {
  const buf = readFileSync(filePath);
  const sha512 = createHash('sha512').update(buf).digest('hex');
  return { sha512, size: buf.byteLength };
}

function collectFilesForPack(
  cwd: string,
  include: string[] | undefined,
  exclude: string[] | undefined,
): string[] {
  const excludeSet = new Set([...DEFAULT_PACK_EXCLUDES, ...(exclude ?? [])]);
  const collected = new Set<string>();

  function walkTarget(absTarget: string): void {
    if (!existsSync(absTarget)) return;
    const st = statSync(absTarget);
    if (st.isFile()) {
      const rel = relative(cwd, absTarget).replace(/\\/g, '/');
      const base = rel.split('/').pop() ?? '';
      if (!excludeSet.has(base) && !excludeSet.has(rel)) {
        collected.add(absTarget);
      }
      return;
    }
    if (!st.isDirectory()) return;

    const entries = readdirSync(absTarget, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (excludeSet.has(entry.name)) continue;
      const full = join(absTarget, entry.name);
      const rel = relative(cwd, full).replace(/\\/g, '/');
      if (excludeSet.has(rel)) continue;
      if (entry.isDirectory()) {
        walkTarget(full);
      } else if (entry.isFile()) {
        collected.add(full);
      }
    }
  }

  const targets = include && include.length > 0 ? include : ['.'];
  for (const t of targets) {
    walkTarget(resolve(cwd, t));
  }

  return Array.from(collected).sort((a, b) => {
    const ra = relative(cwd, a).replace(/\\/g, '/');
    const rb = relative(cwd, b).replace(/\\/g, '/');
    return ra < rb ? -1 : ra > rb ? 1 : 0;
  });
}

export function computeDedupStats(entries: HoloCiPackEntry[]): HoloCiPackDedupStats {
  const uniqueSizes = new Map<string, number>();
  let rawBytes = 0;

  for (const entry of entries) {
    rawBytes += entry.size;
    if (!uniqueSizes.has(entry.sha512)) {
      uniqueSizes.set(entry.sha512, entry.size);
    }
  }

  let uniqueBytes = 0;
  for (const size of uniqueSizes.values()) {
    uniqueBytes += size;
  }

  const savedBytes = Math.max(0, rawBytes - uniqueBytes);
  const dedupRatioPct = rawBytes > 0 ? Number(((savedBytes / rawBytes) * 100).toFixed(2)) : 0;

  return {
    totalAssets: entries.length,
    uniqueSha512Blobs: uniqueSizes.size,
    dedupedBlobs: Math.max(0, entries.length - uniqueSizes.size),
    rawBytes,
    uniqueBytes,
    savedBytes,
    dedupRatioPct,
  };
}

export function runPack(
  manifest: HoloCiManifest,
  options: { cwd?: string; outDir?: string; include?: string[]; exclude?: string[] } = {},
): HoloCiPackResult {
  const cwd = options.cwd ?? process.cwd();
  const casCfg = manifest.casRelease ?? {};
  const outDirRel = options.outDir ?? casCfg.outDir ?? '.';
  const outDir = resolve(cwd, outDirRel);
  const manifestPath = resolve(outDir, casCfg.manifestPath ?? 'holo-v11-manifest.json');
  const sumsPath = resolve(outDir, casCfg.sumsPath ?? 'SHA512SUMS.txt');

  const files = collectFilesForPack(
    cwd,
    options.include ?? casCfg.include,
    options.exclude ?? casCfg.exclude,
  );

  const entries: HoloCiPackEntry[] = files.map((filePath) => {
    const relPath = relative(cwd, filePath).replace(/\\/g, '/');
    const { sha512, size } = hashSha512File(filePath);
    return { path: relPath, size, sha512 };
  });

  const dedup = computeDedupStats(entries);

  mkdirSync(dirname(manifestPath), { recursive: true });
  mkdirSync(dirname(sumsPath), { recursive: true });

  const v11Manifest = {
    schema: HOLO_V11_MANIFEST_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    name: manifest.name,
    kind: manifest.kind,
    entries,
    dedup,
  };

  writeFileSync(manifestPath, `${JSON.stringify(v11Manifest, null, 2)}\n`, 'utf8');
  const sumsText = entries.map((e) => `${e.sha512}  ${e.path}`).join('\n') + (entries.length ? '\n' : '');
  writeFileSync(sumsPath, sumsText, 'utf8');

  return {
    ok: true,
    outDir,
    manifestPath,
    sumsPath,
    entries,
    dedup,
  };
}
