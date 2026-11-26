import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import type {
  HoloCiGitAudit,
  HoloCiManifest,
  HoloCiSyncPair,
  HoloCiSyncPairResult,
  HoloCiSyncResult,
} from './schema.mts';

const DEFAULT_EXCLUDES = new Set(['.git', 'node_modules', '.awesome-oci']);

export function hashFileSha256(filePath: string): string {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return hash.digest('hex');
}

export function collectDirectoryHashes(dirPath: string, excludes: string[] = []): Map<string, string> {
  const result = new Map<string, string>();
  if (!existsSync(dirPath)) return result;

  const excludeSet = new Set([...DEFAULT_EXCLUDES, ...excludes]);

  function walk(current: string): void {
    const entries = readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (excludeSet.has(entry.name)) continue;
      const fullPath = join(current, entry.name);
      const relPosix = relative(dirPath, fullPath).replace(/\\/g, '/');
      if (excludeSet.has(relPosix)) continue;
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        result.set(relPosix, hashFileSha256(fullPath));
      }
    }
  }

  walk(dirPath);
  return result;
}

export function compareSyncPair(pair: HoloCiSyncPair, cwd: string): HoloCiSyncPairResult {
  const srcRoot = resolve(cwd, pair.source);
  const dstRoot = resolve(cwd, pair.target);
  const srcHashes = collectDirectoryHashes(srcRoot, pair.excludes ?? []);
  const dstHashes = collectDirectoryHashes(dstRoot, pair.excludes ?? []);

  const matched: string[] = [];
  const drifted: string[] = [];
  const missingInTarget: string[] = [];
  const extraInTarget: string[] = [];

  for (const [rel, sha] of srcHashes.entries()) {
    const dstSha = dstHashes.get(rel);
    if (dstSha === undefined) {
      missingInTarget.push(rel);
    } else if (dstSha === sha) {
      matched.push(rel);
    } else {
      drifted.push(rel);
    }
  }

  for (const rel of dstHashes.keys()) {
    if (!srcHashes.has(rel)) {
      extraInTarget.push(rel);
    }
  }

  const ok =
    existsSync(srcRoot) &&
    existsSync(dstRoot) &&
    drifted.length === 0 &&
    missingInTarget.length === 0 &&
    extraInTarget.length === 0;

  return {
    label: pair.label ?? `${pair.source} -> ${pair.target}`,
    source: pair.source,
    target: pair.target,
    ok,
    matched,
    drifted,
    missingInTarget,
    extraInTarget,
  };
}

function runGit(args: string[], cwd: string): { status: number; stdout: string } {
  const winGitShim = 'E:\\awesome-os\\bin\\git.ps1';
  const useShim = process.platform === 'win32' && existsSync(winGitShim);
  const res = useShim
    ? spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', winGitShim, ...args], {
        cwd,
        encoding: 'utf8',
      })
    : spawnSync('git', args, { cwd, encoding: 'utf8' });

  return {
    status: res.status ?? (res.error ? 1 : 0),
    stdout: (res.stdout ?? '').trim(),
  };
}

export function auditGitStatus(cwd: string): HoloCiGitAudit {
  const inside = runGit(['rev-parse', '--is-inside-work-tree'], cwd);
  if (inside.status !== 0 || inside.stdout !== 'true') {
    return {
      available: false,
      branch: '',
      headSha: '',
      clean: true,
      modified: [],
      untracked: [],
    };
  }

  const branchRes = runGit(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  const shaRes = runGit(['rev-parse', 'HEAD'], cwd);
  const statusRes = runGit(['status', '--porcelain'], cwd);

  const modified: string[] = [];
  const untracked: string[] = [];
  for (const line of statusRes.stdout.split(/\r?\n/)) {
    if (!line) continue;
    if (line.startsWith('?? ')) {
      untracked.push(line.slice(3).trim());
    } else {
      modified.push(line.slice(3).trim());
    }
  }

  return {
    available: true,
    branch: branchRes.stdout,
    headSha: shaRes.stdout,
    clean: modified.length === 0 && untracked.length === 0,
    modified,
    untracked,
  };
}

export function runSync(
  manifest: HoloCiManifest,
  options: { cwd?: string; requireCleanGit?: boolean } = {},
): HoloCiSyncResult {
  const cwd = options.cwd ?? process.cwd();
  const pairs = (manifest.syncPairs ?? []).map((pair) => compareSyncPair(pair, cwd));
  const git = auditGitStatus(cwd);

  const pairsOk = pairs.every((p) => p.ok);
  const gitOk = options.requireCleanGit ? git.clean : true;

  return {
    ok: pairsOk && gitOk,
    pairs,
    git,
  };
}
