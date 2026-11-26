import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const HOLO_CI_SCHEMA = 'holo-ci.v1' as const;
export const HOLO_CI_RECEIPT_SCHEMA = 'holo-ci.receipt.v1' as const;
export const HOLO_V11_MANIFEST_SCHEMA = 'holo-v11.manifest.v1' as const;
export const B8G_ABI_MAGIC_V3 = '0x33564742' as const;

export type HoloCiKind = 'monorepo' | 'native-fork' | 'control-plane' | 'app';
export type HoloCiPhase = 'verify' | 'sync' | 'bump' | 'pack' | 'telemetry' | 'maintain' | 'init';

export interface HoloCiGuards {
  zeroGhost?: boolean;
  zeroCasV1?: boolean;
  zeroHttpIpc?: boolean;
}

export interface HoloCiSyncPair {
  label?: string;
  source: string;
  target: string;
  excludes?: string[];
}

export interface HoloCiUpstreamPin {
  name: string;
  pinned: string;
  upstream: string;
}

export interface HoloCiCasReleaseConfig {
  outDir?: string;
  include?: string[];
  exclude?: string[];
  manifestPath?: string;
  sumsPath?: string;
}

export interface HoloCiEndpointCheck {
  name?: string;
  url: string;
  expectedStatus?: number;
  sha512?: string;
  publicKeyPem?: string;
  signatureBase64?: string;
}

export interface HoloCiManifest {
  schema: 'holo-ci.v1';
  name: string;
  kind: HoloCiKind;
  version?: string;
  tests?: string[];
  nativeGates?: string[];
  docs?: string[];
  guards?: HoloCiGuards;
  syncPairs?: HoloCiSyncPair[];
  upstreamPins?: HoloCiUpstreamPin[];
  casRelease?: HoloCiCasReleaseConfig;
  endpoints?: HoloCiEndpointCheck[];
}

export interface HoloCiCommandResult {
  command: string;
  kind: 'test' | 'nativeGate';
  exitCode: number;
  durationMs: number;
  ok: boolean;
  stdout: string;
  stderr: string;
}

export interface HoloCiDocCheckResult {
  path: string;
  exists: boolean;
}

export interface HoloCiGuardViolation {
  guard: 'zeroGhost' | 'zeroCasV1' | 'zeroHttpIpc';
  file: string;
  line: number;
  snippet: string;
}

export interface HoloCiVerifyResult {
  ok: boolean;
  tests: HoloCiCommandResult[];
  nativeGates: HoloCiCommandResult[];
  docs: HoloCiDocCheckResult[];
  guardViolations: HoloCiGuardViolation[];
}

export interface HoloCiSyncPairResult {
  label: string;
  source: string;
  target: string;
  ok: boolean;
  matched: string[];
  drifted: string[];
  missingInTarget: string[];
  extraInTarget: string[];
}

export interface HoloCiGitAudit {
  available: boolean;
  branch: string;
  headSha: string;
  clean: boolean;
  modified: string[];
  untracked: string[];
}

export interface HoloCiSyncResult {
  ok: boolean;
  pairs: HoloCiSyncPairResult[];
  git: HoloCiGitAudit;
}

export interface HoloCiPinCheckResult {
  name: string;
  pinned: string;
  upstream: string;
  ok: boolean;
  status: 'pinned-match' | 'pinned-ahead' | 'pinned-behind';
}

export interface HoloCiPackageBumpResult {
  path: string;
  previousVersion: string;
  newVersion: string;
  updated: boolean;
  dryRun: boolean;
}

export interface HoloCiBumpResult {
  ok: boolean;
  pins: HoloCiPinCheckResult[];
  packageBump?: HoloCiPackageBumpResult;
}

export interface HoloCiPackEntry {
  path: string;
  size: number;
  sha512: string;
}

export interface HoloCiPackDedupStats {
  totalAssets: number;
  uniqueSha512Blobs: number;
  dedupedBlobs: number;
  rawBytes: number;
  uniqueBytes: number;
  savedBytes: number;
  dedupRatioPct: number;
}

export interface HoloCiPackResult {
  ok: boolean;
  outDir: string;
  manifestPath: string;
  sumsPath: string;
  entries: HoloCiPackEntry[];
  dedup: HoloCiPackDedupStats;
}

export interface HoloCiEndpointResult {
  name: string;
  url: string;
  ok: boolean;
  status: number;
  expectedStatus: number;
  bytes: number;
  sha512Actual?: string;
  sha512Verified?: boolean;
  ed25519Verified?: boolean;
  error?: string;
}

export interface HoloCiMaintainResult {
  ok: boolean;
  endpoints: HoloCiEndpointResult[];
  bundleChecked: number;
  bundleMismatches: string[];
}

export interface HoloCiReceipt {
  schema: 'holo-ci.receipt.v1';
  abiMagic: '0x33564742';
  generatedAt: string;
  phase: HoloCiPhase;
  name: string;
  kind: HoloCiKind;
  ok: boolean;
  durationMs: number;
  verify?: HoloCiVerifyResult;
  sync?: HoloCiSyncResult;
  bump?: HoloCiBumpResult;
  pack?: HoloCiPackResult;
  maintain?: HoloCiMaintainResult;
  errors?: string[];
}

const VALID_KINDS = new Set<HoloCiKind>(['monorepo', 'native-fork', 'control-plane', 'app']);

interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  pre: string[];
}

function parseSemver(input: string): ParsedSemver {
  const cleaned = input.trim().replace(/^v/i, '');
  const withoutBuild = cleaned.split('+')[0] ?? cleaned;
  const dashIdx = withoutBuild.indexOf('-');
  const core = dashIdx === -1 ? withoutBuild : withoutBuild.slice(0, dashIdx);
  const preRaw = dashIdx === -1 ? '' : withoutBuild.slice(dashIdx + 1);

  const parts = core.split('.');
  if (parts.length < 1 || parts.length > 3) {
    throw new Error(`Invalid semver string: "${input}"`);
  }
  const nums = [0, 0, 0];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (!/^\d+$/.test(p)) {
      throw new Error(`Invalid semver numeric segment "${p}" in "${input}"`);
    }
    nums[i] = Number(p);
  }
  const pre = preRaw.length > 0 ? preRaw.split('.') : [];
  return {
    major: nums[0],
    minor: nums[1],
    patch: nums[2],
    pre,
  };
}

/**
 * Compare two semver strings (supports optional leading `v`, prerelease tags, ignores build metadata).
 * Returns -1 if a < b, 0 if a === b, 1 if a > b.
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);

  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;

  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;

  const len = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < len; i++) {
    const ia = pa.pre[i];
    const ib = pb.pre[i];
    if (ia === undefined) return -1;
    if (ib === undefined) return 1;
    const na = /^\d+$/.test(ia);
    const nb = /^\d+$/.test(ib);
    if (na && nb) {
      const va = Number(ia);
      const vb = Number(ib);
      if (va !== vb) return va < vb ? -1 : 1;
    } else if (na !== nb) {
      return na ? -1 : 1;
    } else if (ia !== ib) {
      return ia < ib ? -1 : 1;
    }
  }
  return 0;
}

export function validateManifest(raw: unknown): HoloCiManifest {
  if (!raw || typeof raw !== 'object') {
    throw new Error('holo-ci manifest must be a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schema !== HOLO_CI_SCHEMA) {
    throw new Error(`Unsupported holo-ci schema: "${String(obj.schema)}" (expected "${HOLO_CI_SCHEMA}")`);
  }
  if (typeof obj.name !== 'string' || obj.name.trim().length === 0) {
    throw new Error('holo-ci manifest requires a non-empty string "name"');
  }
  if (typeof obj.kind !== 'string' || !VALID_KINDS.has(obj.kind as HoloCiKind)) {
    throw new Error(`Invalid holo-ci "kind": "${String(obj.kind)}"`);
  }
  return raw as HoloCiManifest;
}

export function loadManifest(configPath = 'holo-ci.json', cwd = process.cwd()): HoloCiManifest {
  const fullPath = resolve(cwd, configPath);
  if (!existsSync(fullPath)) {
    throw new Error(`holo-ci config not found at ${fullPath}`);
  }
  const text = readFileSync(fullPath, 'utf8');
  const parsed: unknown = JSON.parse(text);
  return validateManifest(parsed);
}
