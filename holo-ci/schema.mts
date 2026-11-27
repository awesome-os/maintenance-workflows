import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { AuditStackRunResult } from './audit-stack.mts';
import type { FleetForensicsReport } from './fleet-forensics.mts';
import type { FleetWorkflowHardeningResult, HardenWorkflowsDirResult } from './wf-harden.mts';

export const HOLO_CI_SCHEMA = 'holo-ci.v1' as const;
export const HOLO_CI_RECEIPT_SCHEMA = 'holo-ci.receipt.v1' as const;
export const HOLO_V11_MANIFEST_SCHEMA = 'holo-v11.manifest.v1' as const;
export const HOLO_BOUNDARY_SCHEMA = 'holo-boundary.v1' as const;
export const HOLO_RULE_VIOLATION_SCHEMA = 'holo-rule-violation.v1' as const;
export const B8G_ABI_MAGIC_V3 = '0x33564742' as const;

export type HoloRuleSeverity = 'error' | 'warning' | 'info';
export type HoloRuleCategory =
  | 'security'
  | 'ipc'
  | 'geometry'
  | 'abi'
  | 'governance'
  | 'workflow'
  | 'docs'
  | 'brand'
  | 'telemetry';

export interface HoloRuleViolation {
  schema: typeof HOLO_RULE_VIOLATION_SCHEMA;
  ruleId: string;
  severity: HoloRuleSeverity;
  category: HoloRuleCategory;
  repo: string;
  file: string;
  line: number;
  snippet: string;
  message: string;
  autofixable: boolean;
  fingerprint: string;
}

export interface CreateRuleViolationInput {
  ruleId: string;
  severity: HoloRuleSeverity;
  category: HoloRuleCategory;
  repo: string;
  file: string;
  line?: number;
  snippet?: string;
  message: string;
  autofixable?: boolean;
  fingerprint?: string;
}

export type HoloCiKind = 'monorepo' | 'native-fork' | 'control-plane' | 'app';
export type HoloCiPhase =
  | 'verify'
  | 'sync'
  | 'bump'
  | 'pack'
  | 'telemetry'
  | 'maintain'
  | 'init'
  | 'lock-compat'
  | 'boundary-audit'
  | 'wf-harden'
  | 'audit-stack'
  | 'fleet-forensics';

export interface HoloCiGuards {
  zeroGhost?: boolean;
  zeroCasV1?: boolean;
  zeroHttpIpc?: boolean;
  spdxLicense?: boolean;
  gitattributes?: boolean;
  codeowners?: boolean;
  noBrokenBadges?: boolean;
  noWorkflowBloat?: boolean;
  maxWorkflowLines?: number;
  requireWorkflowHardening?: boolean;
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
  upstreamRepo?: string;
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
  guard:
    | 'zeroGhost'
    | 'zeroCasV1'
    | 'zeroHttpIpc'
    | 'spdxLicense'
    | 'gitattributes'
    | 'codeowners'
    | 'noBrokenBadges'
    | 'noWorkflowBloat'
    | 'requireWorkflowHardening';
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
  bumpedCount?: number;
  bumpedPins?: string[];
  applied?: boolean;
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
  casRoot?: string;
  casWrittenFiles?: number;
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

export interface HoloCiLockCompatPackageEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
  dev?: boolean;
  workspaces?: string[];
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  holoCasStore?: 'v11';
  zeroCopyNodeModules?: boolean;
}

export interface HoloCiLockfileV3 {
  name: string;
  version: string;
  lockfileVersion: 3;
  requires: true;
  holoCasStore: 'v11';
  zeroCopyNodeModules: true;
  packages: Record<string, HoloCiLockCompatPackageEntry>;
}

export type HoloCiLockCompatEcosystem =
  | 'all'
  | 'npm'
  | 'cargo'
  | 'uv'
  | 'go'
  | 'vcpkg'
  | 'winget'
  | 'apt'
  | 'composer'
  | 'rubygems';

export type HoloCiLockCompatSingleEcosystem = Exclude<HoloCiLockCompatEcosystem, 'all'>;

export interface HoloCiLockCompatArtifact {
  ecosystem: HoloCiLockCompatSingleEcosystem;
  path: string;
  relPath: string;
  bytes: number;
  sha256: string;
  written: boolean;
}

export interface HoloCiLockCompatResult {
  ok: boolean;
  ecosystem: HoloCiLockCompatEcosystem;
  ecosystemsGenerated: HoloCiLockCompatSingleEcosystem[];
  name: string;
  version: string;
  outFile: string;
  outDir: string;
  dryRun: boolean;
  written: boolean;
  lockfileVersion: 3;
  holoCasStore: 'v11';
  zeroCopyNodeModules: true;
  packageCount: number;
  workspaceCount: number;
  resolvedFromPnpmLock: number;
  resolvedFromMaxLock: number;
  sha256: string;
  artifacts: HoloCiLockCompatArtifact[];
  lockfile?: HoloCiLockfileV3;
}

export type HoloBoundaryPlane = 1 | 2 | 3 | 4 | 5;

export interface HoloBoundaryLayerRule {
  prefix: string;
  rank: number;
}

export interface HoloBoundaryManifest {
  schema: 'holo-boundary.v1';
  plane?: HoloBoundaryPlane;
  publicEntrypoints?: string[];
  includePaths?: string[];
  excludeDirs?: string[];
  allowedImports?: string[];
  forbiddenImports?: string[];
  maxParentTraversals?: number;
  scanSourceHttpIpc?: boolean;
  abiGoldenFiles?: string[];
  enforceDag?: boolean;
  enforceLayers?: boolean;
  layerRules?: HoloBoundaryLayerRule[];
  allowedGeometryEdges?: string[];
}

export type HoloCiBoundaryRule =
  | 'boundaryManifest'
  | 'forbiddenImport'
  | 'parentTraversal'
  | 'httpIpc'
  | 'abiGolden'
  | 'cyclicImport'
  | 'layerInversion';

export interface HoloCiBoundaryViolation {
  rule: HoloCiBoundaryRule;
  file: string;
  line: number;
  snippet: string;
  message: string;
}

export interface HoloCiBoundaryAxes {
  dependencyPurity: number;
  encapsulation: number;
  ipcCompliance: number;
  abiContract: number;
  governance: number;
}

export interface HoloCiBoundaryResult {
  ok: boolean;
  score: number;
  manifestFound: boolean;
  boundaryPath?: string;
  plane?: HoloBoundaryPlane;
  scannedFiles: number;
  axes: HoloCiBoundaryAxes;
  violations: HoloCiBoundaryViolation[];
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
  lockCompat?: HoloCiLockCompatResult;
  boundaryAudit?: HoloCiBoundaryResult;
  wfHarden?: HardenWorkflowsDirResult;
  wfHardenFleet?: FleetWorkflowHardeningResult;
  auditStack?: AuditStackRunResult;
  fleetForensics?: FleetForensicsReport;
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

/**
 * Computes a deterministic 16-character lowercase hex SHA-256 fingerprint for a rule violation.
 */
export function computeViolationFingerprint(
  ruleId: string,
  repo: string,
  file: string,
  message: string,
): string {
  const normalizedFile = file.replace(/\\/g, '/');
  return createHash('sha256')
    .update(`${ruleId}\0${repo}\0${normalizedFile}\0${message}`)
    .digest('hex')
    .slice(0, 16);
}

/**
 * Constructs a canonical `holo-rule-violation.v1` IR record with deterministic fingerprint.
 */
export function createRuleViolation(input: CreateRuleViolationInput): HoloRuleViolation {
  const normalizedFile = input.file.replace(/\\/g, '/');
  const line =
    typeof input.line === 'number' && Number.isFinite(input.line) && input.line > 0
      ? Math.trunc(input.line)
      : 1;
  const snippet = (input.snippet ?? '').slice(0, 160);
  const fingerprint =
    input.fingerprint ?? computeViolationFingerprint(input.ruleId, input.repo, normalizedFile, input.message);

  return {
    schema: HOLO_RULE_VIOLATION_SCHEMA,
    ruleId: input.ruleId,
    severity: input.severity,
    category: input.category,
    repo: input.repo,
    file: normalizedFile,
    line,
    snippet,
    message: input.message,
    autofixable: Boolean(input.autofixable),
    fingerprint,
  };
}

interface GuardRuleMeta {
  readonly ruleId: string;
  readonly severity: HoloRuleSeverity;
  readonly category: HoloRuleCategory;
  readonly autofixable: boolean;
  readonly formatMessage: (snippet: string) => string;
}

const GUARD_RULE_META: Record<HoloCiGuardViolation['guard'], GuardRuleMeta> = {
  zeroGhost: {
    ruleId: 'holo.brand.zero-ghost',
    severity: 'error',
    category: 'brand',
    autofixable: false,
    formatMessage: (snippet) => `Forbidden legacy ghost identifier detected: ${snippet}`,
  },
  zeroCasV1: {
    ruleId: 'holo.governance.zero-cas-v1',
    severity: 'error',
    category: 'governance',
    autofixable: false,
    formatMessage: (snippet) => `Forbidden legacy CAS v1 reference detected: ${snippet}`,
  },
  zeroHttpIpc: {
    ruleId: 'B8G016',
    severity: 'error',
    category: 'ipc',
    autofixable: false,
    formatMessage: (snippet) => `B8G016 violation: illegal loopback HTTP IPC binding (${snippet})`,
  },
  spdxLicense: {
    ruleId: 'holo.governance.spdx-license',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    formatMessage: (snippet) => snippet,
  },
  gitattributes: {
    ruleId: 'holo.governance.gitattributes',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    formatMessage: (snippet) => snippet,
  },
  codeowners: {
    ruleId: 'holo.governance.codeowners',
    severity: 'error',
    category: 'governance',
    autofixable: true,
    formatMessage: (snippet) => snippet,
  },
  noBrokenBadges: {
    ruleId: 'holo.docs.no-broken-badges',
    severity: 'warning',
    category: 'docs',
    autofixable: true,
    formatMessage: (snippet) => `Broken Shields.io badge encoding (%2F): ${snippet}`,
  },
  noWorkflowBloat: {
    ruleId: 'holo.workflow.no-bloat',
    severity: 'error',
    category: 'workflow',
    autofixable: false,
    formatMessage: (snippet) => snippet,
  },
  requireWorkflowHardening: {
    ruleId: 'holo.workflow.hardening',
    severity: 'error',
    category: 'workflow',
    autofixable: true,
    formatMessage: (snippet) => snippet,
  },
};

/**
 * Adapts a `HoloCiGuardViolation` into a universal `HoloRuleViolation` IR object.
 */
export function guardViolationToRuleViolation(v: HoloCiGuardViolation, repo: string): HoloRuleViolation {
  const meta = GUARD_RULE_META[v.guard];
  return createRuleViolation({
    ruleId: meta.ruleId,
    severity: meta.severity,
    category: meta.category,
    repo,
    file: v.file,
    line: v.line,
    snippet: v.snippet,
    message: meta.formatMessage(v.snippet),
    autofixable: meta.autofixable,
  });
}

interface BoundaryRuleMeta {
  readonly ruleId: string;
  readonly severity: HoloRuleSeverity;
  readonly category: HoloRuleCategory;
  readonly autofixable: boolean;
}

const BOUNDARY_RULE_META: Record<HoloCiBoundaryRule, BoundaryRuleMeta> = {
  boundaryManifest: {
    ruleId: 'holo.geometry.boundary-manifest',
    severity: 'error',
    category: 'governance',
    autofixable: false,
  },
  forbiddenImport: {
    ruleId: 'holo.geometry.forbidden-import',
    severity: 'error',
    category: 'geometry',
    autofixable: false,
  },
  parentTraversal: {
    ruleId: 'holo.geometry.parent-traversal',
    severity: 'error',
    category: 'geometry',
    autofixable: false,
  },
  httpIpc: {
    ruleId: 'B8G016',
    severity: 'error',
    category: 'ipc',
    autofixable: false,
  },
  abiGolden: {
    ruleId: 'holo.abi.golden',
    severity: 'error',
    category: 'abi',
    autofixable: false,
  },
  cyclicImport: {
    ruleId: 'holo.geometry.cyclic-import',
    severity: 'error',
    category: 'geometry',
    autofixable: false,
  },
  layerInversion: {
    ruleId: 'holo.geometry.layer-inversion',
    severity: 'error',
    category: 'geometry',
    autofixable: false,
  },
};

/**
 * Adapts a `HoloCiBoundaryViolation` into a universal `HoloRuleViolation` IR object.
 */
export function boundaryViolationToRuleViolation(
  v: HoloCiBoundaryViolation,
  repo: string,
): HoloRuleViolation {
  const meta = BOUNDARY_RULE_META[v.rule];
  return createRuleViolation({
    ruleId: meta.ruleId,
    severity: meta.severity,
    category: meta.category,
    repo,
    file: v.file,
    line: v.line,
    snippet: v.snippet,
    message: v.message,
    autofixable: meta.autofixable,
  });
}
