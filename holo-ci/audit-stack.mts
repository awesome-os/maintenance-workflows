/**
 * @file holo-ci/audit-stack.mts
 * @description Pluggable Programmatic Audit Stack Registry & Continuous Ratification Runner.
 *
 * Supports concurrent `'fail-fast'` (AbortController cancellation on first breach) and
 * `'exhaust'` (full parallel sweep for maximum failing telemetry) execution over registered
 * programmatic audits, emitting canonical `holo-rule-violation.v1` JSONL telemetry and
 * `b8g.audit-push.v1` payloads for `holo-v11/scripts/audit-stack-hub.mts --ingest`.
 *
 * Strictly `erasableSyntaxOnly: true`, zero external npm dependencies, zero loopback HTTP IPC.
 */

import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, relative, resolve } from 'node:path';
import { runBoundaryAudit } from './boundary.mts';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_RULE_VIOLATION_SCHEMA,
  boundaryViolationToRuleViolation,
  createRuleViolation,
  guardViolationToRuleViolation,
  loadManifest,
  type HoloRuleCategory,
  type HoloRuleSeverity,
  type HoloRuleViolation,
} from './schema.mts';
import { checkRepoGovernance, scanGuardViolations } from './verify.mts';
import { runWorkflowHardening } from './wf-harden.mts';

export const HOLO_AUDIT_PUSH_SCHEMA = 'b8g.audit-push.v1' as const;
export const HOLO_AUDIT_STACK_RESULT_SCHEMA = 'b8g.audit-stack-run.v1' as const;

export const BUILTIN_HOLO_CI_AUDIT_IDS = [
  'holo-ci/wf-harden',
  'holo-ci/governance',
  'holo-ci/boundary',
  'holo-ci/guards',
  'holo-ci/non-github-io-cname',
  'holo-ci/erasable-syntax',
  'holo-ci/secret-scan',
  'holo-ci/no-broken-local-links',
  'holo-ci/dead-exports',
  'holo-ci/binary-budget',
  'holo-ci/test-hermeticity',
  'holo-ci/spdx-header',
  'holo-ci/abi-surface',
] as const;

export type AuditStackMode = 'fail-fast' | 'exhaust';
export type ProgrammaticAuditEntryStatus = 'passed' | 'failed' | 'aborted';

export interface ProgrammaticAuditContext {
  readonly cwd: string;
  readonly repo: string;
  readonly signal: AbortSignal;
}

export interface ProgrammaticAuditSpec {
  readonly id: string;
  readonly title: string;
  readonly category: HoloRuleCategory;
  readonly severity: HoloRuleSeverity;
  readonly rollbackHint: string;
  readonly remediationCmd: string;
  run(ctx: ProgrammaticAuditContext): Promise<HoloRuleViolation[]> | HoloRuleViolation[];
}

export interface ProgrammaticAuditEntryResult {
  readonly id: string;
  readonly title: string;
  readonly category: HoloRuleCategory;
  readonly severity: HoloRuleSeverity;
  readonly rollbackHint: string;
  readonly remediationCmd: string;
  readonly status: ProgrammaticAuditEntryStatus;
  readonly ok: boolean;
  readonly aborted: boolean;
  readonly violationCount: number;
  readonly durationMs: number;
  readonly violations: HoloRuleViolation[];
  readonly error?: string;
}

export interface HoloAuditPushAuditSummary {
  readonly id: string;
  readonly title: string;
  readonly category: HoloRuleCategory;
  readonly severity: HoloRuleSeverity;
  readonly status: ProgrammaticAuditEntryStatus;
  readonly ok: boolean;
  readonly aborted: boolean;
  readonly violationCount: number;
  readonly durationMs: number;
  readonly rollbackHint: string;
  readonly remediationCmd: string;
}

export interface HoloAuditPushPayload {
  readonly schema: typeof HOLO_AUDIT_PUSH_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly repo: string;
  readonly mode: AuditStackMode;
  readonly ok: boolean;
  readonly ratified: boolean;
  readonly failedFast: boolean;
  readonly totalAudits: number;
  readonly passedAudits: number;
  readonly failedAudits: number;
  readonly abortedAudits: number;
  readonly violationCount: number;
  readonly durationMs: number;
  readonly audits: HoloAuditPushAuditSummary[];
  readonly violations: HoloRuleViolation[];
  readonly violationCountsByRule: Record<string, number>;
  readonly fingerprints: string[];
}

export interface AuditStackRunResult {
  readonly schema: typeof HOLO_AUDIT_STACK_RESULT_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly repo: string;
  readonly mode: AuditStackMode;
  readonly ok: boolean;
  readonly ratified: boolean;
  readonly failedFast: boolean;
  readonly totalAudits: number;
  readonly passedAudits: number;
  readonly failedAudits: number;
  readonly abortedAudits: number;
  readonly violationCount: number;
  readonly durationMs: number;
  readonly entries: ProgrammaticAuditEntryResult[];
  readonly violations: HoloRuleViolation[];
  readonly pushPayload: HoloAuditPushPayload;
  readonly telemetryOutPath?: string;
  readonly pushOutPath?: string;
}

export interface AuditStackRunOptions {
  readonly cwd?: string;
  readonly repo?: string;
  readonly mode?: AuditStackMode;
  readonly onlyIds?: readonly string[];
  readonly concurrency?: number;
  readonly telemetryOutPath?: string;
  readonly pushOutPath?: string;
  readonly signal?: AbortSignal;
}

export interface AuditStackRegistry {
  register(spec: ProgrammaticAuditSpec): AuditStackRegistry;
  list(): ProgrammaticAuditSpec[];
  get(id: string): ProgrammaticAuditSpec | undefined;
  remove(id: string): boolean;
  run(options?: AuditStackRunOptions): Promise<AuditStackRunResult>;
}

function resolveDefaultRepoName(cwd: string): string {
  const manifestPath = resolve(cwd, 'holo-ci.json');
  if (existsSync(manifestPath)) {
    try {
      const manifest = loadManifest('holo-ci.json', cwd);
      if (manifest.name.trim().length > 0) {
        return manifest.name;
      }
    } catch {
      // Fallback to directory basename when holo-ci.json is absent or malformed
    }
  }
  return basename(cwd);
}

function readManifestDocFiles(cwd: string): string[] {
  const manifestPath = resolve(cwd, 'holo-ci.json');
  if (!existsSync(manifestPath)) return [];
  try {
    const manifest = loadManifest('holo-ci.json', cwd);
    return Array.isArray(manifest.docs) ? manifest.docs : [];
  } catch {
    return [];
  }
}

function normalizeViolation(raw: HoloRuleViolation, fallbackRepo: string): HoloRuleViolation {
  if (
    raw &&
    raw.schema === HOLO_RULE_VIOLATION_SCHEMA &&
    typeof raw.fingerprint === 'string' &&
    raw.fingerprint.length > 0
  ) {
    return raw;
  }
  return createRuleViolation({
    ruleId: raw.ruleId,
    severity: raw.severity,
    category: raw.category,
    repo: raw.repo || fallbackRepo,
    file: raw.file || '.',
    line: raw.line,
    snippet: raw.snippet,
    message: raw.message,
    autofixable: raw.autofixable,
    fingerprint: raw.fingerprint,
  });
}

function executeSingleAudit(
  spec: ProgrammaticAuditSpec,
  ctx: ProgrammaticAuditContext,
): Promise<{
  readonly aborted: boolean;
  readonly violations: HoloRuleViolation[];
  readonly durationMs: number;
  readonly error?: string;
}> {
  if (ctx.signal.aborted) {
    return Promise.resolve({ aborted: true, violations: [], durationMs: 0 });
  }

  const start = Date.now();
  return new Promise((resolveRun) => {
    let settled = false;

    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      resolveRun({
        aborted: true,
        violations: [],
        durationMs: Date.now() - start,
      });
    };

    ctx.signal.addEventListener('abort', onAbort, { once: true });

    Promise.resolve()
      .then(() => {
        if (settled || ctx.signal.aborted) {
          return null;
        }
        return spec.run(ctx);
      })
      .then(
        (rawResult) => {
          ctx.signal.removeEventListener('abort', onAbort);
          if (settled) return;
          settled = true;

          if (rawResult === null) {
            resolveRun({
              aborted: true,
              violations: [],
              durationMs: Date.now() - start,
            });
            return;
          }

          const list = Array.isArray(rawResult)
            ? rawResult.map((v) => normalizeViolation(v, ctx.repo))
            : [];

          if (ctx.signal.aborted && list.length === 0) {
            resolveRun({
              aborted: true,
              violations: [],
              durationMs: Date.now() - start,
            });
            return;
          }

          resolveRun({
            aborted: false,
            violations: list,
            durationMs: Date.now() - start,
          });
        },
        (err) => {
          ctx.signal.removeEventListener('abort', onAbort);
          if (settled) return;
          settled = true;

          if (ctx.signal.aborted) {
            resolveRun({
              aborted: true,
              violations: [],
              durationMs: Date.now() - start,
            });
            return;
          }

          const errMsg = err instanceof Error ? err.message : String(err);
          resolveRun({
            aborted: false,
            violations: [
              createRuleViolation({
                ruleId: spec.id,
                severity: spec.severity,
                category: spec.category,
                repo: ctx.repo,
                file: '.',
                line: 1,
                snippet: errMsg,
                message: `Programmatic audit "${spec.id}" threw an error: ${errMsg}`,
                autofixable: false,
              }),
            ],
            durationMs: Date.now() - start,
            error: errMsg,
          });
        },
      );
  });
}

function makeAbortedEntry(spec: ProgrammaticAuditSpec, durationMs = 0): ProgrammaticAuditEntryResult {
  return {
    id: spec.id,
    title: spec.title,
    category: spec.category,
    severity: spec.severity,
    rollbackHint: spec.rollbackHint,
    remediationCmd: spec.remediationCmd,
    status: 'aborted',
    ok: false,
    aborted: true,
    violationCount: 0,
    durationMs,
    violations: [],
  };
}

/**
 * Creates a pluggable Programmatic Audit Stack Registry supporting concurrent `'fail-fast'`
 * (AbortController cancellation) and `'exhaust'` (maximum failing telemetry) execution modes.
 */
export function createAuditStackRegistry(): AuditStackRegistry {
  const specs = new Map<string, ProgrammaticAuditSpec>();

  const registry: AuditStackRegistry = {
    register(spec: ProgrammaticAuditSpec): AuditStackRegistry {
      if (!spec || typeof spec.id !== 'string' || spec.id.trim().length === 0) {
        throw new Error('ProgrammaticAuditSpec requires a non-empty string "id"');
      }
      if (typeof spec.run !== 'function') {
        throw new Error(`ProgrammaticAuditSpec "${spec.id}" requires a "run(ctx)" function`);
      }
      specs.set(spec.id, spec);
      return registry;
    },

    list(): ProgrammaticAuditSpec[] {
      return [...specs.values()];
    },

    get(id: string): ProgrammaticAuditSpec | undefined {
      return specs.get(id);
    },

    remove(id: string): boolean {
      return specs.delete(id);
    },

    async run(options: AuditStackRunOptions = {}): Promise<AuditStackRunResult> {
      const start = Date.now();
      const cwd = resolve(options.cwd ?? process.cwd());
      const repo =
        typeof options.repo === 'string' && options.repo.trim().length > 0
          ? options.repo.trim()
          : resolveDefaultRepoName(cwd);
      const mode: AuditStackMode = options.mode ?? 'fail-fast';
      if (mode !== 'fail-fast' && mode !== 'exhaust') {
        throw new Error(`Unsupported audit-stack mode "${String(mode)}" (expected "fail-fast" or "exhaust")`);
      }

      const selectedSpecs =
        options.onlyIds !== undefined
          ? (() => {
              const wanted = new Set(options.onlyIds);
              return [...specs.values()].filter((s) => wanted.has(s.id));
            })()
          : [...specs.values()];

      const controller = new AbortController();
      const externalSignal = options.signal;
      const forwardExternalAbort = (): void => {
        if (!controller.signal.aborted) {
          controller.abort(externalSignal?.reason ?? new Error('Audit stack aborted by caller signal'));
        }
      };

      if (externalSignal) {
        if (externalSignal.aborted) {
          forwardExternalAbort();
        } else {
          externalSignal.addEventListener('abort', forwardExternalAbort, { once: true });
        }
      }

      const entries: ProgrammaticAuditEntryResult[] = new Array(selectedSpecs.length);
      let failedFastTriggered = false;

      const requestedConcurrency =
        typeof options.concurrency === 'number' &&
        Number.isFinite(options.concurrency) &&
        options.concurrency >= 1
          ? Math.trunc(options.concurrency)
          : Math.max(1, selectedSpecs.length);
      const workerCount = Math.min(Math.max(1, selectedSpecs.length), requestedConcurrency);

      let nextIndex = 0;

      const worker = async (): Promise<void> => {
        while (true) {
          const idx = nextIndex++;
          if (idx >= selectedSpecs.length) return;
          const spec = selectedSpecs[idx]!;

          if (controller.signal.aborted) {
            entries[idx] = makeAbortedEntry(spec, 0);
            continue;
          }

          const outcome = await executeSingleAudit(spec, {
            cwd,
            repo,
            signal: controller.signal,
          });

          if (outcome.aborted) {
            entries[idx] = makeAbortedEntry(spec, outcome.durationMs);
            continue;
          }

          const passed = outcome.violations.length === 0 && outcome.error === undefined;
          entries[idx] = {
            id: spec.id,
            title: spec.title,
            category: spec.category,
            severity: spec.severity,
            rollbackHint: spec.rollbackHint,
            remediationCmd: spec.remediationCmd,
            status: passed ? 'passed' : 'failed',
            ok: passed,
            aborted: false,
            violationCount: outcome.violations.length,
            durationMs: outcome.durationMs,
            violations: outcome.violations,
            ...(outcome.error !== undefined ? { error: outcome.error } : {}),
          };

          if (!passed && mode === 'fail-fast' && !controller.signal.aborted) {
            failedFastTriggered = true;
            controller.abort(
              new Error(`Fail-fast triggered by audit "${spec.id}" (${outcome.violations.length} violation(s))`),
            );
          }
        }
      };

      try {
        if (selectedSpecs.length > 0) {
          await Promise.all(Array.from({ length: workerCount }, () => worker()));
        }
      } finally {
        if (externalSignal) {
          externalSignal.removeEventListener('abort', forwardExternalAbort);
        }
      }

      let passedAudits = 0;
      let failedAudits = 0;
      let abortedAudits = 0;
      const violations: HoloRuleViolation[] = [];
      const violationCountsByRule: Record<string, number> = {};
      const fingerprintSet = new Set<string>();

      for (const entry of entries) {
        if (entry.status === 'passed') {
          passedAudits++;
        } else if (entry.status === 'failed') {
          failedAudits++;
        } else {
          abortedAudits++;
        }
        for (const v of entry.violations) {
          violations.push(v);
          violationCountsByRule[v.ruleId] = (violationCountsByRule[v.ruleId] ?? 0) + 1;
          fingerprintSet.add(v.fingerprint);
        }
      }

      const durationMs = Date.now() - start;
      const generatedAt = new Date().toISOString();
      const totalAudits = entries.length;
      const ok = failedAudits === 0 && abortedAudits === 0 && violations.length === 0;
      const ratified = ok;
      const failedFast = mode === 'fail-fast' && failedFastTriggered;

      const pushPayload: HoloAuditPushPayload = {
        schema: HOLO_AUDIT_PUSH_SCHEMA,
        abiMagic: B8G_ABI_MAGIC_V3,
        generatedAt,
        repo,
        mode,
        ok,
        ratified,
        failedFast,
        totalAudits,
        passedAudits,
        failedAudits,
        abortedAudits,
        violationCount: violations.length,
        durationMs,
        audits: entries.map((e) => ({
          id: e.id,
          title: e.title,
          category: e.category,
          severity: e.severity,
          status: e.status,
          ok: e.ok,
          aborted: e.aborted,
          violationCount: e.violationCount,
          durationMs: e.durationMs,
          rollbackHint: e.rollbackHint,
          remediationCmd: e.remediationCmd,
        })),
        violations,
        violationCountsByRule,
        fingerprints: [...fingerprintSet],
      };

      let writtenTelemetryPath: string | undefined;
      if (options.telemetryOutPath) {
        const absTelemetry = resolve(cwd, options.telemetryOutPath);
        mkdirSync(dirname(absTelemetry), { recursive: true });
        const jsonlPayload =
          violations.length > 0
            ? `${violations.map((v) => JSON.stringify(v)).join('\n')}\n`
            : '';
        appendFileSync(absTelemetry, jsonlPayload, 'utf8');
        writtenTelemetryPath = absTelemetry;
      }

      let writtenPushPath: string | undefined;
      if (options.pushOutPath) {
        const absPush = resolve(cwd, options.pushOutPath);
        mkdirSync(dirname(absPush), { recursive: true });
        writeFileSync(absPush, `${JSON.stringify(pushPayload, null, 2)}\n`, 'utf8');
        writtenPushPath = absPush;
      }

      return {
        schema: HOLO_AUDIT_STACK_RESULT_SCHEMA,
        abiMagic: B8G_ABI_MAGIC_V3,
        generatedAt,
        repo,
        mode,
        ok,
        ratified,
        failedFast,
        totalAudits,
        passedAudits,
        failedAudits,
        abortedAudits,
        violationCount: violations.length,
        durationMs,
        entries,
        violations,
        pushPayload,
        ...(writtenTelemetryPath ? { telemetryOutPath: writtenTelemetryPath } : {}),
        ...(writtenPushPath ? { pushOutPath: writtenPushPath } : {}),
      };
    },
  };

  return registry;
}

const DEFAULT_SCAN_SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'target',
  'out',
  'archive',
  'third_party',
  'deps',
  'v8',
  'v8_monolith',
  'github-mirror',
  'github-releases-mirror',
  'repository',
  't2-release',
  '.b8g-cas',
  '.awesome-oci',
  '.tmp-snapshots',
  'models',
  'electron-docs',
  'fdir',
  '.holo-ci-runtime',
  'Apps',
]);

const BINARY_SCAN_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.webp',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.wasm',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.zip',
  '.tar',
  '.gz',
  '.7z',
  '.b8p',
  '.b8e',
  '.pdf',
  '.bin',
  '.lockb',
]);

const MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024;

function walkRepoFiles(
  rootDir: string,
  signal?: AbortSignal,
  skipDirs: ReadonlySet<string> = DEFAULT_SCAN_SKIP_DIRS,
): string[] {
  if (!existsSync(rootDir)) return [];
  const results: string[] = [];

  const visit = (dir: string): void => {
    if (signal?.aborted) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (signal?.aborted) return;
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        visit(fullPath);
      } else if (entry.isFile()) {
        results.push(relative(rootDir, fullPath).replaceAll('\\', '/'));
      }
    }
  };

  visit(rootDir);
  return results;
}

/**
 * Replaces comments (`//`, `/* * /`) and string/template literals with spaces while
 * preserving newlines so 1-based line numbers remain exact.
 */
function stripTsCommentsAndStrings(source: string): string {
  const out: string[] = [];
  let i = 0;
  const len = source.length;
  while (i < len) {
    const ch = source[i]!;
    const next = i + 1 < len ? source[i + 1]! : '';

    if (ch === '/' && next === '/') {
      out.push('  ');
      i += 2;
      while (i < len && source[i] !== '\n') {
        out.push(' ');
        i++;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      out.push('  ');
      i += 2;
      while (i < len) {
        if (source[i] === '*' && i + 1 < len && source[i + 1] === '/') {
          out.push('  ');
          i += 2;
          break;
        }
        out.push(source[i] === '\n' ? '\n' : ' ');
        i++;
      }
      continue;
    }

    if (ch === '\'' || ch === '"' || ch === '`') {
      const quote = ch;
      out.push(' ');
      i++;
      while (i < len) {
        const cur = source[i]!;
        if (cur === '\\' && i + 1 < len) {
          out.push(' ');
          out.push(source[i + 1] === '\n' ? '\n' : ' ');
          i += 2;
          continue;
        }
        if (cur === quote) {
          out.push(' ');
          i++;
          break;
        }
        out.push(cur === '\n' ? '\n' : ' ');
        i++;
      }
      continue;
    }

    out.push(ch);
    i++;
  }
  return out.join('');
}

function lineNumberAtOffset(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

function scanErasableSyntaxViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const files = walkRepoFiles(ctx.cwd, ctx.signal);
  const violations: HoloRuleViolation[] = [];

  const rules: ReadonlyArray<{ label: string; regex: RegExp }> = [
    {
      label: 'enum declaration',
      regex: /^[ \t]*(?:export[ \t]+)?(?:const[ \t]+)?enum[ \t]+[A-Za-z_$][\w$]*[ \t]*\{/gm,
    },
    {
      label: 'namespace declaration',
      regex: /^[ \t]*(?:export[ \t]+)?(?:declare[ \t]+)?namespace[ \t]+[A-Za-z_$][\w$.]*[ \t]*\{/gm,
    },
    {
      label: 'constructor parameter property',
      regex: /\bconstructor\s*\([^)]*\b(?:public|private|protected|readonly)\s+[A-Za-z_$][\w$]*\s*(?:[:=,)?])/g,
    },
  ];

  for (const relFile of files) {
    if (ctx.signal.aborted) return violations;
    if (!relFile.endsWith('.mts') && !relFile.endsWith('.ts')) continue;
    if (relFile.endsWith('.d.mts') || relFile.endsWith('.d.ts')) continue;

    const absFile = resolve(ctx.cwd, relFile);
    let raw: string;
    try {
      if (statSync(absFile).size > MAX_SCAN_FILE_BYTES) continue;
      raw = readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }

    const stripped = stripTsCommentsAndStrings(raw);
    const rawLines = raw.split(/\r?\n/);

    for (const rule of rules) {
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(stripped)) !== null) {
        const line = lineNumberAtOffset(stripped, match.index);
        const snippet = (rawLines[line - 1] ?? '').trim().slice(0, 160);
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-ERASABLE-SYNTAX',
            severity: 'error',
            category: 'abi',
            repo: ctx.repo,
            file: relFile,
            line,
            snippet,
            message: `Non-erasable TypeScript syntax (${rule.label}) violates erasableSyntaxOnly: true`,
            autofixable: false,
          }),
        );
      }
    }
  }

  return violations;
}

function redactSecretSnippet(line: string, match: RegExpExecArray): string {
  const token = match[0];
  const prefix = token.slice(0, Math.min(6, token.length));
  const redacted = `${prefix}***REDACTED***`;
  const before = line.slice(0, match.index);
  const after = line.slice(match.index + token.length);
  return `${before}${redacted}${after}`.trim().slice(0, 160);
}

function scanSecretViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const files = walkRepoFiles(ctx.cwd, ctx.signal);
  const violations: HoloRuleViolation[] = [];

  const secretPatterns: ReadonlyArray<{ label: string; regex: RegExp }> = [
    { label: 'GitHub classic personal access token (ghp_)', regex: /\bghp_[A-Za-z0-9_]{8,}/ },
    { label: 'GitHub fine-grained PAT (github_pat_)', regex: /\bgithub_pat_[A-Za-z0-9_]{8,}/ },
    { label: 'Google API key (AIza)', regex: /\bAIza[0-9A-Za-z_-]{12,}/ },
    { label: 'AWS access key ID (AKIA)', regex: /\bAKIA[0-9A-Z]{12,}/ },
    { label: 'Private key PEM header', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  ];

  for (const relFile of files) {
    if (ctx.signal.aborted) return violations;
    if (BINARY_SCAN_EXTENSIONS.has(extname(relFile).toLowerCase())) continue;

    const absFile = resolve(ctx.cwd, relFile);
    let raw: string;
    try {
      if (statSync(absFile).size > MAX_SCAN_FILE_BYTES) continue;
      raw = readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }

    if (raw.includes('\0')) continue;
    if (
      !raw.includes('ghp_') &&
      !raw.includes('github_pat_') &&
      !raw.includes('AIza') &&
      !raw.includes('AKIA') &&
      !raw.includes('PRIVATE KEY-----')
    ) {
      continue;
    }
    const lines = raw.split(/\r?\n/);
    const header = lines.slice(0, 5).join('\n');
    if (header.includes('holo-ci-allow-secret') || header.includes('holo-ci-test-fixture')) {
      continue;
    }

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx]!;
      if (line.includes('holo-ci-allow-secret') || line.includes('holo-ci-test-fixture')) {
        continue;
      }
      for (const pattern of secretPatterns) {
        const match = pattern.regex.exec(line);
        if (!match) continue;
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-SECRET-SCAN',
            severity: 'error',
            category: 'security',
            repo: ctx.repo,
            file: relFile,
            line: idx + 1,
            snippet: redactSecretSnippet(line, match),
            message: `High-confidence ${pattern.label} detected; remove secret or mark intentional fixtures with holo-ci-allow-secret`,
            autofixable: false,
          }),
        );
      }
    }
  }

  return violations;
}

function scanBrokenLocalLinkViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const mdRelPaths: string[] = [];
  if (existsSync(resolve(ctx.cwd, 'README.md'))) {
    mdRelPaths.push('README.md');
  }
  const docsDir = resolve(ctx.cwd, 'docs');
  if (existsSync(docsDir)) {
    const docFiles = walkRepoFiles(docsDir, ctx.signal);
    for (const relDoc of docFiles) {
      if (relDoc.toLowerCase().endsWith('.md')) {
        mdRelPaths.push(`docs/${relDoc}`);
      }
    }
  }

  const violations: HoloRuleViolation[] = [];
  const linkRegex = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;

  for (const relMd of mdRelPaths) {
    if (ctx.signal.aborted) return violations;
    const absMd = resolve(ctx.cwd, relMd);
    let raw: string;
    try {
      raw = readFileSync(absMd, 'utf8');
    } catch {
      continue;
    }

    const lines = raw.split(/\r?\n/);
    let inFence = false;
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx]!;
      const trimmed = line.trimStart();
      if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) {
        inFence = !inFence;
        continue;
      }
      if (inFence) continue;

      const withoutInlineCode = line.replace(/`[^`]*`/g, '');
      linkRegex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = linkRegex.exec(withoutInlineCode)) !== null) {
        const rawTarget = match[1]!;
        if (!rawTarget.startsWith('./') && !rawTarget.startsWith('../')) continue;
        const cleanTarget = rawTarget.split('#')[0]!.split('?')[0]!;
        if (cleanTarget.length === 0) continue;

        const resolvedTarget = resolve(dirname(absMd), cleanTarget);
        if (!existsSync(resolvedTarget)) {
          violations.push(
            createRuleViolation({
              ruleId: 'B8G-BROKEN-LOCAL-LINK',
              severity: 'error',
              category: 'docs',
              repo: ctx.repo,
              file: relMd,
              line: idx + 1,
              snippet: rawTarget.slice(0, 160),
              message: `Broken local relative markdown link "${rawTarget}" (target does not exist on disk)`,
              autofixable: false,
            }),
          );
        }
      }
    }
  }

  return violations;
}

function stripCommentsPreservingNewlines(source: string): string {
  const out: string[] = [];
  let i = 0;
  const len = source.length;
  while (i < len) {
    const ch = source[i]!;
    const next = i + 1 < len ? source[i + 1]! : '';

    if (ch === '/' && next === '/') {
      out.push('  ');
      i += 2;
      while (i < len && source[i] !== '\n') {
        out.push(' ');
        i++;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      out.push('  ');
      i += 2;
      while (i < len) {
        if (source[i] === '*' && i + 1 < len && source[i + 1] === '/') {
          out.push('  ');
          i += 2;
          break;
        }
        out.push(source[i] === '\n' ? '\n' : ' ');
        i++;
      }
      continue;
    }

    if (ch === '\'' || ch === '"' || ch === '`') {
      const quote = ch;
      out.push(ch);
      i++;
      while (i < len) {
        const cur = source[i]!;
        out.push(cur);
        if (cur === '\\' && i + 1 < len) {
          out.push(source[i + 1]!);
          i += 2;
          continue;
        }
        if (cur === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    out.push(ch);
    i++;
  }
  return out.join('');
}

function resolveRelativeModuleTarget(fromAbsFile: string, specifier: string): boolean {
  const cleanSpec = specifier.split('?')[0]!.split('#')[0]!;
  if (cleanSpec.length === 0) return true;
  const baseTarget = resolve(dirname(fromAbsFile), cleanSpec);
  try {
    if (existsSync(baseTarget) && statSync(baseTarget).isFile()) {
      return true;
    }
  } catch {
    // Continue to extension probing
  }
  if (extname(baseTarget) === '') {
    const candidates = [
      `${baseTarget}.mts`,
      `${baseTarget}.ts`,
      `${baseTarget}.mjs`,
      `${baseTarget}.js`,
      resolve(baseTarget, 'index.mts'),
      resolve(baseTarget, 'index.ts'),
      resolve(baseTarget, 'index.mjs'),
      resolve(baseTarget, 'index.js'),
    ];
    for (const candidate of candidates) {
      try {
        if (existsSync(candidate) && statSync(candidate).isFile()) {
          return true;
        }
      } catch {
        // Ignore stat errors
      }
    }
  }
  return false;
}

function scanDeadExportsViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const files = walkRepoFiles(ctx.cwd, ctx.signal);
  const violations: HoloRuleViolation[] = [];
  const reExportRegex =
    /^[ \t]*export(?:\s+type)?\s+(?:\*(?:\s+as\s+[A-Za-z_$][\w$]*)?|\{[\s\S]*?\})\s+from\s+(['"])(\.{1,2}\/[^'"]+)\1/gm;

  for (const relFile of files) {
    if (ctx.signal.aborted) return violations;
    if (!relFile.endsWith('.mts') && !relFile.endsWith('.ts')) continue;
    if (relFile.endsWith('.d.mts') || relFile.endsWith('.d.ts')) continue;

    const absFile = resolve(ctx.cwd, relFile);
    let raw: string;
    try {
      if (statSync(absFile).size > MAX_SCAN_FILE_BYTES) continue;
      raw = readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }

    const stripped = stripCommentsPreservingNewlines(raw);
    const rawLines = raw.split(/\r?\n/);
    reExportRegex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = reExportRegex.exec(stripped)) !== null) {
      const specifier = match[2]!;
      if (!resolveRelativeModuleTarget(absFile, specifier)) {
        const line = lineNumberAtOffset(stripped, match.index);
        const snippet = (rawLines[line - 1] ?? '').trim().slice(0, 160);
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-DEAD-EXPORT',
            severity: 'error',
            category: 'geometry',
            repo: ctx.repo,
            file: relFile,
            line,
            snippet,
            message: `Dead barrel re-export target "${specifier}" does not exist on disk`,
            autofixable: false,
          }),
        );
      }
    }
  }

  return violations;
}

const DEFAULT_BINARY_BUDGET_BYTES = 512 * 1024;
const BINARY_BUDGET_EXTENSIONS = new Set(['.b8p', '.wasm', '.so', '.dll', '.exe']);

function resolveBinaryBudgetBytes(cwd: string): number {
  const manifestPath = resolve(cwd, 'holo-ci.json');
  if (!existsSync(manifestPath)) return DEFAULT_BINARY_BUDGET_BYTES;
  try {
    const parsed = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
    if (typeof parsed.binaryBudgetBytes === 'number' && Number.isFinite(parsed.binaryBudgetBytes) && parsed.binaryBudgetBytes > 0) {
      return Math.trunc(parsed.binaryBudgetBytes);
    }
    if (typeof parsed.binaryBudgetKb === 'number' && Number.isFinite(parsed.binaryBudgetKb) && parsed.binaryBudgetKb > 0) {
      return Math.trunc(parsed.binaryBudgetKb * 1024);
    }
  } catch {
    // Fallback to default 512 KB budget
  }
  return DEFAULT_BINARY_BUDGET_BYTES;
}

function scanBinaryBudgetViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const budgetBytes = resolveBinaryBudgetBytes(ctx.cwd);
  const distDirs: string[] = [];

  const rootDist = resolve(ctx.cwd, 'dist');
  if (existsSync(rootDist)) {
    distDirs.push(rootDist);
  }

  const sectionsDir = resolve(ctx.cwd, 'sections');
  if (existsSync(sectionsDir)) {
    try {
      const sectionEntries = readdirSync(sectionsDir, { withFileTypes: true }).sort((a, b) =>
        a.name.localeCompare(b.name),
      );
      for (const entry of sectionEntries) {
        if (!entry.isDirectory()) continue;
        const sectionDist = resolve(sectionsDir, entry.name, 'dist');
        if (existsSync(sectionDist)) {
          distDirs.push(sectionDist);
        }
      }
    } catch {
      // Ignore unreadable sections dir
    }
  }

  const violations: HoloRuleViolation[] = [];
  const emptySkipDirs = new Set<string>();

  for (const distDir of distDirs) {
    if (ctx.signal.aborted) return violations;
    const relFiles = walkRepoFiles(distDir, ctx.signal, emptySkipDirs);
    for (const relInDist of relFiles) {
      if (ctx.signal.aborted) return violations;
      const ext = extname(relInDist).toLowerCase();
      if (!BINARY_BUDGET_EXTENSIONS.has(ext)) continue;

      const absArtifact = resolve(distDir, relInDist);
      let size = 0;
      try {
        size = statSync(absArtifact).size;
      } catch {
        continue;
      }

      if (size > budgetBytes) {
        const relFromRoot = relative(ctx.cwd, absArtifact).replaceAll('\\', '/');
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-BINARY-BUDGET',
            severity: 'error',
            category: 'abi',
            repo: ctx.repo,
            file: relFromRoot,
            line: 1,
            snippet: `${size} bytes > ${budgetBytes} bytes`,
            message: `Compiled artifact "${relFromRoot}" (${size} bytes) exceeds ${budgetBytes}-byte binary budget`,
            autofixable: false,
          }),
        );
      }
    }
  }

  return violations;
}

function scanTestHermeticityViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const files = walkRepoFiles(ctx.cwd, ctx.signal);
  const violations: HoloRuleViolation[] = [];
  const writeCallRegex = /\b(?:writeFileSync|appendFileSync|mkdirSync|writeFile|appendFile|mkdir)\s*\(/g;
  const directArgRegex = /^\s*(?:['"][^'"]+['"]|(?:join|resolve)\s*\(\s*(?:process\.cwd\(\)|REPO_ROOT)\s*,)/;
  const tmpIsolationRegex = /\b(?:tmpdir|mkdtempSync|mkdtemp)\b/;
  const cleanupRegex = /\b(?:rmSync|rm|rmdirSync)\b/;

  for (const relFile of files) {
    if (ctx.signal.aborted) return violations;
    if (!relFile.endsWith('.test.mts')) continue;

    const absFile = resolve(ctx.cwd, relFile);
    let raw: string;
    try {
      if (statSync(absFile).size > MAX_SCAN_FILE_BYTES) continue;
      raw = readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }

    const stripped = stripTsCommentsAndStrings(raw);
    writeCallRegex.lastIndex = 0;
    const firstWrite = writeCallRegex.exec(stripped);
    if (!firstWrite) continue;

    const rawLines = raw.split(/\r?\n/);
    const hasIsolation = tmpIsolationRegex.test(stripped) && cleanupRegex.test(stripped);

    if (!hasIsolation) {
      const line = lineNumberAtOffset(stripped, firstWrite.index);
      const snippet = (rawLines[line - 1] ?? '').trim().slice(0, 160);
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-TEST-HERMETICITY',
          severity: 'error',
          category: 'governance',
          repo: ctx.repo,
          file: relFile,
          line,
          snippet,
          message: 'Test performs filesystem writes without os.tmpdir()/mkdtempSync isolation and rmSync cleanup',
          autofixable: false,
        }),
      );
      continue;
    }

    writeCallRegex.lastIndex = 0;
    let callMatch: RegExpExecArray | null;
    while ((callMatch = writeCallRegex.exec(stripped)) !== null) {
      const argSlice = raw.slice(callMatch.index + callMatch[0].length, callMatch.index + callMatch[0].length + 120);
      if (directArgRegex.test(argSlice)) {
        const line = lineNumberAtOffset(stripped, callMatch.index);
        const snippet = (rawLines[line - 1] ?? '').trim().slice(0, 160);
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-TEST-HERMETICITY',
            severity: 'error',
            category: 'governance',
            repo: ctx.repo,
            file: relFile,
            line,
            snippet,
            message: 'Test writes directly to a relative/working-tree path instead of an isolated os.tmpdir() directory',
            autofixable: false,
          }),
        );
      }
    }
  }

  return violations;
}

const ALLOWED_SPDX_LICENSES = new Set(['BSD-3-Clause', 'MIT', 'Apache-2.0']);

function detectLicenseSpdxFromText(raw: string): string | null {
  if (/SPDX-License-Identifier:\s*BSD-3-Clause\b/i.test(raw) || /Redistribution and use in source and binary forms/i.test(raw)) {
    return 'BSD-3-Clause';
  }
  if (/SPDX-License-Identifier:\s*MIT\b/i.test(raw) || /MIT License/i.test(raw) || /Permission is hereby granted, free of charge/i.test(raw)) {
    return 'MIT';
  }
  if (/SPDX-License-Identifier:\s*Apache-2\.0\b/i.test(raw) || (/Apache License/i.test(raw) && /Version 2\.0/i.test(raw))) {
    return 'Apache-2.0';
  }
  return null;
}

function scanSpdxHeaderViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const violations: HoloRuleViolation[] = [];
  const licensePath = resolve(ctx.cwd, 'LICENSE');
  let detectedLicense: string | null = null;

  if (!existsSync(licensePath)) {
    violations.push(
      createRuleViolation({
        ruleId: 'B8G-SPDX-LICENSE',
        severity: 'error',
        category: 'governance',
        repo: ctx.repo,
        file: 'LICENSE',
        line: 1,
        snippet: 'missing LICENSE',
        message: 'Root LICENSE file is missing (expected BSD-3-Clause, MIT, or Apache-2.0)',
        autofixable: false,
      }),
    );
  } else {
    try {
      const licenseRaw = readFileSync(licensePath, 'utf8');
      detectedLicense = detectLicenseSpdxFromText(licenseRaw);
      if (detectedLicense === null) {
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-SPDX-LICENSE',
            severity: 'error',
            category: 'governance',
            repo: ctx.repo,
            file: 'LICENSE',
            line: 1,
            snippet: licenseRaw.split(/\r?\n/, 1)[0]?.trim().slice(0, 160) ?? '',
            message: 'Root LICENSE does not match an approved SPDX license (BSD-3-Clause, MIT, Apache-2.0)',
            autofixable: false,
          }),
        );
      }
    } catch {
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-SPDX-LICENSE',
          severity: 'error',
          category: 'governance',
          repo: ctx.repo,
          file: 'LICENSE',
          line: 1,
          snippet: 'unreadable LICENSE',
          message: 'Unable to read root LICENSE file',
          autofixable: false,
        }),
      );
    }
  }

  const pkgPath = resolve(ctx.cwd, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
      const pkgLicense = typeof pkg.license === 'string' ? pkg.license.trim() : '';
      if (pkgLicense.length === 0) {
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-SPDX-LICENSE',
            severity: 'error',
            category: 'governance',
            repo: ctx.repo,
            file: 'package.json',
            line: 1,
            snippet: '"license": <missing>',
            message: 'package.json is missing an SPDX "license" field (BSD-3-Clause, MIT, or Apache-2.0)',
            autofixable: false,
          }),
        );
      } else if (!ALLOWED_SPDX_LICENSES.has(pkgLicense)) {
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-SPDX-LICENSE',
            severity: 'error',
            category: 'governance',
            repo: ctx.repo,
            file: 'package.json',
            line: 1,
            snippet: `"license": "${pkgLicense}"`,
            message: `package.json "license" ("${pkgLicense}") is not in approved SPDX set (BSD-3-Clause, MIT, Apache-2.0)`,
            autofixable: false,
          }),
        );
      } else if (detectedLicense !== null && pkgLicense !== detectedLicense) {
        violations.push(
          createRuleViolation({
            ruleId: 'B8G-SPDX-LICENSE',
            severity: 'error',
            category: 'governance',
            repo: ctx.repo,
            file: 'package.json',
            line: 1,
            snippet: `"license": "${pkgLicense}" !== LICENSE (${detectedLicense})`,
            message: `package.json "license" ("${pkgLicense}") does not match root LICENSE ("${detectedLicense}")`,
            autofixable: false,
          }),
        );
      }
    } catch {
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-SPDX-LICENSE',
          severity: 'error',
          category: 'governance',
          repo: ctx.repo,
          file: 'package.json',
          line: 1,
          snippet: 'invalid package.json',
          message: 'Unable to parse package.json for SPDX license verification',
          autofixable: false,
        }),
      );
    }
  }

  return violations;
}

function scanAbiSurfaceViolations(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
  const files = walkRepoFiles(ctx.cwd, ctx.signal);
  const violations: HoloRuleViolation[] = [];

  for (const relFile of files) {
    if (ctx.signal.aborted) return violations;
    if (basename(relFile) !== 'abi-golden.json') continue;

    const absFile = resolve(ctx.cwd, relFile);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(readFileSync(absFile, 'utf8')) as Record<string, unknown>;
    } catch {
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-ABI-SURFACE',
          severity: 'error',
          category: 'abi',
          repo: ctx.repo,
          file: relFile,
          line: 1,
          snippet: 'invalid JSON',
          message: `Invalid JSON in ABI golden file "${relFile}"`,
          autofixable: false,
        }),
      );
      continue;
    }

    if (parsed.abiMagic !== B8G_ABI_MAGIC_V3) {
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-ABI-SURFACE',
          severity: 'error',
          category: 'abi',
          repo: ctx.repo,
          file: relFile,
          line: 1,
          snippet: `abiMagic=${String(parsed.abiMagic ?? '<missing>')}`,
          message: `ABI golden "${relFile}" has invalid or missing abiMagic (expected ${B8G_ABI_MAGIC_V3})`,
          autofixable: false,
        }),
      );
    }

    const header = typeof parsed.header === 'string' ? parsed.header.trim() : '';
    const headerExists =
      header.length > 0 &&
      (existsSync(resolve(ctx.cwd, header)) || existsSync(resolve(dirname(absFile), header)));
    if (!headerExists) {
      violations.push(
        createRuleViolation({
          ruleId: 'B8G-ABI-SURFACE',
          severity: 'error',
          category: 'abi',
          repo: ctx.repo,
          file: relFile,
          line: 1,
          snippet: `header=${header || '<missing>'}`,
          message: `ABI golden "${relFile}" references missing or unspecified header "${header || '<missing>'}"`,
          autofixable: false,
        }),
      );
    }
  }

  return violations;
}

/**
 * Registers the 13 canonical built-in `holo-ci` programmatic audits into `registry`:
 *   1. `holo-ci/wf-harden` — GitHub Actions workflow hardening check
 *   2. `holo-ci/governance` — SPDX LICENSE, CODEOWNERS, .gitattributes, badges & workflow bloat
 *   3. `holo-ci/boundary` — Chromium-style boundary/DAG/B8G016 check when `boundary.json` exists
 *   4. `holo-ci/guards` — `zeroGhost`, `zeroCasV1`, and `zeroHttpIpc` (`B8G016`) guards
 *   5. `holo-ci/non-github-io-cname` — Rejects non-`awesome-os.github.io` custom `CNAME` files
 *   6. `holo-ci/erasable-syntax` — Rejects non-erasable TypeScript syntax (`enum`, `namespace`, parameter properties)
 *   7. `holo-ci/secret-scan` — Detects high-confidence leaked token prefixes & private keys
 *   8. `holo-ci/no-broken-local-links` — Detects broken relative file links in `README.md` and `docs/*.md`
 *   9. `holo-ci/dead-exports` — Detects broken relative barrel re-exports (`export ... from './missing.mts'`)
 *  10. `holo-ci/binary-budget` — Enforces compiled `.b8p`/`.wasm`/`.so`/`.dll`/`.exe` size budgets under `dist/`
 *  11. `holo-ci/test-hermeticity` — Rejects `*.test.mts` files with unisolated working-tree fixture writes
 *  12. `holo-ci/spdx-header` — Verifies `package.json` `"license"` and root `LICENSE` SPDX consistency
 *  13. `holo-ci/abi-surface` — Verifies `abi-golden.json` `abiMagic === '0x33564742'` & header existence
 */
export function registerBuiltinHoloCiAudits(registry: AuditStackRegistry): AuditStackRegistry {
  registry.register({
    id: 'holo-ci/wf-harden',
    title: 'GitHub Actions Workflow Hardening',
    category: 'workflow',
    severity: 'error',
    rollbackHint: 'Revert workflow edits or hold promotion via RollingReleaseManifest O(1) rollback',
    remediationCmd: 'holo-ci wf-harden --fix',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      const res = runWorkflowHardening(ctx.cwd, { fix: false });
      const violations: HoloRuleViolation[] = [];
      for (const fileRes of res.files) {
        if (ctx.signal.aborted) return violations;
        for (const finding of fileRes.findings) {
          violations.push(
            createRuleViolation({
              ruleId: `holo.workflow.${finding.rule}`,
              severity: finding.severity,
              category: 'workflow',
              repo: ctx.repo,
              file: finding.file,
              line: finding.line,
              snippet: finding.snippet,
              message: finding.message,
              autofixable: true,
            }),
          );
        }
      }
      return violations;
    },
  });

  registry.register({
    id: 'holo-ci/governance',
    title: 'Repository Governance (SPDX, CODEOWNERS, .gitattributes, Badges & Bloat)',
    category: 'governance',
    severity: 'error',
    rollbackHint: 'Restore ratified LICENSE, .gitattributes, CODEOWNERS, and thin workflow manifests',
    remediationCmd: 'holo-ci verify --config holo-ci.json',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      const docFiles = readManifestDocFiles(ctx.cwd);
      const gov = checkRepoGovernance(
        ctx.cwd,
        {
          spdxLicense: true,
          gitattributes: true,
          codeowners: true,
          noBrokenBadges: true,
          noWorkflowBloat: true,
          requireWorkflowHardening: false,
        },
        { docFiles },
      );
      return gov.violations.map((v) => guardViolationToRuleViolation(v, ctx.repo));
    },
  });

  registry.register({
    id: 'holo-ci/boundary',
    title: 'Architectural Boundary & DAG/IPC Audit (boundary.json)',
    category: 'geometry',
    severity: 'error',
    rollbackHint: 'Revert forbidden cross-layer imports or roll back via RollingReleaseManifest O(1)',
    remediationCmd: 'holo-ci boundary-audit --boundary boundary.json --min-score 100',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      const boundaryFile = resolve(ctx.cwd, 'boundary.json');
      if (!existsSync(boundaryFile)) {
        return [];
      }
      const res = runBoundaryAudit({ cwd: ctx.cwd });
      return res.violations.map((v) => boundaryViolationToRuleViolation(v, ctx.repo));
    },
  });

  registry.register({
    id: 'holo-ci/guards',
    title: 'Core Security & Brand Guards (zeroGhost, zeroCasV1, B8G016 zeroHttpIpc)',
    category: 'security',
    severity: 'error',
    rollbackHint: 'Hold promotion and roll back to last ratified SHA-512 CAS v11 release bundle',
    remediationCmd: 'holo-ci verify --config holo-ci.json',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      const violations = scanGuardViolations(ctx.cwd, {
        zeroGhost: true,
        zeroCasV1: true,
        zeroHttpIpc: true,
        noBrokenBadges: false,
      });
      return violations.map((v) => guardViolationToRuleViolation(v, ctx.repo));
    },
  });

  registry.register({
    id: 'holo-ci/non-github-io-cname',
    title: 'Canonical awesome-os.github.io Domain Guard (Zero Custom CNAME)',
    category: 'governance',
    severity: 'error',
    rollbackHint: 'Delete root CNAME and restore Pages portal under https://awesome-os.github.io/*',
    remediationCmd: 'Remove root CNAME file and re-run holo-ci audit-stack',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      const cnamePath = resolve(ctx.cwd, 'CNAME');
      if (!existsSync(cnamePath)) {
        return [];
      }
      const raw = readFileSync(cnamePath, 'utf8').trim();
      const normalized = raw.toLowerCase();
      if (normalized.length === 0 || normalized === 'awesome-os.github.io') {
        return [];
      }
      return [
        createRuleViolation({
          ruleId: 'holo.pages.non-github-io-cname',
          severity: 'error',
          category: 'governance',
          repo: ctx.repo,
          file: 'CNAME',
          line: 1,
          snippet: raw.slice(0, 160),
          message: `Forbidden custom non-awesome-os.github.io CNAME "${raw}" detected; serve strictly via https://awesome-os.github.io/`,
          autofixable: true,
        }),
      ];
    },
  });

  registry.register({
    id: 'holo-ci/erasable-syntax',
    title: 'Non-Erasable TypeScript Syntax Guard (erasableSyntaxOnly)',
    category: 'abi',
    severity: 'error',
    rollbackHint: 'Replace enum, namespace, and constructor parameter properties with erasable TypeScript syntax',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/erasable-syntax',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanErasableSyntaxViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/secret-scan',
    title: 'High-Confidence Secret & Private Key Scanner',
    category: 'security',
    severity: 'error',
    rollbackHint: 'Revoke leaked credential, purge from history, and rotate secret immediately',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/secret-scan',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanSecretViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/no-broken-local-links',
    title: 'Documentation Local Relative Link Hygiene',
    category: 'docs',
    severity: 'error',
    rollbackHint: 'Fix broken relative markdown link or restore missing target file',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/no-broken-local-links',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanBrokenLocalLinkViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/dead-exports',
    title: 'Dead Barrel Re-Export & Unreachable Target Guard',
    category: 'geometry',
    severity: 'error',
    rollbackHint: 'Remove dead barrel re-export or restore missing target module',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/dead-exports',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanDeadExportsViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/binary-budget',
    title: 'Compiled Artifact Binary Size Budget Guard',
    category: 'abi',
    severity: 'error',
    rollbackHint: 'Revert binary bloat or trigger RollingReleaseManifest O(1) rollback',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/binary-budget',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanBinaryBudgetViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/test-hermeticity',
    title: 'Test Suite Hermeticity & Temp-Dir Isolation Guard',
    category: 'governance',
    severity: 'error',
    rollbackHint: 'Isolate test writes into os.tmpdir()/mkdtempSync with rmSync cleanup',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/test-hermeticity',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanTestHermeticityViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/spdx-header',
    title: 'SPDX License & package.json Consistency Guard',
    category: 'governance',
    severity: 'error',
    rollbackHint: 'Align package.json "license" and root LICENSE to BSD-3-Clause, MIT, or Apache-2.0',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/spdx-header',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanSpdxHeaderViolations(ctx);
    },
  });

  registry.register({
    id: 'holo-ci/abi-surface',
    title: 'ABI Golden Magic (B8G_ABI_MAGIC_V3) & Header Guard',
    category: 'abi',
    severity: 'error',
    rollbackHint: 'Regenerate abi-golden.json with B8G_ABI_MAGIC_V3 (0x33564742) and valid header path',
    remediationCmd: 'holo-ci audit-stack --only holo-ci/abi-surface',
    run(ctx: ProgrammaticAuditContext): HoloRuleViolation[] {
      if (ctx.signal.aborted) return [];
      return scanAbiSurfaceViolations(ctx);
    },
  });

  return registry;
}

/**
 * Convenience runner that creates a registry with all 13 built-in `holo-ci` audits and executes it.
 */
export async function runBuiltinAuditStack(
  options: AuditStackRunOptions = {},
): Promise<AuditStackRunResult> {
  const registry = registerBuiltinHoloCiAudits(createAuditStackRegistry());
  return registry.run(options);
}
