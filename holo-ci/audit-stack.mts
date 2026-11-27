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

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
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

/**
 * Registers the 5 canonical built-in `holo-ci` programmatic audits into `registry`:
 *   1. `holo-ci/wf-harden` — GitHub Actions workflow hardening check
 *   2. `holo-ci/governance` — SPDX LICENSE, CODEOWNERS, .gitattributes, badges & workflow bloat
 *   3. `holo-ci/boundary` — Chromium-style boundary/DAG/B8G016 check when `boundary.json` exists
 *   4. `holo-ci/guards` — `zeroGhost`, `zeroCasV1`, and `zeroHttpIpc` (`B8G016`) guards
 *   5. `holo-ci/non-github-io-cname` — Rejects non-`awesome-os.github.io` custom `CNAME` files
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

  return registry;
}

/**
 * Convenience runner that creates a registry with all 5 built-in `holo-ci` audits and executes it.
 */
export async function runBuiltinAuditStack(
  options: AuditStackRunOptions = {},
): Promise<AuditStackRunResult> {
  const registry = registerBuiltinHoloCiAudits(createAuditStackRegistry());
  return registry.run(options);
}
