#!/usr/bin/env node
/**
 * @file holo-ci/fleet-forensics.mts
 * @description Single-process GitHub Actions fleet forensics scanner using `gh-client.mts`
 * (zero PowerShell `gh` subprocess fan-out).
 *
 * Scans recent workflow runs across an org or explicit repo list within a configurable
 * time window (`--hours`), classifies failed, cancelled, and slow (`> --slow-sec`) runs/jobs,
 * strips ANSI escape sequences, and emits structured `b8g.fleet-forensics.v1` JSON + Markdown.
 *
 * Strictly `erasableSyntaxOnly: true`, Node built-ins only, zero external dependencies.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGithubClient, mapConcurrent, type GithubClient } from './gh-client.mts';

export const FLEET_FORENSICS_SCHEMA = 'b8g.fleet-forensics.v1' as const;
export const B8G_ABI_MAGIC_V3 = '0x33564742' as const;
export const DEFAULT_FORENSICS_OWNER = 'awesome-os' as const;
export const DEFAULT_FORENSICS_HOURS = 4;
export const DEFAULT_SLOW_THRESHOLD_SEC = 300;
export const DEFAULT_FORENSICS_CONCURRENCY = 6;

const FAILED_CONCLUSIONS = new Set([
  'failure',
  'timed_out',
  'startup_failure',
  'action_required',
]);

const GREEN_CONCLUSIONS = new Set(['success', 'skipped', 'neutral']);

// Matches CSI, OSC, and 2-byte ESC ANSI escape sequences.
const ANSI_ESCAPE_REGEX =
  // eslint-disable-next-line no-control-regex
  /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]/g;

/**
 * Strips ANSI terminal escape codes (CSI, OSC, 2-byte ESC) from log/title strings.
 */
export function stripAnsi(text: string): string {
  if (!text) return '';
  return text.replace(ANSI_ESCAPE_REGEX, '');
}

export interface FleetForensicsRunEntry {
  readonly repo: string;
  readonly runId: number;
  readonly workflowName: string;
  readonly conclusion: string;
  readonly status: string;
  readonly headBranch: string;
  readonly event: string;
  readonly htmlUrl: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly durationSec: number;
  readonly failedSteps: readonly string[];
}

export interface FleetForensicsSlowJobEntry {
  readonly repo: string;
  readonly runId: number;
  readonly jobId: number;
  readonly workflowName: string;
  readonly jobName: string;
  readonly conclusion: string;
  readonly status: string;
  readonly htmlUrl: string;
  readonly durationSec: number;
}

export interface CollectFleetForensicsOptions {
  readonly owner?: string;
  readonly repos?: readonly string[];
  readonly hours?: number;
  readonly slowThresholdSec?: number;
  readonly concurrency?: number;
  readonly nowMs?: number;
  readonly client?: GithubClient;
}

export interface FleetForensicsReport {
  readonly schema: typeof FLEET_FORENSICS_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly generatedAt: string;
  readonly owner: string;
  readonly hours: number;
  readonly slowThresholdSec: number;
  readonly ok: boolean;
  readonly reposScanned: number;
  readonly greenOnLatest: number;
  readonly failedRuns: readonly FleetForensicsRunEntry[];
  readonly cancelledRuns: readonly FleetForensicsRunEntry[];
  readonly slowJobs: readonly FleetForensicsSlowJobEntry[];
  readonly errors?: readonly string[];
  readonly durationMs: number;
}

interface GhRepoSummary {
  readonly name: string;
  readonly archived?: boolean;
  readonly disabled?: boolean;
}

interface GhWorkflowRun {
  readonly id: number;
  readonly workflow_id?: number;
  readonly name?: string;
  readonly display_title?: string;
  readonly status?: string;
  readonly conclusion?: string | null;
  readonly head_branch?: string;
  readonly event?: string;
  readonly html_url?: string;
  readonly created_at?: string;
  readonly run_started_at?: string;
  readonly updated_at?: string;
}

interface GhWorkflowJobStep {
  readonly name?: string;
  readonly conclusion?: string | null;
}

interface GhWorkflowJob {
  readonly id: number;
  readonly name?: string;
  readonly status?: string;
  readonly conclusion?: string | null;
  readonly html_url?: string;
  readonly started_at?: string;
  readonly completed_at?: string;
  readonly steps?: readonly GhWorkflowJobStep[];
}

function computeDurationSec(startIso: string | undefined, endIso: string | undefined, fallbackNowMs: number): number {
  const startMs = startIso ? Date.parse(startIso) : Number.NaN;
  const endMs = endIso ? Date.parse(endIso) : fallbackNowMs;
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return 0;
  return Math.max(0, Math.round((endMs - startMs) / 1000));
}

function escapeMdCell(value: string): string {
  return stripAnsi(value).replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
}

/**
 * Collects single-process GitHub Actions forensics across an organization or explicit repo list.
 */
export async function collectFleetForensics(
  options: CollectFleetForensicsOptions = {},
): Promise<FleetForensicsReport> {
  const startMs = Date.now();
  const owner = options.owner?.trim() || DEFAULT_FORENSICS_OWNER;
  const hours =
    typeof options.hours === 'number' && Number.isFinite(options.hours) && options.hours > 0
      ? options.hours
      : DEFAULT_FORENSICS_HOURS;
  const slowThresholdSec =
    typeof options.slowThresholdSec === 'number' &&
    Number.isFinite(options.slowThresholdSec) &&
    options.slowThresholdSec > 0
      ? options.slowThresholdSec
      : DEFAULT_SLOW_THRESHOLD_SEC;
  const concurrency =
    typeof options.concurrency === 'number' &&
    Number.isInteger(options.concurrency) &&
    options.concurrency > 0
      ? options.concurrency
      : DEFAULT_FORENSICS_CONCURRENCY;
  const nowMs = typeof options.nowMs === 'number' && Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const cutoffMs = nowMs - hours * 3_600_000;
  const client = options.client ?? createGithubClient({ maxConcurrency: concurrency });

  let repoNames: string[];
  if (options.repos && options.repos.length > 0) {
    const seen = new Set<string>();
    repoNames = [];
    for (const raw of options.repos) {
      const cleaned = raw.trim();
      if (cleaned.length > 0 && !seen.has(cleaned)) {
        seen.add(cleaned);
        repoNames.push(cleaned);
      }
    }
  } else {
    const orgRepos = await client.restPaginate<GhRepoSummary>(
      `/orgs/${encodeURIComponent(owner)}/repos?type=all&sort=pushed`,
      { perPage: 100, maxPages: 10 },
    );
    repoNames = orgRepos
      .filter((r) => Boolean(r?.name) && !r.archived && !r.disabled)
      .map((r) => r.name)
      .sort((a, b) => a.localeCompare(b));
  }

  interface PerRepoForensics {
    readonly repo: string;
    readonly greenOnLatest: boolean;
    readonly failedRuns: FleetForensicsRunEntry[];
    readonly cancelledRuns: FleetForensicsRunEntry[];
    readonly slowJobs: FleetForensicsSlowJobEntry[];
    readonly error?: string;
  }

  const perRepoResults = await mapConcurrent<string, PerRepoForensics>(
    repoNames,
    async (repo) => {
      const failedRuns: FleetForensicsRunEntry[] = [];
      const cancelledRuns: FleetForensicsRunEntry[] = [];
      const slowJobs: FleetForensicsSlowJobEntry[] = [];

      try {
        const runsPayload = await client.rest<{ workflow_runs?: GhWorkflowRun[] }>(
          'GET',
          `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs?per_page=30`,
        );
        const allRuns = Array.isArray(runsPayload?.workflow_runs) ? runsPayload.workflow_runs : [];
        const windowRuns = allRuns.filter((run) => {
          if (!run.created_at) return true;
          const createdMs = Date.parse(run.created_at);
          return !Number.isFinite(createdMs) || createdMs >= cutoffMs;
        });

        // Determine if every workflow's latest completed run in the repo is green.
        const latestByWorkflow = new Map<string, GhWorkflowRun>();
        for (const run of allRuns) {
          const wfKey = String(run.workflow_id ?? run.name ?? run.id);
          if (!latestByWorkflow.has(wfKey)) {
            latestByWorkflow.set(wfKey, run);
          }
        }
        let repoGreen = true;
        for (const latestRun of latestByWorkflow.values()) {
          const conc = (latestRun.conclusion ?? '').toLowerCase();
          if (conc.length > 0 && !GREEN_CONCLUSIONS.has(conc)) {
            repoGreen = false;
            break;
          }
        }

        for (const run of windowRuns) {
          const workflowName = stripAnsi(run.name ?? run.display_title ?? `workflow-${run.id}`).trim();
          const status = stripAnsi(run.status ?? 'unknown').trim();
          const conclusion = stripAnsi(run.conclusion ?? '').trim().toLowerCase();
          const headBranch = stripAnsi(run.head_branch ?? '').trim();
          const event = stripAnsi(run.event ?? '').trim();
          const htmlUrl = run.html_url ?? '';
          const createdAt = run.created_at ?? '';
          const updatedAt = run.updated_at ?? '';
          const runDurationSec = computeDurationSec(run.run_started_at ?? run.created_at, run.updated_at, nowMs);

          const isFailed = FAILED_CONCLUSIONS.has(conclusion);
          const isCancelled = conclusion === 'cancelled';
          const isSlowRun = runDurationSec > slowThresholdSec;

          let fetchedJobs: GhWorkflowJob[] | null = null;
          const failedSteps: string[] = [];

          if (isFailed || isSlowRun) {
            try {
              const jobsPayload = await client.rest<{ jobs?: GhWorkflowJob[] }>(
                'GET',
                `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs/${run.id}/jobs?per_page=50`,
              );
              fetchedJobs = Array.isArray(jobsPayload?.jobs) ? jobsPayload.jobs : [];
            } catch {
              fetchedJobs = [];
            }
          }

          if (fetchedJobs && fetchedJobs.length > 0) {
            for (const job of fetchedJobs) {
              const jobName = stripAnsi(job.name ?? `job-${job.id}`).trim();
              const jobConc = stripAnsi(job.conclusion ?? '').trim().toLowerCase();
              const jobStatus = stripAnsi(job.status ?? 'unknown').trim();
              const jobDurationSec = computeDurationSec(job.started_at, job.completed_at, nowMs);

              if (FAILED_CONCLUSIONS.has(jobConc)) {
                const jobFailedSteps = (job.steps ?? [])
                  .filter((s) => FAILED_CONCLUSIONS.has((s.conclusion ?? '').toLowerCase()))
                  .map((s) => `${jobName} :: ${stripAnsi(s.name ?? 'step').trim()}`);
                if (jobFailedSteps.length > 0) {
                  failedSteps.push(...jobFailedSteps);
                } else {
                  failedSteps.push(jobName);
                }
              }

              if (jobDurationSec > slowThresholdSec) {
                slowJobs.push({
                  repo,
                  runId: run.id,
                  jobId: job.id,
                  workflowName,
                  jobName,
                  conclusion: jobConc || jobStatus,
                  status: jobStatus,
                  htmlUrl: job.html_url ?? htmlUrl,
                  durationSec: jobDurationSec,
                });
              }
            }
          } else if (isSlowRun) {
            slowJobs.push({
              repo,
              runId: run.id,
              jobId: 0,
              workflowName,
              jobName: workflowName,
              conclusion: conclusion || status,
              status,
              htmlUrl,
              durationSec: runDurationSec,
            });
          }

          if (isFailed) {
            failedRuns.push({
              repo,
              runId: run.id,
              workflowName,
              conclusion,
              status,
              headBranch,
              event,
              htmlUrl,
              createdAt,
              updatedAt,
              durationSec: runDurationSec,
              failedSteps,
            });
          } else if (isCancelled) {
            cancelledRuns.push({
              repo,
              runId: run.id,
              workflowName,
              conclusion,
              status,
              headBranch,
              event,
              htmlUrl,
              createdAt,
              updatedAt,
              durationSec: runDurationSec,
              failedSteps: [],
            });
          }
        }

        return {
          repo,
          greenOnLatest: repoGreen,
          failedRuns,
          cancelledRuns,
          slowJobs,
        };
      } catch (err) {
        return {
          repo,
          greenOnLatest: false,
          failedRuns,
          cancelledRuns,
          slowJobs,
          error: `${repo}: ${stripAnsi(err instanceof Error ? err.message : String(err))}`,
        };
      }
    },
    concurrency,
  );

  const failedRuns: FleetForensicsRunEntry[] = [];
  const cancelledRuns: FleetForensicsRunEntry[] = [];
  const slowJobs: FleetForensicsSlowJobEntry[] = [];
  const errors: string[] = [];
  let greenOnLatest = 0;

  for (const r of perRepoResults) {
    if (r.greenOnLatest) greenOnLatest += 1;
    failedRuns.push(...r.failedRuns);
    cancelledRuns.push(...r.cancelledRuns);
    slowJobs.push(...r.slowJobs);
    if (r.error) errors.push(r.error);
  }

  failedRuns.sort((a, b) => a.repo.localeCompare(b.repo) || b.runId - a.runId);
  cancelledRuns.sort((a, b) => a.repo.localeCompare(b.repo) || b.runId - a.runId);
  slowJobs.sort((a, b) => b.durationSec - a.durationSec || a.repo.localeCompare(b.repo));

  return {
    schema: FLEET_FORENSICS_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    generatedAt: new Date(nowMs).toISOString(),
    owner,
    hours,
    slowThresholdSec,
    ok: failedRuns.length === 0 && errors.length === 0,
    reposScanned: repoNames.length,
    greenOnLatest,
    failedRuns,
    cancelledRuns,
    slowJobs,
    ...(errors.length > 0 ? { errors } : {}),
    durationMs: Date.now() - startMs,
  };
}

/**
 * Formats a `FleetForensicsReport` into a concise GitHub Step Summary Markdown document.
 */
export function formatForensicsSummaryMarkdown(report: FleetForensicsReport): string {
  const statusBadge = report.ok ? 'PASS' : 'FAIL';
  const lines: string[] = [
    `## Fleet Forensics — \`${report.owner}\` (${report.hours}h window) [${statusBadge}]`,
    '',
    '| Metric | Value |',
    '| :--- | :--- |',
    `| Schema / ABI Magic | \`${report.schema}\` / \`${report.abiMagic}\` |`,
    `| Repos Scanned | ${report.reposScanned} |`,
    `| Green on Latest | ${report.greenOnLatest}/${report.reposScanned} |`,
    `| Failed Runs | ${report.failedRuns.length} |`,
    `| Cancelled Runs | ${report.cancelledRuns.length} |`,
    `| Slow Jobs (> ${report.slowThresholdSec}s) | ${report.slowJobs.length} |`,
    `| Scan Duration | ${report.durationMs} ms |`,
  ];

  if (report.failedRuns.length > 0) {
    lines.push(
      '',
      `### Failed Runs (${report.failedRuns.length})`,
      '',
      '| Repo | Workflow | Conclusion | Branch | Duration | Failed Steps |',
      '| :--- | :--- | :--- | :--- | :--- | :--- |',
    );
    for (const run of report.failedRuns) {
      const wfCell = run.htmlUrl
        ? `[${escapeMdCell(run.workflowName)}](${run.htmlUrl})`
        : escapeMdCell(run.workflowName);
      const stepsCell =
        run.failedSteps.length > 0 ? escapeMdCell(run.failedSteps.join('; ')) : '—';
      lines.push(
        `| \`${escapeMdCell(run.repo)}\` | ${wfCell} | \`${escapeMdCell(run.conclusion)}\` | \`${escapeMdCell(run.headBranch)}\` | ${run.durationSec}s | ${stepsCell} |`,
      );
    }
  }

  if (report.cancelledRuns.length > 0) {
    lines.push(
      '',
      `### Cancelled Runs (${report.cancelledRuns.length})`,
      '',
      '| Repo | Workflow | Branch | Duration |',
      '| :--- | :--- | :--- | :--- |',
    );
    for (const run of report.cancelledRuns) {
      const wfCell = run.htmlUrl
        ? `[${escapeMdCell(run.workflowName)}](${run.htmlUrl})`
        : escapeMdCell(run.workflowName);
      lines.push(
        `| \`${escapeMdCell(run.repo)}\` | ${wfCell} | \`${escapeMdCell(run.headBranch)}\` | ${run.durationSec}s |`,
      );
    }
  }

  if (report.slowJobs.length > 0) {
    lines.push(
      '',
      `### Slow Jobs (> ${report.slowThresholdSec}s) (${report.slowJobs.length})`,
      '',
      '| Repo | Workflow | Job | Conclusion | Duration |',
      '| :--- | :--- | :--- | :--- | :--- |',
    );
    for (const job of report.slowJobs) {
      const jobCell = job.htmlUrl
        ? `[${escapeMdCell(job.jobName)}](${job.htmlUrl})`
        : escapeMdCell(job.jobName);
      lines.push(
        `| \`${escapeMdCell(job.repo)}\` | ${escapeMdCell(job.workflowName)} | ${jobCell} | \`${escapeMdCell(job.conclusion)}\` | ${job.durationSec}s |`,
      );
    }
  }

  if (report.errors && report.errors.length > 0) {
    lines.push('', '### Scan Errors', '');
    for (const err of report.errors) {
      lines.push(`- ${escapeMdCell(err)}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

export interface ParsedFleetForensicsCliArgs {
  readonly owner: string;
  readonly repos?: readonly string[];
  readonly hours: number;
  readonly slowThresholdSec: number;
  readonly concurrency?: number;
  readonly json: boolean;
  readonly help: boolean;
}

export function getFleetForensicsHelpText(): string {
  return [
    'fleet-forensics — Single-process GitHub Actions fleet forensics scanner',
    '',
    'Usage:',
    '  node holo-ci/fleet-forensics.mts [--owner <org>] [--repos <a,b>] [--hours <n>] [--slow-sec <n>] [--json]',
    '',
    'Options:',
    `  --owner <org>       GitHub organization/owner (default: ${DEFAULT_FORENSICS_OWNER})`,
    '  --repos <a,b>       Comma-separated repo names to scan (default: all active org repos)',
    `  --hours <n>         Lookback window in hours (default: ${DEFAULT_FORENSICS_HOURS})`,
    `  --slow-sec <n>      Slow job duration threshold in seconds (default: ${DEFAULT_SLOW_THRESHOLD_SEC})`,
    `  --concurrency <n>   Max concurrent repo scans (default: ${DEFAULT_FORENSICS_CONCURRENCY})`,
    '  --json              Emit structured b8g.fleet-forensics.v1 JSON to stdout',
    '  -h, --help          Show this help message',
    '',
  ].join('\n');
}

export function parseFleetForensicsCliArgs(argv: readonly string[]): ParsedFleetForensicsCliArgs {
  let owner: string = DEFAULT_FORENSICS_OWNER;
  let repos: string[] | undefined;
  let hours = DEFAULT_FORENSICS_HOURS;
  let slowThresholdSec = DEFAULT_SLOW_THRESHOLD_SEC;
  let concurrency: number | undefined;
  let json = false;
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--owner' && i + 1 < argv.length) {
      owner = argv[++i]!.trim();
    } else if (arg === '--repos' && i + 1 < argv.length) {
      repos = argv[++i]!
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);
    } else if (arg === '--hours' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error(`Invalid --hours value: "${argv[i]}"`);
      }
      hours = parsed;
    } else if (arg === '--slow-sec' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error(`Invalid --slow-sec value: "${argv[i]}"`);
      }
      slowThresholdSec = parsed;
    } else if (arg === '--concurrency' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --concurrency value: "${argv[i]}"`);
      }
      concurrency = parsed;
    } else {
      throw new Error(`Unknown or incomplete argument: "${arg}"`);
    }
  }

  return {
    owner,
    ...(repos ? { repos } : {}),
    hours,
    slowThresholdSec,
    ...(concurrency !== undefined ? { concurrency } : {}),
    json,
    help,
  };
}

export async function runFleetForensicsCli(
  argv: readonly string[],
  client?: GithubClient,
): Promise<{ readonly exitCode: number; readonly report?: FleetForensicsReport }> {
  const opts = parseFleetForensicsCliArgs(argv);
  if (opts.help) {
    process.stdout.write(getFleetForensicsHelpText());
    return { exitCode: 0 };
  }

  const report = await collectFleetForensics({
    owner: opts.owner,
    repos: opts.repos,
    hours: opts.hours,
    slowThresholdSec: opts.slowThresholdSec,
    concurrency: opts.concurrency,
    client,
  });

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(formatForensicsSummaryMarkdown(report));
  }

  return { exitCode: report.ok ? 0 : 1, report };
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  runFleetForensicsCli(process.argv.slice(2))
    .then(({ exitCode }) => {
      process.exitCode = exitCode;
    })
    .catch((err) => {
      process.stderr.write(`[fleet-forensics] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    });
}
