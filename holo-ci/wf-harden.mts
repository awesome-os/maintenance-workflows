#!/usr/bin/env node
/**
 * @file holo-ci/wf-harden.mts
 * @description Generic GitHub Actions workflow hardening auditor and deterministic autofixer.
 *
 * Rules match `requireWorkflowHardening` in `holo-ci/verify.mts` 1:1 plus sensitive-workflow
 * concurrency race protection and GitHub Pages action upgrades:
 *   1. Upgrade `goto-bus-stop/setup-zig@*` -> `mlugg/setup-zig@v2`
 *   2. Upgrade legacy core actions:
 *      - `actions/checkout@v1..4` -> `@v7`
 *      - `actions/setup-node@v1..4` -> `@v7`
 *      - `actions/upload-artifact@v1..4` -> `@v7`
 *      - `actions/download-artifact@v1..4` -> `@v8`
 *      - `actions/cache(|/restore|/save)@v1..4` -> `@v6`
 *      - `actions/configure-pages@v1..5` -> `@v6`
 *      - `actions/upload-pages-artifact@v1..4` -> `@v5`
 *      - `actions/deploy-pages@v1..4` -> `@v5`
 *   3. Insert missing top-level `concurrency:` on non-`workflow_call` workflows
 *      (`cancel-in-progress: false` for deploy/publish/release/bump/autoroll, `true` otherwise)
 *   4. Fix `cancel-in-progress: true` race hazards on deploy/publish/release/bump/autoroll -> `false`
 *   5. Insert missing `timeout-minutes: <default>` on jobs declaring `runs-on:`
 *   6. Insert missing `retention-days: <default>` under `actions/upload-artifact` `with:` blocks
 *
 * Strictly `erasableSyntaxOnly: true`, Node built-ins only, `shell: false`.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const WF_HARDEN_SCHEMA = 'holo-ci.wf-harden.v1' as const;
export const B8G_ABI_MAGIC_V3 = '0x33564742' as const;
export const DEFAULT_TIMEOUT_MINUTES = 30;
export const DEFAULT_RETENTION_DAYS = 7;

export type WorkflowHardenRule =
  | 'deprecated-zig-action'
  | 'legacy-core-action'
  | 'missing-concurrency'
  | 'concurrency-cancel-race'
  | 'missing-timeout-minutes'
  | 'missing-artifact-retention';

export type WorkflowHardenSeverity = 'error' | 'warning';

export interface WorkflowHardenFinding {
  readonly rule: WorkflowHardenRule;
  readonly severity: WorkflowHardenSeverity;
  readonly file: string;
  readonly line: number;
  readonly message: string;
  readonly snippet: string;
}

export interface WorkflowHardenFix {
  readonly rule: WorkflowHardenRule;
  readonly line: number;
  readonly description: string;
}

export interface AuditAndHardenOptions {
  readonly fix?: boolean;
  readonly defaultTimeoutMinutes?: number;
  readonly defaultRetentionDays?: number;
}

export interface WorkflowHardenResult {
  readonly fileName: string;
  readonly ok: boolean;
  readonly changed: boolean;
  readonly content: string;
  readonly findings: readonly WorkflowHardenFinding[];
  readonly remainingFindings: readonly WorkflowHardenFinding[];
  readonly fixesApplied: readonly WorkflowHardenFix[];
}

export interface HardenWorkflowsDirOptions {
  readonly fix?: boolean;
  readonly defaultTimeoutMinutes?: number;
  readonly defaultRetentionDays?: number;
}

export interface HardenWorkflowsDirResult {
  readonly schema: typeof WF_HARDEN_SCHEMA;
  readonly abiMagic: typeof B8G_ABI_MAGIC_V3;
  readonly repoDir: string;
  readonly mode: 'check' | 'fix';
  readonly ok: boolean;
  readonly workflowsScanned: number;
  readonly totalFindings: number;
  readonly remainingFindings: number;
  readonly totalFixesApplied: number;
  readonly modifiedFiles: readonly string[];
  readonly files: readonly WorkflowHardenResult[];
}

interface CoreActionUpgradeRule {
  readonly actionPrefix: string;
  readonly regex: RegExp;
  readonly targetTag: string;
}

const DEPRECATED_ZIG_ACTION_REGEX = /\bgoto-bus-stop\/setup-zig(?:@[^\s'"#,}]+)?/gi;

const CORE_ACTION_UPGRADE_RULES: readonly CoreActionUpgradeRule[] = [
  {
    actionPrefix: 'actions/checkout',
    regex: /\b(actions\/checkout)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v7',
  },
  {
    actionPrefix: 'actions/setup-node',
    regex: /\b(actions\/setup-node)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v7',
  },
  {
    actionPrefix: 'actions/upload-artifact',
    regex: /\b(actions\/upload-artifact)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v7',
  },
  {
    actionPrefix: 'actions/download-artifact',
    regex: /\b(actions\/download-artifact)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v8',
  },
  {
    actionPrefix: 'actions/cache',
    regex: /\b(actions\/cache(?:\/restore|\/save)?)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v6',
  },
  {
    actionPrefix: 'actions/configure-pages',
    regex: /\b(actions\/configure-pages)@v[1-5](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v6',
  },
  {
    actionPrefix: 'actions/upload-pages-artifact',
    regex: /\b(actions\/upload-pages-artifact)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v5',
  },
  {
    actionPrefix: 'actions/deploy-pages',
    regex: /\b(actions\/deploy-pages)@v[1-4](?:\.[0-9]+)*(?![0-9])/gi,
    targetTag: 'v5',
  },
];

const UPLOAD_ARTIFACT_USES_REGEX = /\buses\s*:\s*['"]?actions\/upload-artifact(?:@[^\s'"#,}]+)?/i;
const SENSITIVE_WORKFLOW_REGEX = /(?:deploy|publish|release|bump|autoroll)/i;
const RUN_KEY_REGEX = /^(\s*(?:-\s+)?)run\s*:\s*(.*)$/;
const CANCEL_IN_PROGRESS_TRUE_REGEX = /(\bcancel-in-progress\s*:\s*)(['"]?)true\2(?=\s|$|#|,|\})/i;

interface LineInsertion {
  readonly afterIndex: number; // -1 inserts before line 0
  readonly order: number;
  readonly lines: readonly string[];
  readonly fix: WorkflowHardenFix;
}

interface JobScanState {
  readonly name: string;
  propIndent: number;
  hasRunsOn: boolean;
  runsOnLineIndex: number;
  runsOnLastLineIndex: number;
  inRunsOnBlock: boolean;
  hasTimeout: boolean;
  stepsKeyIndent: number;
  stepListIndent: number;
  inJobConcurrency: boolean;
  jobConcurrencyIndent: number;
}

interface StepScanState {
  readonly listIndent: number;
  propIndent: number;
  lastContentLineIndex: number;
  uploadLineIndex: number | null;
  uploadAllowlisted: boolean;
  hasRetention: boolean;
  withLineIndex: number | null;
  withIndent: number;
  withInlineFlow: boolean;
  withChildIndent: number;
  withLastContentLineIndex: number;
  inWithBlock: boolean;
}

function isAllowlistedLine(lineText: string): boolean {
  return lineText.includes('holo-ci-allow-guard');
}

function splitYamlCodeAndComment(line: string): { readonly code: string; readonly comment: string } {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle && (i === 0 || line[i - 1] !== '\\')) {
      inDouble = !inDouble;
    } else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]!))) {
      return { code: line.slice(0, i), comment: line.slice(i) };
    }
  }
  return { code: line, comment: '' };
}

function stripYamlComment(value: string): string {
  return splitYamlCodeAndComment(value).code.trim();
}

function stripYamlQuotes(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function upgradeActionsInLine(lineText: string): {
  readonly updated: string;
  readonly findings: readonly { readonly rule: WorkflowHardenRule; readonly from: string; readonly to: string }[];
} {
  const { code, comment } = splitYamlCodeAndComment(lineText);
  let nextCode = code;
  const hitFindings: Array<{ readonly rule: WorkflowHardenRule; readonly from: string; readonly to: string }> = [];

  DEPRECATED_ZIG_ACTION_REGEX.lastIndex = 0;
  nextCode = nextCode.replace(DEPRECATED_ZIG_ACTION_REGEX, (match) => {
    hitFindings.push({
      rule: 'deprecated-zig-action',
      from: match,
      to: 'mlugg/setup-zig@v2',
    });
    return 'mlugg/setup-zig@v2';
  });

  for (const rule of CORE_ACTION_UPGRADE_RULES) {
    rule.regex.lastIndex = 0;
    nextCode = nextCode.replace(rule.regex, (match, actionName: string) => {
      const upgraded = `${actionName.toLowerCase()}@${rule.targetTag}`;
      hitFindings.push({
        rule: 'legacy-core-action',
        from: match,
        to: upgraded,
      });
      return upgraded;
    });
  }

  return {
    updated: `${nextCode}${comment}`,
    findings: hitFindings,
  };
}

function insertRetentionInInlineFlowWith(lineText: string, retentionDays: number): string | null {
  const { code, comment } = splitYamlCodeAndComment(lineText);
  const openIdx = code.indexOf('{');
  const closeIdx = code.lastIndexOf('}');
  if (openIdx === -1 || closeIdx === -1 || closeIdx <= openIdx) return null;

  const inside = code.slice(openIdx + 1, closeIdx);
  const trimmedInside = inside.trim();
  const hasTrailingSpace = /\s$/.test(inside);
  const trailingWs = hasTrailingSpace ? ' ' : '';
  const body =
    trimmedInside.length === 0
      ? ` retention-days: ${retentionDays} `
      : `${inside.trimEnd()}, retention-days: ${retentionDays}${trailingWs}`;

  return `${code.slice(0, openIdx + 1)}${body}${code.slice(closeIdx)}${comment}`;
}

interface ScanAndPlanResult {
  readonly findings: readonly WorkflowHardenFinding[];
  readonly lineReplacements: ReadonlyMap<number, { readonly text: string; readonly fixes: readonly WorkflowHardenFix[] }>;
  readonly insertions: readonly LineInsertion[];
}

function scanAndPlanWorkflow(
  lines: readonly string[],
  fileName: string,
  defaultTimeoutMinutes: number,
  defaultRetentionDays: number,
): ScanAndPlanResult {
  const fileBase = basename(fileName, extname(fileName));
  const findings: WorkflowHardenFinding[] = [];
  const lineTexts = [...lines];
  const lineFixes = new Map<number, WorkflowHardenFix[]>();
  const insertions: LineInsertion[] = [];
  let insertionOrder = 0;

  const recordLineReplacement = (lineIndex: number, nextText: string, fix: WorkflowHardenFix): void => {
    lineTexts[lineIndex] = nextText;
    const bucket = lineFixes.get(lineIndex);
    if (bucket) {
      bucket.push(fix);
    } else {
      lineFixes.set(lineIndex, [fix]);
    }
  };

  let workflowName = '';
  let hasTopConcurrency = false;
  let hasWorkflowCall = false;
  let inOnBlock = false;
  let onLastContentLineIndex = -1;
  let jobsLineIndex = -1;
  let nameLineIndex = -1;
  let inTopConcurrencyBlock = false;
  let inJobsBlock = false;
  let jobKeyIndent = -1;

  let currentJob: JobScanState | null = null;
  const jobs: JobScanState[] = [];
  const cancelRaceLineIndices: number[] = [];

  let activeStep: StepScanState | null = null;
  let inRunBlock = false;
  let runKeyIndent = -1;
  let runBlockIndent = -1;

  const flushUploadStep = (): void => {
    if (activeStep && activeStep.uploadLineIndex !== null && !activeStep.uploadAllowlisted && !activeStep.hasRetention) {
      const uploadLine = activeStep.uploadLineIndex + 1;
      findings.push({
        rule: 'missing-artifact-retention',
        severity: 'warning',
        file: fileName,
        line: uploadLine,
        message: `${fileName}:${uploadLine} uses actions/upload-artifact without explicit retention-days`,
        snippet: lines[activeStep.uploadLineIndex]!.trim().slice(0, 160),
      });

      const fix: WorkflowHardenFix = {
        rule: 'missing-artifact-retention',
        line: uploadLine,
        description: `Add retention-days: ${defaultRetentionDays} to actions/upload-artifact step`,
      };

      if (activeStep.withInlineFlow && activeStep.withLineIndex !== null) {
        const inlineUpdated = insertRetentionInInlineFlowWith(
          lineTexts[activeStep.withLineIndex]!,
          defaultRetentionDays,
        );
        if (inlineUpdated !== null) {
          recordLineReplacement(activeStep.withLineIndex, inlineUpdated, fix);
        }
      } else if (activeStep.withLineIndex !== null) {
        const childIndent =
          activeStep.withChildIndent !== -1 ? activeStep.withChildIndent : activeStep.withIndent + 2;
        insertions.push({
          afterIndex: activeStep.withLastContentLineIndex,
          order: insertionOrder++,
          lines: [`${' '.repeat(childIndent)}retention-days: ${defaultRetentionDays}`],
          fix,
        });
      } else {
        const propIndent =
          activeStep.propIndent !== -1 ? activeStep.propIndent : activeStep.listIndent + 2;
        insertions.push({
          afterIndex: activeStep.lastContentLineIndex,
          order: insertionOrder++,
          lines: [
            `${' '.repeat(propIndent)}with:`,
            `${' '.repeat(propIndent + 2)}retention-days: ${defaultRetentionDays}`,
          ],
          fix,
        });
      }
    }
    activeStep = null;
  };

  const flushJob = (): void => {
    flushUploadStep();
    if (currentJob) {
      jobs.push(currentJob);
      currentJob = null;
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i]!;
    const trimmed = lineText.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    const indent = lineText.length - lineText.trimStart().length;

    if (inRunBlock) {
      if (indent <= runKeyIndent || (runBlockIndent !== -1 && indent < runBlockIndent)) {
        inRunBlock = false;
        runKeyIndent = -1;
        runBlockIndent = -1;
      } else {
        if (runBlockIndent === -1) runBlockIndent = indent;
        if (activeStep) {
          activeStep.lastContentLineIndex = i;
        }
        if (!isAllowlistedLine(lineText)) {
          const { updated, findings: actionHits } = upgradeActionsInLine(lineTexts[i]!);
          if (actionHits.length > 0) {
            for (const hit of actionHits) {
              findings.push({
                rule: hit.rule,
                severity: 'warning',
                file: fileName,
                line: i + 1,
                message: `${fileName}:${i + 1} upgrades ${hit.from} -> ${hit.to}`,
                snippet: trimmed.slice(0, 160),
              });
              recordLineReplacement(i, updated, {
                rule: hit.rule,
                line: i + 1,
                description: `Upgrade ${hit.from} -> ${hit.to}`,
              });
            }
          }
        }
        continue;
      }
    }

    if (!isAllowlistedLine(lineText)) {
      const { updated, findings: actionHits } = upgradeActionsInLine(lineTexts[i]!);
      if (actionHits.length > 0) {
        for (const hit of actionHits) {
          findings.push({
            rule: hit.rule,
            severity: 'warning',
            file: fileName,
            line: i + 1,
            message: `${fileName}:${i + 1} upgrades ${hit.from} -> ${hit.to}`,
            snippet: trimmed.slice(0, 160),
          });
          recordLineReplacement(i, updated, {
            rule: hit.rule,
            line: i + 1,
            description: `Upgrade ${hit.from} -> ${hit.to}`,
          });
        }
      }
    }

    if (indent === 0) {
      flushJob();
      inOnBlock = false;
      inTopConcurrencyBlock = false;
      inJobsBlock = false;
      jobKeyIndent = -1;

      if (/^name\s*:/.test(trimmed)) {
        nameLineIndex = i;
        workflowName = stripYamlQuotes(stripYamlComment(trimmed.replace(/^name\s*:\s*/, '')));
      } else if (/^concurrency\s*:/.test(trimmed)) {
        hasTopConcurrency = true;
        const afterConcurrency = stripYamlComment(trimmed.replace(/^concurrency\s*:\s*/, ''));
        if (CANCEL_IN_PROGRESS_TRUE_REGEX.test(afterConcurrency) && !isAllowlistedLine(lineText)) {
          cancelRaceLineIndices.push(i);
        }
        if (afterConcurrency.length === 0 || afterConcurrency.startsWith('{')) {
          inTopConcurrencyBlock = true;
        }
      } else if (/^on\s*:/.test(trimmed)) {
        onLastContentLineIndex = i;
        const afterOn = stripYamlComment(trimmed.replace(/^on\s*:\s*/, ''));
        if (afterOn.length === 0) {
          inOnBlock = true;
        } else if (/\bworkflow_call\b/.test(afterOn)) {
          hasWorkflowCall = true;
        }
      } else if (/^jobs\s*:/.test(trimmed)) {
        jobsLineIndex = i;
        inJobsBlock = true;
      }
    } else if (inOnBlock) {
      onLastContentLineIndex = i;
      if (/^(?:-\s+)?workflow_call(?:\s*:|\s*$)/.test(stripYamlComment(trimmed))) {
        hasWorkflowCall = true;
      }
    } else if (inTopConcurrencyBlock) {
      const codeOnly = stripYamlComment(trimmed);
      if (CANCEL_IN_PROGRESS_TRUE_REGEX.test(codeOnly) && !isAllowlistedLine(lineText)) {
        cancelRaceLineIndices.push(i);
      }
    } else if (inJobsBlock) {
      if (jobKeyIndent === -1) jobKeyIndent = indent;

      if (indent === jobKeyIndent && /^[A-Za-z0-9_.-]+\s*:/.test(trimmed)) {
        flushJob();
        currentJob = {
          name: trimmed.split(':')[0]!.trim(),
          propIndent: -1,
          hasRunsOn: false,
          runsOnLineIndex: i,
          runsOnLastLineIndex: i,
          inRunsOnBlock: false,
          hasTimeout: false,
          stepsKeyIndent: -1,
          stepListIndent: -1,
          inJobConcurrency: false,
          jobConcurrencyIndent: -1,
        };
        continue;
      }

      if (currentJob) {
        if (currentJob.propIndent === -1 && indent > jobKeyIndent) {
          currentJob.propIndent = indent;
        }

        if (currentJob.inRunsOnBlock) {
          if (indent > currentJob.propIndent) {
            currentJob.runsOnLastLineIndex = i;
            continue;
          }
          currentJob.inRunsOnBlock = false;
        }

        if (currentJob.inJobConcurrency && indent <= currentJob.jobConcurrencyIndent) {
          currentJob.inJobConcurrency = false;
          currentJob.jobConcurrencyIndent = -1;
        }

        if (
          currentJob.stepsKeyIndent !== -1 &&
          indent <= currentJob.stepsKeyIndent &&
          !trimmed.startsWith('-')
        ) {
          flushUploadStep();
          currentJob.stepsKeyIndent = -1;
          currentJob.stepListIndent = -1;
        }

        if (currentJob.inJobConcurrency) {
          const codeOnly = stripYamlComment(trimmed);
          if (CANCEL_IN_PROGRESS_TRUE_REGEX.test(codeOnly) && !isAllowlistedLine(lineText)) {
            cancelRaceLineIndices.push(i);
          }
        } else if (indent === currentJob.propIndent && currentJob.stepsKeyIndent === -1) {
          if (/^runs-on\s*:/.test(trimmed)) {
            currentJob.hasRunsOn = true;
            currentJob.runsOnLineIndex = i;
            currentJob.runsOnLastLineIndex = i;
            const afterRunsOn = stripYamlComment(trimmed.replace(/^runs-on\s*:\s*/, ''));
            if (afterRunsOn.length === 0) {
              currentJob.inRunsOnBlock = true;
            }
          } else if (/^timeout-minutes\s*:/.test(trimmed)) {
            currentJob.hasTimeout = true;
          } else if (/^concurrency\s*:/.test(trimmed)) {
            const afterJobConc = stripYamlComment(trimmed.replace(/^concurrency\s*:\s*/, ''));
            if (CANCEL_IN_PROGRESS_TRUE_REGEX.test(afterJobConc) && !isAllowlistedLine(lineText)) {
              cancelRaceLineIndices.push(i);
            }
            if (afterJobConc.length === 0) {
              currentJob.inJobConcurrency = true;
              currentJob.jobConcurrencyIndent = indent;
            }
          } else if (/^steps\s*:/.test(trimmed)) {
            currentJob.stepsKeyIndent = indent;
          }
        } else if (currentJob.stepsKeyIndent !== -1) {
          if (currentJob.stepListIndent === -1 && trimmed.startsWith('-')) {
            currentJob.stepListIndent = indent;
          }
          if (currentJob.stepListIndent !== -1) {
            if (indent < currentJob.stepListIndent) {
              flushUploadStep();
            } else if (indent === currentJob.stepListIndent && /^-\s+/.test(trimmed)) {
              flushUploadStep();
              activeStep = {
                listIndent: indent,
                propIndent: -1,
                lastContentLineIndex: i,
                uploadLineIndex: null,
                uploadAllowlisted: false,
                hasRetention: false,
                withLineIndex: null,
                withIndent: -1,
                withInlineFlow: false,
                withChildIndent: -1,
                withLastContentLineIndex: -1,
                inWithBlock: false,
              };
            }

            if (activeStep) {
              activeStep.lastContentLineIndex = i;
              const isDashLine = indent === activeStep.listIndent && /^-\s+/.test(trimmed);
              const stepBody = isDashLine ? trimmed.replace(/^-\s+/, '') : trimmed;

              if (!isDashLine && activeStep.propIndent === -1 && indent > activeStep.listIndent) {
                activeStep.propIndent = indent;
              }

              if (activeStep.inWithBlock) {
                if (indent <= activeStep.withIndent) {
                  activeStep.inWithBlock = false;
                } else {
                  if (activeStep.withChildIndent === -1) {
                    activeStep.withChildIndent = indent;
                  }
                  activeStep.withLastContentLineIndex = i;
                  if (/\bretention-days\s*:/i.test(stripYamlComment(stepBody))) {
                    activeStep.hasRetention = true;
                  }
                }
              }

              if (!activeStep.inWithBlock) {
                if (UPLOAD_ARTIFACT_USES_REGEX.test(stepBody)) {
                  activeStep.uploadLineIndex = i;
                  activeStep.uploadAllowlisted = isAllowlistedLine(lineText);
                }

                const effectivePropIndent =
                  activeStep.propIndent !== -1 ? activeStep.propIndent : activeStep.listIndent + 2;
                const isWithKey =
                  (isDashLine || indent === effectivePropIndent) && /^with\s*:/.test(stepBody);
                if (isWithKey) {
                  activeStep.withLineIndex = i;
                  activeStep.withIndent = isDashLine ? activeStep.listIndent + 2 : indent;
                  activeStep.withLastContentLineIndex = i;
                  const afterWith = stripYamlComment(stepBody.replace(/^with\s*:\s*/, ''));
                  if (afterWith.startsWith('{') && afterWith.endsWith('}')) {
                    activeStep.withInlineFlow = true;
                    if (/\bretention-days\s*:/i.test(afterWith)) {
                      activeStep.hasRetention = true;
                    }
                  } else if (afterWith.length === 0) {
                    activeStep.inWithBlock = true;
                  }
                } else if (/\bretention-days\s*:/i.test(stripYamlComment(stepBody))) {
                  activeStep.hasRetention = true;
                }
              }
            }
          }
        }
      }
    }

    const runMatch = RUN_KEY_REGEX.exec(lineText);
    if (runMatch) {
      const rest = runMatch[2]!.trim();
      if (/^[|>][+-]?(?:\s+#.*)?$/.test(rest)) {
        inRunBlock = true;
        runKeyIndent = indent;
        runBlockIndent = -1;
      }
    }
  }

  flushJob();

  const isSensitiveWorkflow =
    SENSITIVE_WORKFLOW_REGEX.test(fileBase) || SENSITIVE_WORKFLOW_REGEX.test(workflowName);

  if (!hasWorkflowCall && !hasTopConcurrency) {
    const cancelInProgress = !isSensitiveWorkflow;
    findings.push({
      rule: 'missing-concurrency',
      severity: 'warning',
      file: fileName,
      line: 1,
      message: `${fileName}:1 non-reusable workflow is missing top-level concurrency group`,
      snippet: 'Non-reusable workflow missing top-level concurrency:',
    });

    const anchorIndex =
      onLastContentLineIndex !== -1
        ? onLastContentLineIndex
        : jobsLineIndex !== -1
          ? jobsLineIndex - 1
          : nameLineIndex;

    const concurrencyBlock = [
      'concurrency:',
      '  group: ${{ github.workflow }}-${{ github.ref }}',
      `  cancel-in-progress: ${cancelInProgress ? 'true' : 'false'}`,
    ];

    const prevLineIsBlank = anchorIndex >= 0 && (lines[anchorIndex]?.trim().length ?? 0) === 0;
    const nextLineExists = anchorIndex + 1 < lines.length;
    const nextLineIsBlank = nextLineExists && (lines[anchorIndex + 1]?.trim().length ?? 0) === 0;

    const linesToInsert: string[] = [];
    if (anchorIndex >= 0 && !prevLineIsBlank) {
      linesToInsert.push('');
    }
    linesToInsert.push(...concurrencyBlock);
    if (nextLineExists && !nextLineIsBlank) {
      linesToInsert.push('');
    }

    insertions.push({
      afterIndex: anchorIndex,
      order: insertionOrder++,
      lines: linesToInsert,
      fix: {
        rule: 'missing-concurrency',
        line: Math.max(1, anchorIndex + 2),
        description: `Insert top-level concurrency (cancel-in-progress: ${cancelInProgress ? 'true' : 'false'})`,
      },
    });
  }

  if (isSensitiveWorkflow) {
    for (const raceIndex of cancelRaceLineIndices) {
      findings.push({
        rule: 'concurrency-cancel-race',
        severity: 'error',
        file: fileName,
        line: raceIndex + 1,
        message: `${fileName}:${raceIndex + 1} sets cancel-in-progress: true on deploy/publish/release/bump/autoroll workflow (race hazard)`,
        snippet: lines[raceIndex]!.trim().slice(0, 160),
      });

      const currentLine = lineTexts[raceIndex]!;
      const { code, comment } = splitYamlCodeAndComment(currentLine);
      const replacedCode = code.replace(CANCEL_IN_PROGRESS_TRUE_REGEX, '$1$2false$2');
      if (replacedCode !== code) {
        recordLineReplacement(raceIndex, `${replacedCode}${comment}`, {
          rule: 'concurrency-cancel-race',
          line: raceIndex + 1,
          description: 'Change cancel-in-progress: true -> false on sensitive workflow',
        });
      }
    }
  }

  for (const job of jobs) {
    if (job.hasRunsOn && !job.hasTimeout) {
      const runsOnLine = job.runsOnLineIndex + 1;
      findings.push({
        rule: 'missing-timeout-minutes',
        severity: 'warning',
        file: fileName,
        line: runsOnLine,
        message: `${fileName}:${runsOnLine} job "${job.name}" declares runs-on without timeout-minutes`,
        snippet: `Job "${job.name}" declares runs-on without timeout-minutes`,
      });

      const indentSpaces = ' '.repeat(job.propIndent > 0 ? job.propIndent : 4);
      insertions.push({
        afterIndex: job.runsOnLastLineIndex,
        order: insertionOrder++,
        lines: [`${indentSpaces}timeout-minutes: ${defaultTimeoutMinutes}`],
        fix: {
          rule: 'missing-timeout-minutes',
          line: runsOnLine,
          description: `Insert timeout-minutes: ${defaultTimeoutMinutes} on job "${job.name}"`,
        },
      });
    }
  }

  const lineReplacements = new Map<
    number,
    { readonly text: string; readonly fixes: readonly WorkflowHardenFix[] }
  >();
  for (const [idx, fixes] of lineFixes.entries()) {
    lineReplacements.set(idx, { text: lineTexts[idx]!, fixes });
  }

  return { findings, lineReplacements, insertions };
}

/**
 * Audits a single GitHub Actions workflow YAML document against Awesome-OS hardening rules
 * and optionally applies deterministic autofixes preserving indentation and comments.
 */
export function auditAndHardenWorkflowYaml(
  yamlText: string,
  fileName: string,
  options: AuditAndHardenOptions = {},
): WorkflowHardenResult {
  const fix = options.fix === true;
  const defaultTimeoutMinutes =
    typeof options.defaultTimeoutMinutes === 'number' &&
    Number.isInteger(options.defaultTimeoutMinutes) &&
    options.defaultTimeoutMinutes > 0
      ? options.defaultTimeoutMinutes
      : DEFAULT_TIMEOUT_MINUTES;
  const defaultRetentionDays =
    typeof options.defaultRetentionDays === 'number' &&
    Number.isInteger(options.defaultRetentionDays) &&
    options.defaultRetentionDays > 0
      ? options.defaultRetentionDays
      : DEFAULT_RETENTION_DAYS;

  const eol = yamlText.includes('\r\n') ? '\r\n' : '\n';
  const hasTrailingNewline = /\r?\n$/.test(yamlText);
  const rawLines =
    yamlText.length === 0 ? [] : yamlText.replace(/\r?\n$/, '').split(/\r?\n/);

  const plan = scanAndPlanWorkflow(rawLines, fileName, defaultTimeoutMinutes, defaultRetentionDays);

  if (!fix) {
    return {
      fileName,
      ok: plan.findings.length === 0,
      changed: false,
      content: yamlText,
      findings: plan.findings,
      remainingFindings: plan.findings,
      fixesApplied: [],
    };
  }

  const outLines = [...rawLines];
  const fixesApplied: WorkflowHardenFix[] = [];

  for (const [lineIdx, rep] of plan.lineReplacements.entries()) {
    outLines[lineIdx] = rep.text;
    fixesApplied.push(...rep.fixes);
  }

  const sortedInsertions = [...plan.insertions].sort(
    (a, b) => b.afterIndex - a.afterIndex || b.order - a.order,
  );
  for (const ins of sortedInsertions) {
    const splicePos = Math.max(0, ins.afterIndex + 1);
    outLines.splice(splicePos, 0, ...ins.lines);
    fixesApplied.push(ins.fix);
  }

  fixesApplied.sort((a, b) => a.line - b.line || a.rule.localeCompare(b.rule));

  const rendered =
    outLines.length === 0
      ? ''
      : `${outLines.join(eol)}${hasTrailingNewline || fixesApplied.length > 0 ? eol : ''}`;
  const changed = rendered !== yamlText;

  const recheckLines =
    rendered.length === 0 ? [] : rendered.replace(/\r?\n$/, '').split(/\r?\n/);
  const remaining = scanAndPlanWorkflow(
    recheckLines,
    fileName,
    defaultTimeoutMinutes,
    defaultRetentionDays,
  ).findings;

  return {
    fileName,
    ok: remaining.length === 0,
    changed,
    content: rendered,
    findings: plan.findings,
    remainingFindings: remaining,
    fixesApplied,
  };
}

/**
 * Scans `.github/workflows/*.{yml,yaml}` under `repoDir` and audits or autofixes every workflow.
 */
export function hardenWorkflowsInDir(
  repoDir: string,
  options: HardenWorkflowsDirOptions = {},
): HardenWorkflowsDirResult {
  const resolvedRepoDir = resolve(repoDir);
  const fix = options.fix === true;
  const workflowsDir = join(resolvedRepoDir, '.github', 'workflows');
  const workflowPaths: string[] = [];

  if (existsSync(workflowsDir)) {
    for (const entry of readdirSync(workflowsDir, { withFileTypes: true })) {
      if (entry.isFile() && /\.(ya?ml)$/i.test(entry.name)) {
        workflowPaths.push(join(workflowsDir, entry.name));
      }
    }
  }
  workflowPaths.sort((a, b) => a.localeCompare(b));

  const files: WorkflowHardenResult[] = [];
  const modifiedFiles: string[] = [];
  let totalFindings = 0;
  let remainingFindings = 0;
  let totalFixesApplied = 0;

  for (const wfPath of workflowPaths) {
    const relPath = relative(resolvedRepoDir, wfPath).replace(/\\/g, '/');
    const original = readFileSync(wfPath, 'utf8');
    const res = auditAndHardenWorkflowYaml(original, relPath, options);

    if (fix && res.changed) {
      writeFileSync(wfPath, res.content, 'utf8');
      modifiedFiles.push(relPath);
    }

    totalFindings += res.findings.length;
    remainingFindings += res.remainingFindings.length;
    totalFixesApplied += res.fixesApplied.length;
    files.push(res);
  }

  return {
    schema: WF_HARDEN_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    repoDir: resolvedRepoDir,
    mode: fix ? 'fix' : 'check',
    ok: files.every((f) => f.ok),
    workflowsScanned: workflowPaths.length,
    totalFindings,
    remainingFindings,
    totalFixesApplied,
    modifiedFiles,
    files,
  };
}

export interface ParsedWfHardenCliArgs {
  readonly fix: boolean;
  readonly cwd: string;
  readonly json: boolean;
  readonly help: boolean;
  readonly defaultTimeoutMinutes?: number;
  readonly defaultRetentionDays?: number;
}

export function getWfHardenHelpText(): string {
  return [
    'wf-harden — Generic GitHub Actions workflow hardening auditor & autofixer',
    '',
    'Usage:',
    '  node holo-ci/wf-harden.mts [--check | --fix] [--cwd <dir>] [--json]',
    '                             [--timeout-minutes <n>] [--retention-days <n>]',
    '',
    'Options:',
    '  --check                Audit workflows without modifying files (default)',
    '  --fix                  Deterministically autofix workflows in-place',
    '  --cwd <dir>            Target repository root (default: process.cwd())',
    '  --json                 Emit structured JSON report to stdout',
    `  --timeout-minutes <n>  Default timeout-minutes to insert (default: ${DEFAULT_TIMEOUT_MINUTES})`,
    `  --retention-days <n>   Default artifact retention-days to insert (default: ${DEFAULT_RETENTION_DAYS})`,
    '  -h, --help             Show this help message',
    '',
  ].join('\n');
}

export function parseWfHardenCliArgs(argv: readonly string[]): ParsedWfHardenCliArgs {
  let fix = false;
  let cwd = process.cwd();
  let json = false;
  let help = false;
  let defaultTimeoutMinutes: number | undefined;
  let defaultRetentionDays: number | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--fix') {
      fix = true;
    } else if (arg === '--check') {
      fix = false;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--cwd' && i + 1 < argv.length) {
      cwd = resolve(argv[++i]!);
    } else if (arg === '--timeout-minutes' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout-minutes value: "${argv[i]}"`);
      }
      defaultTimeoutMinutes = parsed;
    } else if (arg === '--retention-days' && i + 1 < argv.length) {
      const parsed = Number(argv[++i]!);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --retention-days value: "${argv[i]}"`);
      }
      defaultRetentionDays = parsed;
    } else {
      throw new Error(`Unknown or incomplete argument: "${arg}"`);
    }
  }

  return {
    fix,
    cwd,
    json,
    help,
    ...(defaultTimeoutMinutes !== undefined ? { defaultTimeoutMinutes } : {}),
    ...(defaultRetentionDays !== undefined ? { defaultRetentionDays } : {}),
  };
}

export function runWfHardenCli(argv: readonly string[]): {
  readonly exitCode: number;
  readonly result?: HardenWorkflowsDirResult;
} {
  const opts = parseWfHardenCliArgs(argv);
  if (opts.help) {
    process.stdout.write(getWfHardenHelpText());
    return { exitCode: 0 };
  }

  const result = hardenWorkflowsInDir(opts.cwd, {
    fix: opts.fix,
    defaultTimeoutMinutes: opts.defaultTimeoutMinutes,
    defaultRetentionDays: opts.defaultRetentionDays,
  });

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    const status = result.ok ? 'PASS' : 'FAIL';
    process.stdout.write(
      `[wf-harden] ${result.mode} ${result.workflowsScanned} workflow(s) -> ${status} (findings=${result.totalFindings}, fixed=${result.totalFixesApplied}, remaining=${result.remainingFindings}, modified=${result.modifiedFiles.length})\n`,
    );
    for (const file of result.files) {
      const reportFindings = opts.fix ? file.remainingFindings : file.findings;
      for (const finding of reportFindings) {
        process.stdout.write(`  [${finding.rule}] ${finding.file}:${finding.line} ${finding.message}\n`);
      }
    }
  }

  return { exitCode: result.ok ? 0 : 1, result };
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  try {
    const { exitCode } = runWfHardenCli(process.argv.slice(2));
    process.exitCode = exitCode;
  } catch (err) {
    process.stderr.write(`[wf-harden] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}
