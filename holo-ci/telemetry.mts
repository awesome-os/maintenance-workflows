import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_CI_RECEIPT_SCHEMA,
  type HoloCiManifest,
  type HoloCiPhase,
  type HoloCiReceipt,
} from './schema.mts';

export interface BuildReceiptInput {
  manifest: HoloCiManifest;
  phase: HoloCiPhase;
  ok: boolean;
  durationMs: number;
  verify?: HoloCiReceipt['verify'];
  sync?: HoloCiReceipt['sync'];
  bump?: HoloCiReceipt['bump'];
  pack?: HoloCiReceipt['pack'];
  maintain?: HoloCiReceipt['maintain'];
  lockCompat?: HoloCiReceipt['lockCompat'];
  boundaryAudit?: HoloCiReceipt['boundaryAudit'];
  wfHarden?: HoloCiReceipt['wfHarden'];
  wfHardenFleet?: HoloCiReceipt['wfHardenFleet'];
  auditStack?: HoloCiReceipt['auditStack'];
  fleetForensics?: HoloCiReceipt['fleetForensics'];
  errors?: string[];
}

export function buildReceipt(input: BuildReceiptInput): HoloCiReceipt {
  return {
    schema: HOLO_CI_RECEIPT_SCHEMA,
    abiMagic: B8G_ABI_MAGIC_V3,
    generatedAt: new Date().toISOString(),
    phase: input.phase,
    name: input.manifest.name,
    kind: input.manifest.kind,
    ok: input.ok,
    durationMs: input.durationMs,
    ...(input.verify ? { verify: input.verify } : {}),
    ...(input.sync ? { sync: input.sync } : {}),
    ...(input.bump ? { bump: input.bump } : {}),
    ...(input.pack ? { pack: input.pack } : {}),
    ...(input.maintain ? { maintain: input.maintain } : {}),
    ...(input.lockCompat ? { lockCompat: input.lockCompat } : {}),
    ...(input.boundaryAudit ? { boundaryAudit: input.boundaryAudit } : {}),
    ...(input.wfHarden ? { wfHarden: input.wfHarden } : {}),
    ...(input.wfHardenFleet ? { wfHardenFleet: input.wfHardenFleet } : {}),
    ...(input.auditStack ? { auditStack: input.auditStack } : {}),
    ...(input.fleetForensics ? { fleetForensics: input.fleetForensics } : {}),
    ...(input.errors && input.errors.length > 0 ? { errors: input.errors } : {}),
  };
}

interface SummaryViolationRow {
  readonly rule: string;
  readonly location: string;
  readonly detail: string;
}

function escapeMdCell(value: string): string {
  return value.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim().slice(0, 220);
}

function appendViolationTable(lines: string[], heading: string, rows: readonly SummaryViolationRow[]): void {
  if (rows.length === 0) return;
  lines.push(
    '',
    `### ${heading} (${rows.length})`,
    '',
    '| Rule / Guard | File:Line | Snippet / Message |',
    '| :--- | :--- | :--- |',
  );
  for (const row of rows) {
    lines.push(
      `| \`${escapeMdCell(row.rule)}\` | \`${escapeMdCell(row.location)}\` | ${escapeMdCell(row.detail)} |`,
    );
  }
}

export function formatStepSummaryMarkdown(receipt: HoloCiReceipt): string {
  const statusBadge = receipt.ok ? 'PASS' : 'FAIL';
  const lines: string[] = [
    `## Holo-CI Receipt — \`${receipt.name}\` (\`${receipt.phase}\`) [${statusBadge}]`,
    '',
    '| Field | Value |',
    '| :--- | :--- |',
    `| Schema / ABI Magic | \`${receipt.schema}\` / \`${receipt.abiMagic}\` |`,
    `| Repository Kind | \`${receipt.kind}\` |`,
    `| Phase | \`${receipt.phase}\` |`,
    `| Status | **${statusBadge}** (${receipt.durationMs} ms) |`,
  ];

  if (receipt.verify) {
    const passedTests = receipt.verify.tests.filter((t) => t.ok).length;
    const passedGates = receipt.verify.nativeGates.filter((g) => g.ok).length;
    const foundDocs = receipt.verify.docs.filter((d) => d.exists).length;
    lines.push(
      `| Tests | ${passedTests}/${receipt.verify.tests.length} passed |`,
      `| Native Gates | ${passedGates}/${receipt.verify.nativeGates.length} passed |`,
      `| Docs Verified | ${foundDocs}/${receipt.verify.docs.length} present |`,
      `| Guard Violations | ${receipt.verify.guardViolations.length} |`,
    );
  }

  if (receipt.sync) {
    const cleanPairs = receipt.sync.pairs.filter((p) => p.ok).length;
    lines.push(
      `| Sync Pairs | ${cleanPairs}/${receipt.sync.pairs.length} clean |`,
      `| Git Audit | ${receipt.sync.git.available ? (receipt.sync.git.clean ? 'clean' : 'dirty') : 'n/a'} (${receipt.sync.git.branch || 'detached'}) |`,
    );
  }

  if (receipt.bump) {
    const okPins = receipt.bump.pins.filter((p) => p.ok).length;
    lines.push(`| Upstream Pins | ${okPins}/${receipt.bump.pins.length} compliant |`);
    if (receipt.bump.packageBump) {
      lines.push(
        `| Package Bump | \`${receipt.bump.packageBump.previousVersion}\` -> \`${receipt.bump.packageBump.newVersion}\` (updated=${receipt.bump.packageBump.updated}) |`,
      );
    }
  }

  if (receipt.pack) {
    lines.push(
      `| SHA-512 Pack | ${receipt.pack.dedup.uniqueSha512Blobs} unique / ${receipt.pack.dedup.totalAssets} assets (${receipt.pack.dedup.savedBytes} B saved · ${receipt.pack.dedup.dedupRatioPct}%) |`,
    );
  }

  if (receipt.maintain) {
    const okEndpoints = receipt.maintain.endpoints.filter((e) => e.ok).length;
    lines.push(
      `| Clean-Box Endpoints | ${okEndpoints}/${receipt.maintain.endpoints.length} HTTP 200 verified |`,
      `| Bundle Integrity | ${receipt.maintain.bundleChecked} checked (${receipt.maintain.bundleMismatches.length} mismatches) |`,
    );
  }

  if (receipt.lockCompat) {
    lines.push(
      `| Lock Compat | \`ecosystem=${receipt.lockCompat.ecosystem}\` (\`lockfileVersion: ${receipt.lockCompat.lockfileVersion}\`) · ${receipt.lockCompat.artifacts.length} artifacts · ${receipt.lockCompat.packageCount} entries (${receipt.lockCompat.resolvedFromPnpmLock} pnpm, ${receipt.lockCompat.resolvedFromMaxLock} max-lock, dryRun=${receipt.lockCompat.dryRun}) |`,
    );
  }

  if (receipt.boundaryAudit) {
    const ba = receipt.boundaryAudit;
    const a = ba.axes;
    lines.push(
      `| Boundary Audit | **${ba.score}/100** (files=${ba.scannedFiles}, manifest=${ba.manifestFound ? (ba.boundaryPath ?? 'yes') : 'default'}, violations=${ba.violations.length}) |`,
      `| Boundary Axes | Purity ${a.dependencyPurity}/20 · Encap ${a.encapsulation}/20 · IPC ${a.ipcCompliance}/20 · ABI ${a.abiContract}/20 · Gov ${a.governance}/20 |`,
    );
  }

  if (receipt.wfHarden) {
    const wf = receipt.wfHarden;
    lines.push(
      `| Workflow Hardening | mode=\`${wf.mode}\` · ${wf.workflowsScanned} workflows · findings=${wf.totalFindings} · fixed=${wf.totalFixesApplied} · remaining=${wf.remainingFindings} |`,
    );
  }

  if (receipt.wfHardenFleet) {
    const fleet = receipt.wfHardenFleet;
    lines.push(
      `| Fleet Workflow Hardening | mode=\`${fleet.mode}\` · ${fleet.passedRepos}/${fleet.reposScanned} repos clean · ${fleet.workflowsScanned} workflows · findings=${fleet.totalFindings} · fixed=${fleet.totalFixesApplied} · remaining=${fleet.remainingFindings} |`,
    );
  }

  if (receipt.auditStack) {
    const as = receipt.auditStack;
    lines.push(
      `| Audit Stack | mode=\`${as.mode}\` · ${as.passedAudits}/${as.totalAudits} audits passed · failed=${as.failedAudits} · aborted=${as.abortedAudits} · violations=${as.violationCount} |`,
    );
  }

  if (receipt.fleetForensics) {
    const ff = receipt.fleetForensics;
    lines.push(
      `| Fleet Forensics | owner=\`${ff.owner}\` (${ff.hours}h) · ${ff.greenOnLatest}/${ff.reposScanned} green · failed=${ff.failedRuns.length} · cancelled=${ff.cancelledRuns.length} · slow=${ff.slowJobs.length} |`,
    );
  }

  if (receipt.verify) {
    const verifyRows: SummaryViolationRow[] = [];
    for (const v of receipt.verify.guardViolations) {
      verifyRows.push({
        rule: v.guard,
        location: `${v.file}:${v.line}`,
        detail: v.snippet,
      });
    }
    for (const doc of receipt.verify.docs) {
      if (!doc.exists) {
        verifyRows.push({
          rule: 'verify.doc-missing',
          location: `${doc.path}:1`,
          detail: `Required documentation file missing: ${doc.path}`,
        });
      }
    }
    for (const cmd of [...receipt.verify.tests, ...receipt.verify.nativeGates]) {
      if (!cmd.ok) {
        const excerpt = (cmd.stderr || cmd.stdout || `exit code ${cmd.exitCode}`).trim();
        verifyRows.push({
          rule: `verify.${cmd.kind}`,
          location: `${cmd.command}:0`,
          detail: `exit=${cmd.exitCode}: ${excerpt}`,
        });
      }
    }
    appendViolationTable(lines, 'Guard Violations', verifyRows);
  }

  if (receipt.boundaryAudit && receipt.boundaryAudit.violations.length > 0) {
    appendViolationTable(
      lines,
      'Boundary Violations',
      receipt.boundaryAudit.violations.map((v) => ({
        rule: v.rule,
        location: `${v.file}:${v.line}`,
        detail: v.snippet ? `${v.message} (\`${v.snippet}\`)` : v.message,
      })),
    );
  }

  if (receipt.wfHarden && receipt.wfHarden.remainingFindings > 0) {
    const wfRows: SummaryViolationRow[] = [];
    for (const file of receipt.wfHarden.files) {
      for (const f of file.remainingFindings) {
        wfRows.push({
          rule: f.ruleId ?? f.rule,
          location: `${f.file}:${f.line}`,
          detail: f.message || f.snippet,
        });
      }
    }
    appendViolationTable(lines, 'Workflow Hardening Violations', wfRows);
  }

  if (receipt.wfHardenFleet && receipt.wfHardenFleet.remainingFindings > 0) {
    const fleetRows: SummaryViolationRow[] = [];
    for (const repoEntry of receipt.wfHardenFleet.repos) {
      for (const file of repoEntry.result.files) {
        for (const f of file.remainingFindings) {
          fleetRows.push({
            rule: f.ruleId ?? f.rule,
            location: `${repoEntry.repo}/${f.file}:${f.line}`,
            detail: f.message || f.snippet,
          });
        }
      }
    }
    appendViolationTable(lines, 'Fleet Workflow Hardening Violations', fleetRows);
  }

  if (receipt.auditStack && receipt.auditStack.violations.length > 0) {
    appendViolationTable(
      lines,
      'Audit Stack Violations',
      receipt.auditStack.violations.map((v) => ({
        rule: v.ruleId,
        location: `${v.file}:${v.line}`,
        detail: v.snippet && v.snippet !== v.message ? `${v.message} (\`${v.snippet}\`)` : v.message,
      })),
    );
  }

  if (receipt.fleetForensics && receipt.fleetForensics.failedRuns.length > 0) {
    appendViolationTable(
      lines,
      'Fleet Forensics Failed Runs',
      receipt.fleetForensics.failedRuns.map((run) => ({
        rule: `fleet.${run.conclusion}`,
        location: `${run.repo}:${run.runId}`,
        detail: `${run.workflowName} (${run.headBranch}, ${run.durationSec}s)${run.failedSteps.length > 0 ? ` — ${run.failedSteps.join('; ')}` : ''}`,
      })),
    );
  }

  if (receipt.errors && receipt.errors.length > 0) {
    lines.push('', '### Errors', '');
    for (const err of receipt.errors) {
      lines.push(`- ${err}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

export interface EmitTelemetryOptions {
  cwd?: string;
  receiptPath?: string;
  emitSummary?: boolean;
  summaryPath?: string;
}

export interface EmitTelemetryResult {
  receiptPath?: string;
  summaryPath?: string;
  summaryAppended: boolean;
}

export function emitTelemetry(
  receipt: HoloCiReceipt,
  options: EmitTelemetryOptions = {},
): EmitTelemetryResult {
  const cwd = options.cwd ?? process.cwd();
  let writtenReceiptPath: string | undefined;

  if (options.receiptPath) {
    const absReceipt = resolve(cwd, options.receiptPath);
    mkdirSync(dirname(absReceipt), { recursive: true });
    if (absReceipt.endsWith('.ndjson')) {
      appendFileSync(absReceipt, `${JSON.stringify(receipt)}\n`, 'utf8');
    } else {
      writeFileSync(absReceipt, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
    }
    writtenReceiptPath = absReceipt;
  }

  let summaryAppended = false;
  let targetSummaryPath: string | undefined;
  if (options.emitSummary) {
    const envSummary = options.summaryPath ?? process.env.GITHUB_STEP_SUMMARY;
    if (envSummary && envSummary.trim().length > 0) {
      targetSummaryPath = resolve(cwd, envSummary);
      mkdirSync(dirname(targetSummaryPath), { recursive: true });
      const md = formatStepSummaryMarkdown(receipt);
      appendFileSync(targetSummaryPath, `${md}\n`, 'utf8');
      summaryAppended = true;
    }
  }

  return {
    ...(writtenReceiptPath ? { receiptPath: writtenReceiptPath } : {}),
    ...(targetSummaryPath ? { summaryPath: targetSummaryPath } : {}),
    summaryAppended,
  };
}
