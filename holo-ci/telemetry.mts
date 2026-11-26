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
    ...(input.errors && input.errors.length > 0 ? { errors: input.errors } : {}),
  };
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

  if (receipt.verify && receipt.verify.guardViolations.length > 0) {
    lines.push('', '### Guard Violations', '');
    for (const v of receipt.verify.guardViolations) {
      lines.push(`- \`${v.guard}\` at \`${v.file}:${v.line}\`: \`${v.snippet}\``);
    }
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
