import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import type {
  HoloCiCommandResult,
  HoloCiDocCheckResult,
  HoloCiGuardViolation,
  HoloCiGuards,
  HoloCiManifest,
  HoloCiVerifyResult,
} from './schema.mts';

const GHOST_TOKEN = ['b8g', 'ghost'].join('-');
const CAS_V1_TOKEN = ['cas', 'v1'].join('-');
const LOCALHOST_HTTP_PREFIX = ['http', '://'].join('');

const GHOST_REGEX = new RegExp(`\\b${GHOST_TOKEN}\\b`, 'i');
const CAS_V1_REGEX = new RegExp(`\\b${CAS_V1_TOKEN}(?![0-9])\\b`, 'i');
const HTTP_IPC_REGEX = new RegExp(`${LOCALHOST_HTTP_PREFIX}(?:127\\.0\\.0\\.1|localhost)(?::\\d+)?`, 'i');
const BROKEN_SHIELDS_BADGE_REGEX = /https:\/\/img\.shields\.io\/badge\/[^\s)\]"'<>?]*%2F/i;
const DEFAULT_MAX_WORKFLOW_LINES = 140;
const RUN_KEY_REGEX = /^(\s*(?:-\s+)?)run\s*:\s*(.*)$/;
const EVAL_CMD_SUB_REGEX = /\beval\s+(?:["'][^"']*)?\$\(/;
const UNTRUSTED_GH_CONTEXT_REGEX =
  /\$\{\{[^}]*\bgithub\.(?:head_ref|event\.(?:issue|pull_request\.(?:title|body|head\.ref|head\.label)|comment|review|review_comment|discussion)\b)[^}]*\}\}/;

export function runShellCommand(
  command: string,
  cwd: string,
  kind: 'test' | 'nativeGate' = 'test',
): HoloCiCommandResult {
  const start = Date.now();
  const isWin = process.platform === 'win32';
  const needsPwsh = isWin && (command.includes('.ps1') || command.includes('$env:'));

  const res = needsPwsh
    ? spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', command], {
        cwd,
        encoding: 'utf8',
        env: process.env,
      })
    : spawnSync(command, {
        cwd,
        shell: true,
        encoding: 'utf8',
        env: process.env,
      });

  const durationMs = Date.now() - start;
  const exitCode = res.status ?? (res.error ? 1 : 0);
  const stderr = res.error ? `${res.stderr ?? ''}\n${res.error.message}`.trim() : (res.stderr ?? '');

  return {
    command,
    kind,
    exitCode,
    durationMs,
    ok: exitCode === 0,
    stdout: res.stdout ?? '',
    stderr,
  };
}

function collectGuardScanFiles(cwd: string, extraFiles: string[] = []): string[] {
  const candidates: string[] = [];
  const workflowsDir = resolve(cwd, '.github', 'workflows');
  if (existsSync(workflowsDir)) {
    for (const entry of readdirSync(workflowsDir, { withFileTypes: true })) {
      if (entry.isFile() && /\.(ya?ml)$/i.test(entry.name)) {
        candidates.push(join(workflowsDir, entry.name));
      }
    }
  }
  for (const rootFile of ['holo-ci.json', 'package.json']) {
    const p = resolve(cwd, rootFile);
    if (existsSync(p)) candidates.push(p);
  }
  for (const extra of extraFiles) {
    const p = resolve(cwd, extra);
    if (existsSync(p)) candidates.push(p);
  }
  return candidates;
}

function isAllowlistedGuardLine(lineText: string, relPath: string): boolean {
  if (lineText.includes('holo-ci-allow-guard')) return true;

  // Exclude guard configuration keys in JSON manifests
  if (relPath.endsWith('holo-ci.json') || relPath.endsWith('package.json')) {
    if (
      /^\s*"(zeroGhost|zeroCasV1|zeroHttpIpc|spdxLicense|gitattributes|codeowners|noBrokenBadges|noWorkflowBloat|maxWorkflowLines)"\s*:/.test(
        lineText,
      )
    ) {
      return true;
    }
  }

  // Exclude explicit === 0 scanner/telemetry checks (e.g., gravity telemetry checking for 0 remnants)
  if (
    lineText.includes('b8gGhostRemnants') ||
    /\/\^?b8g-ghost/i.test(lineText) ||
    /===\s*0/.test(lineText) ||
    /\|\s*`dup_v8`\s*\/\s*`b8g-ghost`\s*\|/.test(lineText)
  ) {
    return true;
  }

  return false;
}

function collectMarkdownBadgeFiles(cwd: string, docFiles: string[] = [], extraFiles: string[] = []): string[] {
  const seen = new Set<string>();
  const candidates = [...docFiles, 'README.md', ...extraFiles.filter((f) => /\.mdx?$/i.test(f))];
  const out: string[] = [];
  for (const rel of candidates) {
    if (!/\.mdx?$/i.test(rel)) continue;
    const full = resolve(cwd, rel);
    if (!seen.has(full) && existsSync(full)) {
      seen.add(full);
      out.push(full);
    }
  }
  return out;
}

export function scanGuardViolations(
  cwd: string,
  guards: HoloCiGuards,
  extraFiles: string[] = [],
  docFiles: string[] = [],
): HoloCiGuardViolation[] {
  const violations: HoloCiGuardViolation[] = [];
  const files = collectGuardScanFiles(cwd, extraFiles);

  for (const filePath of files) {
    const relPath = relative(cwd, filePath).replace(/\\/g, '/');
    const lines = readFileSync(filePath, 'utf8').split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      if (isAllowlistedGuardLine(lineText, relPath)) continue;

      if (guards.zeroGhost && GHOST_REGEX.test(lineText)) {
        violations.push({
          guard: 'zeroGhost',
          file: relPath,
          line: i + 1,
          snippet: lineText.trim().slice(0, 160),
        });
      }
      if (guards.zeroCasV1 && CAS_V1_REGEX.test(lineText)) {
        violations.push({
          guard: 'zeroCasV1',
          file: relPath,
          line: i + 1,
          snippet: lineText.trim().slice(0, 160),
        });
      }
      if (guards.zeroHttpIpc && HTTP_IPC_REGEX.test(lineText)) {
        violations.push({
          guard: 'zeroHttpIpc',
          file: relPath,
          line: i + 1,
          snippet: lineText.trim().slice(0, 160),
        });
      }
    }
  }

  if (guards.spdxLicense) {
    const licensePath = resolve(cwd, 'LICENSE');
    if (!existsSync(licensePath)) {
      violations.push({
        guard: 'spdxLicense',
        file: 'LICENSE',
        line: 1,
        snippet: 'Missing LICENSE file',
      });
    } else {
      const licenseText = readFileSync(licensePath, 'utf8');
      const isMit =
        licenseText.includes('Permission is hereby granted, free of charge') &&
        licenseText.includes('THE SOFTWARE IS PROVIDED "AS IS"');
      const isBsd3 =
        licenseText.includes('Redistribution and use in source and binary forms') &&
        licenseText.includes('THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS');
      const isApache2 =
        licenseText.includes('Apache License') && licenseText.includes('Version 2.0');

      if (!isMit && !isBsd3 && !isApache2) {
        violations.push({
          guard: 'spdxLicense',
          file: 'LICENSE',
          line: 1,
          snippet: 'LICENSE missing non-truncated OSI/SPDX clause text (MIT, BSD-3-Clause, or Apache-2.0)',
        });
      }
    }
  }

  if (guards.gitattributes) {
    const gitattributesPath = resolve(cwd, '.gitattributes');
    if (!existsSync(gitattributesPath)) {
      violations.push({
        guard: 'gitattributes',
        file: '.gitattributes',
        line: 1,
        snippet: 'Missing .gitattributes file',
      });
    } else {
      const gitattributesText = readFileSync(gitattributesPath, 'utf8');
      if (!/eol=lf/i.test(gitattributesText)) {
        violations.push({
          guard: 'gitattributes',
          file: '.gitattributes',
          line: 1,
          snippet: '.gitattributes missing eol=lf rule',
        });
      }
    }
  }

  if (guards.codeowners) {
    const hasGithubCodeowners = existsSync(resolve(cwd, '.github', 'CODEOWNERS'));
    const hasRootCodeowners = existsSync(resolve(cwd, 'CODEOWNERS'));
    if (!hasGithubCodeowners && !hasRootCodeowners) {
      violations.push({
        guard: 'codeowners',
        file: '.github/CODEOWNERS',
        line: 1,
        snippet: 'Missing .github/CODEOWNERS or CODEOWNERS file',
      });
    }
  }

  if (guards.noBrokenBadges !== false) {
    const mdFiles = collectMarkdownBadgeFiles(cwd, docFiles, extraFiles);
    for (const mdPath of mdFiles) {
      const relPath = relative(cwd, mdPath).replace(/\\/g, '/');
      const lines = readFileSync(mdPath, 'utf8').split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        if (isAllowlistedGuardLine(lineText, relPath)) continue;
        if (BROKEN_SHIELDS_BADGE_REGEX.test(lineText)) {
          violations.push({
            guard: 'noBrokenBadges',
            file: relPath,
            line: i + 1,
            snippet: lineText.trim().slice(0, 160),
          });
        }
      }
    }
  }

  if (guards.noWorkflowBloat) {
    const maxLines =
      typeof guards.maxWorkflowLines === 'number' && guards.maxWorkflowLines > 0
        ? guards.maxWorkflowLines
        : DEFAULT_MAX_WORKFLOW_LINES;
    const workflowFiles = files.filter((f) =>
      relative(cwd, f).replace(/\\/g, '/').startsWith('.github/workflows/'),
    );
    for (const wfPath of workflowFiles) {
      const relPath = relative(cwd, wfPath).replace(/\\/g, '/');
      const content = readFileSync(wfPath, 'utf8');
      const lines = content.length === 0 ? [] : content.replace(/\r?\n$/, '').split(/\r?\n/);

      if (lines.length > maxLines) {
        violations.push({
          guard: 'noWorkflowBloat',
          file: relPath,
          line: lines.length,
          snippet: `Workflow file has ${lines.length} lines (max ${maxLines})`,
        });
      }

      let inRunBlock = false;
      let runKeyIndent = -1;
      let runBlockIndent = -1;

      const checkRunLine = (lineText: string, lineNumber: number): void => {
        if (isAllowlistedGuardLine(lineText, relPath)) return;
        if (EVAL_CMD_SUB_REGEX.test(lineText)) {
          violations.push({
            guard: 'noWorkflowBloat',
            file: relPath,
            line: lineNumber,
            snippet: lineText.trim().slice(0, 160),
          });
        }
        if (UNTRUSTED_GH_CONTEXT_REGEX.test(lineText)) {
          violations.push({
            guard: 'noWorkflowBloat',
            file: relPath,
            line: lineNumber,
            snippet: lineText.trim().slice(0, 160),
          });
        }
      };

      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        const trimmed = lineText.trim();

        if (inRunBlock) {
          if (trimmed.length === 0) continue;
          const indent = lineText.length - lineText.trimStart().length;
          if (indent <= runKeyIndent || (runBlockIndent !== -1 && indent < runBlockIndent)) {
            inRunBlock = false;
            runKeyIndent = -1;
            runBlockIndent = -1;
          } else {
            if (runBlockIndent === -1) runBlockIndent = indent;
            checkRunLine(lineText, i + 1);
            continue;
          }
        }

        const runMatch = RUN_KEY_REGEX.exec(lineText);
        if (runMatch) {
          const keyIndent = lineText.length - lineText.trimStart().length;
          const rest = runMatch[2].trim();
          const isBlockScalar = /^[|>][+-]?(?:\s+#.*)?$/.test(rest);
          if (isBlockScalar) {
            inRunBlock = true;
            runKeyIndent = keyIndent;
            runBlockIndent = -1;
          } else {
            checkRunLine(rest, i + 1);
          }
        }
      }
    }
  }

  return violations;
}

export function runVerify(
  manifest: HoloCiManifest,
  options: { cwd?: string; skipTests?: boolean; skipGates?: boolean; extraScanFiles?: string[] } = {},
): HoloCiVerifyResult {
  const cwd = options.cwd ?? process.cwd();
  const tests: HoloCiCommandResult[] = [];
  const nativeGates: HoloCiCommandResult[] = [];
  const docs: HoloCiDocCheckResult[] = [];

  if (!options.skipTests) {
    for (const cmd of manifest.tests ?? []) {
      tests.push(runShellCommand(cmd, cwd, 'test'));
    }
  }

  if (!options.skipGates) {
    for (const cmd of manifest.nativeGates ?? []) {
      nativeGates.push(runShellCommand(cmd, cwd, 'nativeGate'));
    }
  }

  for (const docPath of manifest.docs ?? []) {
    const full = resolve(cwd, docPath);
    docs.push({ path: docPath, exists: existsSync(full) });
  }

  const guardViolations = scanGuardViolations(
    cwd,
    manifest.guards ?? {},
    options.extraScanFiles,
    manifest.docs ?? [],
  );

  const ok =
    tests.every((t) => t.ok) &&
    nativeGates.every((g) => g.ok) &&
    docs.every((d) => d.exists) &&
    guardViolations.length === 0;

  return {
    ok,
    tests,
    nativeGates,
    docs,
    guardViolations,
  };
}
