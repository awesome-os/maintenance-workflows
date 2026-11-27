import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { scanHttpIpcSource, type HttpIpcScanMatch } from './boundary.mts';
import type {
  HoloCiCommandResult,
  HoloCiDocCheckResult,
  HoloCiGuardViolation,
  HoloCiGuards,
  HoloCiManifest,
  HoloCiVerifyResult,
} from './schema.mts';
import { auditAndHardenWorkflowYaml, auditWorkflowBloatYaml } from './wf-harden.mts';

const GHOST_TOKEN = ['b8g', 'ghost'].join('-');
const CAS_V1_TOKEN = ['cas', 'v1'].join('-');

const GHOST_REGEX = new RegExp(`\\b${GHOST_TOKEN}\\b`, 'i');
const CAS_V1_REGEX = new RegExp(`\\b${CAS_V1_TOKEN}(?![0-9])\\b`, 'i');
const BROKEN_SHIELDS_BADGE_REGEX = /https:\/\/img\.shields\.io\/badge\/[^\s)\]"'<>?]*%2F/i;

export interface CheckRepoGovernanceOptions {
  extraFiles?: string[];
  docFiles?: string[];
}

export interface RepoGovernanceChecks {
  spdxLicense?: boolean;
  gitattributes?: boolean;
  codeowners?: boolean;
  noBrokenBadges?: boolean;
  noWorkflowBloat?: boolean;
  requireWorkflowHardening?: boolean;
}

export interface RepoGovernanceResult {
  ok: boolean;
  violations: HoloCiGuardViolation[];
  checks: RepoGovernanceChecks;
}

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
      /^\s*"(zeroGhost|zeroCasV1|zeroHttpIpc|spdxLicense|gitattributes|codeowners|noBrokenBadges|noWorkflowBloat|maxWorkflowLines|requireWorkflowHardening)"\s*:/.test(
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

function collectWorkflowFiles(cwd: string, extraFiles: string[] = []): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const workflowsDir = resolve(cwd, '.github', 'workflows');
  if (existsSync(workflowsDir)) {
    for (const entry of readdirSync(workflowsDir, { withFileTypes: true })) {
      if (entry.isFile() && /\.(ya?ml)$/i.test(entry.name)) {
        const full = join(workflowsDir, entry.name);
        if (!seen.has(full)) {
          seen.add(full);
          out.push(full);
        }
      }
    }
  }
  for (const extra of extraFiles) {
    const full = resolve(cwd, extra);
    const rel = relative(cwd, full).replace(/\\/g, '/');
    if (rel.startsWith('.github/workflows/') && existsSync(full) && !seen.has(full)) {
      seen.add(full);
      out.push(full);
    }
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

/**
 * Evaluates repository governance guards (`spdxLicense`, `gitattributes`, `codeowners`,
 * `noBrokenBadges`, `noWorkflowBloat`, `requireWorkflowHardening`) in one reusable entrypoint.
 * Workflow hardening and bloat auditing delegate directly to `holo-ci/wf-harden.mts`.
 */
export function checkRepoGovernance(
  cwd: string,
  guards: HoloCiGuards,
  options: CheckRepoGovernanceOptions = {},
): RepoGovernanceResult {
  const violations: HoloCiGuardViolation[] = [];
  const checks: RepoGovernanceChecks = {};
  const extraFiles = options.extraFiles ?? [];
  const docFiles = options.docFiles ?? [];

  if (guards.spdxLicense) {
    const before = violations.length;
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
    checks.spdxLicense = violations.length === before;
  }

  if (guards.gitattributes) {
    const before = violations.length;
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
    checks.gitattributes = violations.length === before;
  }

  if (guards.codeowners) {
    const before = violations.length;
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
    checks.codeowners = violations.length === before;
  }

  if (guards.noBrokenBadges !== false) {
    const before = violations.length;
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
    checks.noBrokenBadges = violations.length === before;
  }

  const workflowFiles =
    guards.noWorkflowBloat || guards.requireWorkflowHardening
      ? collectWorkflowFiles(cwd, extraFiles)
      : [];

  if (guards.noWorkflowBloat) {
    const before = violations.length;
    for (const wfPath of workflowFiles) {
      const relPath = relative(cwd, wfPath).replace(/\\/g, '/');
      const content = readFileSync(wfPath, 'utf8');
      const findings = auditWorkflowBloatYaml(content, relPath, {
        maxWorkflowLines: guards.maxWorkflowLines,
        isAllowlistedLine: (lineText) => isAllowlistedGuardLine(lineText, relPath),
      });
      for (const finding of findings) {
        violations.push({
          guard: 'noWorkflowBloat',
          file: finding.file,
          line: finding.line,
          snippet: finding.snippet,
        });
      }
    }
    checks.noWorkflowBloat = violations.length === before;
  }

  if (guards.requireWorkflowHardening) {
    const before = violations.length;
    for (const wfPath of workflowFiles) {
      const relPath = relative(cwd, wfPath).replace(/\\/g, '/');
      const content = readFileSync(wfPath, 'utf8');
      const audited = auditAndHardenWorkflowYaml(content, relPath, { fix: false });
      for (const finding of audited.findings) {
        const snippet =
          finding.rule === 'missing-artifact-retention'
            ? 'actions/upload-artifact step missing retention-days'
            : finding.snippet;
        violations.push({
          guard: 'requireWorkflowHardening',
          file: finding.file,
          line: finding.line,
          snippet,
        });
      }
    }
    checks.requireWorkflowHardening = violations.length === before;
  }

  return {
    ok: violations.length === 0,
    violations,
    checks,
  };
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
    const content = readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const httpIpcByLine = new Map<number, HttpIpcScanMatch>();
    if (guards.zeroHttpIpc) {
      for (const match of scanHttpIpcSource(content, relPath)) {
        if (!httpIpcByLine.has(match.line)) {
          httpIpcByLine.set(match.line, match);
        }
      }
    }

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
      const httpHit = httpIpcByLine.get(i + 1);
      if (httpHit) {
        violations.push({
          guard: 'zeroHttpIpc',
          file: relPath,
          line: httpHit.line,
          snippet: httpHit.snippet,
        });
      }
    }
  }

  const governance = checkRepoGovernance(cwd, guards, { extraFiles, docFiles });
  violations.push(...governance.violations);

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
