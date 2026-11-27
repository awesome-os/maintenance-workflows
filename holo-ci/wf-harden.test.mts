import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { scanGuardViolations } from './verify.mts';
import {
  auditAndHardenWorkflowYaml,
  hardenWorkflowsInDir,
  parseWfHardenCliArgs,
  runFleetWorkflowHardening,
  runWfHardenCli,
  runWorkflowHardening,
  WF_HARDEN_FLEET_SCHEMA,
  WF_HARDEN_SCHEMA,
} from './wf-harden.mts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

function withTempRepo(fn: (repoDir: string, workflowsDir: string) => void): void {
  const repoDir = mkdtempSync(join(tmpdir(), 'holo-wf-harden-'));
  const workflowsDir = join(repoDir, '.github', 'workflows');
  mkdirSync(workflowsDir, { recursive: true });
  try {
    fn(repoDir, workflowsDir);
  } finally {
    rmSync(repoDir, { recursive: true, force: true });
  }
}

describe('holo-ci/wf-harden generic workflow hardener', () => {
  it('upgrades deprecated Zig action and all legacy core & Pages actions while preserving comments', () => {
    const input = [
      '# Top-level banner comment',
      'name: Build & Pages',
      '',
      'on:',
      '  push:',
      '    branches: [main]',
      '',
      'concurrency:',
      '  group: ${{ github.workflow }}-${{ github.ref }}',
      '  cancel-in-progress: true',
      '',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 25',
      '    steps:',
      '      - uses: actions/checkout@v4 # keep comment',
      '      - uses: actions/setup-node@v3',
      '      - uses: goto-bus-stop/setup-zig@v2',
      '      - uses: actions/cache@v4',
      '      - uses: actions/cache/restore@v3',
      '      - uses: actions/cache/save@v2',
      '      - uses: actions/download-artifact@v4',
      '      - uses: actions/configure-pages@v5',
      '      - uses: actions/upload-pages-artifact@v3',
      '      - uses: actions/deploy-pages@v4',
      '      - uses: actions/upload-artifact@v4',
      '        with:',
      '          name: logs',
      '          path: logs/',
      '          retention-days: 7',
      '',
    ].join('\n');

    const checkRes = auditAndHardenWorkflowYaml(input, '.github/workflows/build.yml', { fix: false });
    assert.equal(checkRes.ok, false);
    assert.equal(checkRes.changed, false);
    assert.equal(checkRes.findings.length, 11);

    const fixRes = auditAndHardenWorkflowYaml(input, '.github/workflows/build.yml', { fix: true });
    assert.equal(fixRes.ok, true);
    assert.equal(fixRes.changed, true);
    assert.equal(fixRes.remainingFindings.length, 0);
    assert.equal(fixRes.fixesApplied.length, 11);

    assert.ok(fixRes.content.includes('# Top-level banner comment'));
    assert.ok(fixRes.content.includes('uses: actions/checkout@v7 # keep comment'));
    assert.ok(fixRes.content.includes('uses: actions/setup-node@v7'));
    assert.ok(fixRes.content.includes('uses: mlugg/setup-zig@v2'));
    assert.ok(fixRes.content.includes('uses: actions/cache@v6'));
    assert.ok(fixRes.content.includes('uses: actions/cache/restore@v6'));
    assert.ok(fixRes.content.includes('uses: actions/cache/save@v6'));
    assert.ok(fixRes.content.includes('uses: actions/download-artifact@v8'));
    assert.ok(fixRes.content.includes('uses: actions/configure-pages@v6'));
    assert.ok(fixRes.content.includes('uses: actions/upload-pages-artifact@v5'));
    assert.ok(fixRes.content.includes('uses: actions/deploy-pages@v5'));
    assert.ok(fixRes.content.includes('uses: actions/upload-artifact@v7'));

    // Second pass must be strictly idempotent (0 changes, 0 findings)
    const secondPass = auditAndHardenWorkflowYaml(fixRes.content, '.github/workflows/build.yml', {
      fix: true,
    });
    assert.equal(secondPass.ok, true);
    assert.equal(secondPass.changed, false);
    assert.equal(secondPass.findings.length, 0);
    assert.equal(secondPass.fixesApplied.length, 0);
    assert.equal(secondPass.content, fixRes.content);
  });

  it('inserts concurrency (true for CI, false for sensitive), fixes cancel race, adds timeout & retention', () => {
    const ciInput = [
      'name: Unit Tests',
      '',
      'on:',
      '  push:',
      '    branches: [main]',
      '',
      '# Job block comment',
      'jobs:',
      '  test:',
      '    runs-on:',
      '      - ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - name: Upload dist',
      '        uses: actions/upload-artifact@v4',
      '        with:',
      '          name: dist',
      '          path: |',
      '            dist/a.txt',
      '            dist/b.txt',
      '      - name: Upload inline flow',
      '        uses: actions/upload-artifact@v7',
      "        with: { name: 'inline', path: 'out/*' }",
      '      - uses: actions/upload-artifact@v7',
      '  reusable-caller:',
      '    uses: awesome-os/maintenance-workflows/.github/workflows/reusable-holo-ci.yml@v1',
      '',
    ].join('\n');

    const ciFixed = auditAndHardenWorkflowYaml(ciInput, '.github/workflows/ci.yml', {
      fix: true,
      defaultTimeoutMinutes: 20,
      defaultRetentionDays: 7,
    });
    assert.equal(ciFixed.ok, true);
    assert.equal(ciFixed.remainingFindings.length, 0);
    assert.ok(ciFixed.content.includes('concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n\n# Job block comment'));
    assert.ok(ciFixed.content.includes('    runs-on:\n      - ubuntu-latest\n    timeout-minutes: 20\n'));
    assert.ok(ciFixed.content.includes('            dist/b.txt\n          retention-days: 7\n'));
    assert.ok(ciFixed.content.includes("with: { name: 'inline', path: 'out/*', retention-days: 7 }"));
    assert.ok(ciFixed.content.includes('      - uses: actions/upload-artifact@v7\n        with:\n          retention-days: 7\n'));
    // Must NOT add timeout-minutes to reusable-caller job without runs-on
    const callerIdx = ciFixed.content.indexOf('  reusable-caller:');
    assert.ok(!ciFixed.content.slice(callerIdx).includes('timeout-minutes'));

    const ciSecond = auditAndHardenWorkflowYaml(ciFixed.content, '.github/workflows/ci.yml', { fix: true });
    assert.equal(ciSecond.changed, false);
    assert.equal(ciSecond.findings.length, 0);

    // Sensitive release workflow with missing concurrency AND a job-level cancel race
    const releaseInput = [
      'name: Publish Release',
      '',
      'on:',
      '  push:',
      '    tags: ["v*"]',
      '',
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    concurrency:',
      '      group: release-${{ github.ref }}',
      '      cancel-in-progress: true # race hazard',
      '    steps:',
      '      - uses: actions/checkout@v7',
      '',
    ].join('\n');

    const relFixed = auditAndHardenWorkflowYaml(releaseInput, '.github/workflows/release.yml', { fix: true });
    assert.equal(relFixed.ok, true);
    assert.equal(relFixed.remainingFindings.length, 0);
    assert.ok(relFixed.findings.some((f) => f.rule === 'missing-concurrency'));
    assert.ok(relFixed.findings.some((f) => f.rule === 'concurrency-cancel-race'));
    assert.ok(relFixed.findings.some((f) => f.rule === 'missing-timeout-minutes'));
    assert.ok(relFixed.content.includes('  cancel-in-progress: false\n'));
    assert.ok(relFixed.content.includes('      cancel-in-progress: false # race hazard'));

    const relSecond = auditAndHardenWorkflowYaml(relFixed.content, '.github/workflows/release.yml', { fix: true });
    assert.equal(relSecond.changed, false);
    assert.equal(relSecond.findings.length, 0);
  });

  it('does not insert top-level concurrency on workflow_call reusable workflows and preserves CRLF', () => {
    const reusable = [
      'name: Reusable Helper',
      '',
      'on:',
      '  workflow_call:',
      '    inputs:',
      '      target: { type: string, required: false, default: "all" }',
      '',
      'jobs:',
      '  run:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '',
    ].join('\r\n');

    const fixed = auditAndHardenWorkflowYaml(reusable, '.github/workflows/reusable-helper.yml', { fix: true });
    assert.equal(fixed.ok, true);
    assert.ok(!fixed.content.includes('concurrency:'));
    assert.ok(fixed.content.includes('\r\n'));
    assert.ok(fixed.content.includes('timeout-minutes: 30\r\n'));
    assert.ok(fixed.content.includes('uses: actions/checkout@v7\r\n'));
  });

  it('hardenWorkflowsInDir fixes a repo so verify.mts requireWorkflowHardening passes with 0 violations', () => {
    withTempRepo((repoDir, workflowsDir) => {
      const dirtyWorkflow = [
        'name: Deploy Portal',
        '',
        'on:',
        '  push:',
        '    branches: [main]',
        '',
        'concurrency:',
        '  group: deploy-${{ github.ref }}',
        '  cancel-in-progress: true',
        '',
        'jobs:',
        '  deploy:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v3',
        '      - uses: goto-bus-stop/setup-zig@v2',
        '      - uses: actions/upload-artifact@v3',
        '        with:',
        '          name: site',
        '          path: dist/',
        '',
      ].join('\n');

      const wfPath = join(workflowsDir, 'deploy.yml');
      writeFileSync(wfPath, dirtyWorkflow, 'utf8');

      const preCheck = hardenWorkflowsInDir(repoDir, { fix: false });
      assert.equal(preCheck.schema, WF_HARDEN_SCHEMA);
      assert.equal(preCheck.ok, false);
      assert.equal(preCheck.workflowsScanned, 1);
      assert.ok(preCheck.totalFindings >= 5);
      assert.equal(preCheck.modifiedFiles.length, 0);

      const fixRun = hardenWorkflowsInDir(repoDir, { fix: true });
      assert.equal(fixRun.ok, true);
      assert.equal(fixRun.remainingFindings, 0);
      assert.deepEqual(fixRun.modifiedFiles, ['.github/workflows/deploy.yml']);

      // Verify 1:1 agreement with holo-ci/verify.mts requireWorkflowHardening guard
      const verifyViolations = scanGuardViolations(repoDir, {
        requireWorkflowHardening: true,
        noWorkflowBloat: true,
      });
      assert.deepEqual(verifyViolations, []);

      // Second --fix run must produce 0 changes and 0 findings
      const secondFix = hardenWorkflowsInDir(repoDir, { fix: true });
      assert.equal(secondFix.ok, true);
      assert.equal(secondFix.totalFindings, 0);
      assert.equal(secondFix.totalFixesApplied, 0);
      assert.equal(secondFix.modifiedFiles.length, 0);

      // Verify persisted file content
      const persisted = readFileSync(wfPath, 'utf8');
      assert.ok(persisted.includes('cancel-in-progress: false'));
      assert.ok(persisted.includes('mlugg/setup-zig@v2'));
      assert.ok(persisted.includes('actions/checkout@v7'));
      assert.ok(persisted.includes('actions/upload-artifact@v7'));
      assert.ok(persisted.includes('retention-days: 7'));
      assert.ok(persisted.includes('timeout-minutes: 30'));
    });
  });

  it('audits maintenance-workflows repository (including reusable-gravity-issue-governor.yml) cleanly', () => {
    const res = hardenWorkflowsInDir(REPO_ROOT, { fix: false });
    assert.equal(
      res.ok,
      true,
      `Expected 0 findings in maintenance-workflows, got: ${JSON.stringify(res.files.flatMap((f) => f.findings))}`,
    );
    assert.ok(
      res.files.some((f) => f.fileName === '.github/workflows/reusable-gravity-issue-governor.yml'),
      'Expected reusable-gravity-issue-governor.yml to be audited',
    );
  });

  it('supports CLI --check, --fix, --cwd, --json, and --help flags', () => {
    const parsed = parseWfHardenCliArgs(['--fix', '--cwd', REPO_ROOT, '--json', '--timeout-minutes', '15', '--retention-days', '14']);
    assert.equal(parsed.fix, true);
    assert.equal(parsed.json, true);
    assert.equal(parsed.defaultTimeoutMinutes, 15);
    assert.equal(parsed.defaultRetentionDays, 14);

    assert.throws(() => parseWfHardenCliArgs(['--unknown-flag']), /Unknown or incomplete argument/);
    assert.throws(() => parseWfHardenCliArgs(['--timeout-minutes', '0']), /Invalid --timeout-minutes/);

    withTempRepo((repoDir, workflowsDir) => {
      writeFileSync(
        join(workflowsDir, 'sample.yml'),
        'name: Sample\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n',
        'utf8',
      );

      const originalWrite = process.stdout.write.bind(process.stdout);
      const chunks: string[] = [];
      process.stdout.write = ((chunk: string | Uint8Array): boolean => {
        chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
        return true;
      }) as typeof process.stdout.write;

      try {
        const helpRun = runWfHardenCli(['--help']);
        assert.equal(helpRun.exitCode, 0);

        chunks.length = 0;
        const checkRun = runWfHardenCli(['--check', '--cwd', repoDir, '--json']);
        assert.equal(checkRun.exitCode, 1);
        const checkJson = JSON.parse(chunks.join('')) as { ok: boolean; totalFindings: number };
        assert.equal(checkJson.ok, false);
        assert.ok(checkJson.totalFindings >= 3);

        chunks.length = 0;
        const fixRun = runWfHardenCli(['--fix', '--cwd', repoDir, '--json']);
        assert.equal(fixRun.exitCode, 0);
        const fixJson = JSON.parse(chunks.join('')) as { ok: boolean; remainingFindings: number };
        assert.equal(fixJson.ok, true);
        assert.equal(fixJson.remainingFindings, 0);

        chunks.length = 0;
        const recheckRun = runWfHardenCli(['--check', '--cwd', repoDir]);
        assert.equal(recheckRun.exitCode, 0);
        assert.ok(chunks.join('').includes('PASS'));
      } finally {
        process.stdout.write = originalWrite;
      }
    });
  });

  it('detects duplicate-pages-workflow when >1 active workflow invokes actions/deploy-pages', () => {
    withTempRepo((repoDir, workflowsDir) => {
      const canonicalPages = [
        'name: Deploy Pages',
        'on:',
        '  push:',
        '    branches: [main]',
        'concurrency:',
        '  group: pages',
        '  cancel-in-progress: false',
        'jobs:',
        '  deploy:',
        '    runs-on: ubuntu-latest',
        '    timeout-minutes: 15',
        '    steps:',
        '      - uses: actions/checkout@v7',
        '      - uses: actions/configure-pages@v6',
        '      - uses: actions/upload-pages-artifact@v5',
        '      - uses: actions/deploy-pages@v5',
        '',
      ].join('\n');

      const redundantPages = [
        'name: Legacy Pages',
        'on:',
        '  push:',
        '    branches: [main]',
        'concurrency:',
        '  group: legacy-pages',
        '  cancel-in-progress: false',
        'jobs:',
        '  deploy:',
        '    runs-on: ubuntu-latest',
        '    timeout-minutes: 15',
        '    steps:',
        '      - uses: actions/checkout@v7',
        '      - uses: actions/deploy-pages@v5',
        '',
      ].join('\n');

      writeFileSync(join(workflowsDir, 'deploy-pages.yml'), canonicalPages, 'utf8');
      const singleRes = runWorkflowHardening(repoDir, { fix: false });
      assert.equal(singleRes.ok, true);
      assert.equal(singleRes.totalFindings, 0);

      writeFileSync(join(workflowsDir, 'pages.yml'), redundantPages, 'utf8');
      const dupRes = runWorkflowHardening(repoDir, { fix: false });
      assert.equal(dupRes.ok, false);
      assert.equal(dupRes.totalFindings, 1);
      assert.equal(dupRes.remainingFindings, 1);

      const canonicalEntry = dupRes.files.find((f) => f.fileName === '.github/workflows/deploy-pages.yml');
      const redundantEntry = dupRes.files.find((f) => f.fileName === '.github/workflows/pages.yml');
      assert.equal(canonicalEntry?.ok, true);
      assert.equal(redundantEntry?.ok, false);
      assert.equal(redundantEntry?.findings[0]?.rule, 'duplicate-pages-workflow');
      assert.equal(redundantEntry?.findings[0]?.ruleId, 'duplicate-pages-workflow');
      assert.match(redundantEntry?.findings[0]?.message ?? '', /pages\.yml/);
      assert.match(redundantEntry?.findings[0]?.remediation ?? '', /deploy-pages\.yml/);
    });
  });

  it('aggregates and autofixes multiple mirrored repos via runFleetWorkflowHardening and --fleet CLI', () => {
    const mirrorRoot = mkdtempSync(join(tmpdir(), 'holo-wf-fleet-'));
    try {
      const repoA = join(mirrorRoot, 'repo-alpha', '.github', 'workflows');
      const repoB = join(mirrorRoot, 'repo-beta', '.github', 'workflows');
      mkdirSync(repoA, { recursive: true });
      mkdirSync(repoB, { recursive: true });

      writeFileSync(
        join(repoA, 'ci.yml'),
        [
          'name: Alpha CI',
          'on: push',
          'concurrency:',
          '  group: alpha-${{ github.ref }}',
          '  cancel-in-progress: true',
          'jobs:',
          '  test:',
          '    runs-on: ubuntu-latest',
          '    timeout-minutes: 15',
          '    steps:',
          '      - uses: actions/checkout@v7',
          '',
        ].join('\n'),
        'utf8',
      );

      writeFileSync(
        join(repoB, 'ci.yml'),
        [
          'name: Beta CI',
          'on: push',
          'jobs:',
          '  test:',
          '    runs-on: ubuntu-latest',
          '    steps:',
          '      - uses: actions/checkout@v4',
          '',
        ].join('\n'),
        'utf8',
      );

      const checkFleet = runFleetWorkflowHardening({ mirrorRoot, check: true });
      assert.equal(checkFleet.schema, WF_HARDEN_FLEET_SCHEMA);
      assert.equal(checkFleet.ok, false);
      assert.equal(checkFleet.reposScanned, 2);
      assert.equal(checkFleet.passedRepos, 1);
      assert.equal(checkFleet.failedRepos, 1);
      assert.equal(checkFleet.workflowsScanned, 2);
      assert.ok(checkFleet.totalFindings >= 3);

      const parsed = parseWfHardenCliArgs(['--fix', '--fleet', mirrorRoot, '--json']);
      assert.equal(parsed.fix, true);
      assert.equal(parsed.fleetRoot, resolve(mirrorRoot));

      const originalWrite = process.stdout.write.bind(process.stdout);
      const chunks: string[] = [];
      process.stdout.write = ((chunk: string | Uint8Array): boolean => {
        chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
        return true;
      }) as typeof process.stdout.write;

      try {
        const fixCli = runWfHardenCli(['--fix', '--fleet', mirrorRoot, '--json']);
        assert.equal(fixCli.exitCode, 0);
        assert.equal(fixCli.fleetResult?.ok, true);
        assert.equal(fixCli.fleetResult?.passedRepos, 2);
        assert.equal(fixCli.fleetResult?.failedRepos, 0);
        assert.deepEqual(fixCli.fleetResult?.modifiedFiles, ['repo-beta/.github/workflows/ci.yml']);
      } finally {
        process.stdout.write = originalWrite;
      }
    } finally {
      rmSync(mirrorRoot, { recursive: true, force: true });
    }
  });
});
