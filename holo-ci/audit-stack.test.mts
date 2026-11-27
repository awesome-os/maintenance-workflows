import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  BUILTIN_HOLO_CI_AUDIT_IDS,
  HOLO_AUDIT_PUSH_SCHEMA,
  HOLO_AUDIT_STACK_RESULT_SCHEMA,
  createAuditStackRegistry,
  registerBuiltinHoloCiAudits,
  runBuiltinAuditStack,
  type HoloAuditPushPayload,
  type ProgrammaticAuditSpec,
} from './audit-stack.mts';
import {
  B8G_ABI_MAGIC_V3,
  HOLO_BOUNDARY_SCHEMA,
  HOLO_CI_RECEIPT_SCHEMA,
  HOLO_CI_SCHEMA,
  HOLO_RULE_VIOLATION_SCHEMA,
  createRuleViolation,
  type HoloCiReceipt,
  type HoloRuleViolation,
} from './schema.mts';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const CLI_PATH = join(HERE, 'cli.mts');

function makeTempDir(prefix = 'holo-audit-stack-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function seedCleanRepo(dir: string): void {
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(
    join(dir, 'LICENSE'),
    [
      'MIT License',
      '',
      'Permission is hereby granted, free of charge, to any person obtaining a copy',
      'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.',
    ].join('\n'),
    'utf8',
  );
  writeFileSync(join(dir, '.gitattributes'), '* text=auto eol=lf\n', 'utf8');
  writeFileSync(join(dir, '.github', 'CODEOWNERS'), '* @lemanschik\n', 'utf8');
  writeFileSync(join(dir, 'README.md'), '# Clean Repo\n', 'utf8');
  writeFileSync(
    join(dir, 'holo-ci.json'),
    JSON.stringify(
      {
        schema: HOLO_CI_SCHEMA,
        name: 'clean-audit-repo',
        kind: 'app',
        docs: ['README.md'],
        guards: {
          zeroGhost: true,
          zeroCasV1: true,
          zeroHttpIpc: true,
          spdxLicense: true,
          gitattributes: true,
          codeowners: true,
          noWorkflowBloat: true,
          requireWorkflowHardening: true,
        },
      },
      null,
      2,
    ),
    'utf8',
  );
  writeFileSync(
    join(dir, 'boundary.json'),
    JSON.stringify(
      {
        schema: HOLO_BOUNDARY_SCHEMA,
        plane: 2,
        forbiddenImports: ['forbidden-pkg'],
        maxParentTraversals: 2,
        scanSourceHttpIpc: true,
      },
      null,
      2,
    ),
    'utf8',
  );
  writeFileSync(join(dir, 'src', 'index.mts'), 'export const ok = true;\n', 'utf8');
  writeFileSync(
    join(dir, '.github', 'workflows', 'ci.yml'),
    [
      'name: Clean CI',
      'on: [push]',
      'concurrency:',
      '  group: ${{ github.workflow }}-${{ github.ref }}',
      '  cancel-in-progress: true',
      'jobs:',
      '  verify:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 15',
      '    steps:',
      '      - uses: actions/checkout@v7',
      '      - uses: actions/setup-node@v7',
      '',
    ].join('\n'),
    'utf8',
  );
}

describe('holo-ci programmatic audit-stack registry', () => {
  it('supports register(), list(), get(), remove(), custom audits, and 13 built-in holo-ci audits', async () => {
    const reg = createAuditStackRegistry();
    assert.equal(reg.list().length, 0);

    registerBuiltinHoloCiAudits(reg);
    assert.deepEqual(
      reg.list().map((a) => a.id),
      [...BUILTIN_HOLO_CI_AUDIT_IDS],
    );
    assert.equal(reg.list().length, 13);

    const customAudit: ProgrammaticAuditSpec = {
      id: 'custom/zero-todo',
      title: 'Custom Zero TODO Marker Audit',
      category: 'docs',
      severity: 'warning',
      rollbackHint: 'Revert doc commit',
      remediationCmd: 'Resolve TODO markers',
      run: (ctx) => {
        assert.equal(ctx.repo, 'awesome-os/clean-audit-repo');
        assert.equal(ctx.signal.aborted, false);
        return [];
      },
    };
    reg.register(customAudit);
    assert.equal(reg.list().length, 14);
    assert.equal(reg.get('custom/zero-todo')?.title, 'Custom Zero TODO Marker Audit');

    const dir = makeTempDir();
    try {
      seedCleanRepo(dir);
      const res = await reg.run({
        cwd: dir,
        repo: 'awesome-os/clean-audit-repo',
        mode: 'exhaust',
      });
      assert.equal(res.schema, HOLO_AUDIT_STACK_RESULT_SCHEMA);
      assert.equal(res.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(res.ok, true, JSON.stringify(res.violations));
      assert.equal(res.ratified, true);
      assert.equal(res.failedFast, false);
      assert.equal(res.totalAudits, 14);
      assert.equal(res.passedAudits, 14);
      assert.equal(res.failedAudits, 0);
      assert.equal(res.abortedAudits, 0);
      assert.equal(res.violationCount, 0);
      assert.equal(res.pushPayload.schema, HOLO_AUDIT_PUSH_SCHEMA);
      assert.equal(res.pushPayload.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(res.pushPayload.ratified, true);

      assert.equal(reg.remove('custom/zero-todo'), true);
      assert.equal(reg.remove('custom/non-existent'), false);
      assert.equal(reg.list().length, 13);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('aborts slow sibling audits immediately in fail-fast mode when first audit emits violations', async () => {
    const reg = createAuditStackRegistry();
    let slowSignalAborted = false;
    let slowTimerCleared = false;

    reg.register({
      id: 'custom/slow-sibling',
      title: 'Slow Sibling Audit',
      category: 'geometry',
      severity: 'error',
      rollbackHint: 'Rollback slow sibling',
      remediationCmd: 'noop',
      run: (ctx) =>
        new Promise<HoloRuleViolation[]>((resolvePromise) => {
          const timer = setTimeout(() => {
            resolvePromise([]);
          }, 10_000);
          ctx.signal.addEventListener(
            'abort',
            () => {
              slowSignalAborted = true;
              slowTimerCleared = true;
              clearTimeout(timer);
              resolvePromise([]);
            },
            { once: true },
          );
        }),
    });

    reg.register({
      id: 'custom/fast-breach',
      title: 'Fast Failing Audit',
      category: 'security',
      severity: 'error',
      rollbackHint: 'Hold promotion and trigger RollingReleaseManifest O(1) rollback',
      remediationCmd: 'fix-fast-breach',
      run: async (ctx) => {
        await new Promise((r) => setTimeout(r, 15));
        return [
          createRuleViolation({
            ruleId: 'custom.fast.breach',
            severity: 'error',
            category: 'security',
            repo: ctx.repo,
            file: 'src/critical.mts',
            line: 7,
            snippet: 'forbidden_op()',
            message: 'Immediate fundamental invariant breach',
            autofixable: false,
          }),
        ];
      },
    });

    const start = Date.now();
    const res = await reg.run({
      cwd: REPO_ROOT,
      repo: 'awesome-os/fail-fast-demo',
      mode: 'fail-fast',
    });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < 2_500, `fail-fast took ${elapsed} ms; expected immediate abort of 10s sibling`);
    assert.equal(slowSignalAborted, true);
    assert.equal(slowTimerCleared, true);
    assert.equal(res.ok, false);
    assert.equal(res.ratified, false);
    assert.equal(res.failedFast, true);
    assert.equal(res.mode, 'fail-fast');
    assert.equal(res.totalAudits, 2);
    assert.equal(res.failedAudits, 1);
    assert.equal(res.abortedAudits, 1);
    assert.equal(res.passedAudits, 0);
    assert.equal(res.violationCount, 1);
    assert.equal(res.violations[0]?.ruleId, 'custom.fast.breach');

    const slowEntry = res.entries.find((e) => e.id === 'custom/slow-sibling');
    assert.equal(slowEntry?.status, 'aborted');
    assert.equal(slowEntry?.aborted, true);
    assert.equal(slowEntry?.ok, false);

    const fastEntry = res.entries.find((e) => e.id === 'custom/fast-breach');
    assert.equal(fastEntry?.status, 'failed');
    assert.equal(fastEntry?.aborted, false);
    assert.equal(fastEntry?.violationCount, 1);
  });

  it('collects ALL violations in exhaust mode and writes holo-rule-violation.v1 JSONL + b8g.audit-push.v1 JSON', async () => {
    const dir = makeTempDir();
    try {
      const reg = createAuditStackRegistry();
      reg.register({
        id: 'custom/fail-a',
        title: 'Failing Audit A',
        category: 'abi',
        severity: 'error',
        rollbackHint: 'Rollback ABI change',
        remediationCmd: 'regen-abi',
        run: async (ctx) => {
          await new Promise((r) => setTimeout(r, 10));
          return [
            createRuleViolation({
              ruleId: 'custom.abi.drift',
              severity: 'error',
              category: 'abi',
              repo: ctx.repo,
              file: 'sections/a/abi-golden.json',
              line: 3,
              snippet: 'sizeof=64',
              message: 'ABI struct size mismatch',
              autofixable: false,
            }),
            createRuleViolation({
              ruleId: 'custom.abi.magic',
              severity: 'error',
              category: 'abi',
              repo: ctx.repo,
              file: 'sections/a/abi.h',
              line: 1,
              snippet: '0x00000000',
              message: 'Missing B8G_ABI_MAGIC_V3 constant',
              autofixable: false,
            }),
          ];
        },
      });

      reg.register({
        id: 'custom/fail-b',
        title: 'Failing Audit B',
        category: 'ipc',
        severity: 'error',
        rollbackHint: 'Rollback IPC change',
        remediationCmd: 'migrate-pipe',
        run: async (ctx) => {
          await new Promise((r) => setTimeout(r, 25));
          return [
            createRuleViolation({
              ruleId: 'B8G016',
              severity: 'error',
              category: 'ipc',
              repo: ctx.repo,
              file: 'src/daemon.mts',
              line: 42,
              snippet: 'loopback listener',
              message: 'Illegal loopback HTTP IPC listener',
              autofixable: false,
            }),
          ];
        },
      });

      reg.register({
        id: 'custom/pass-c',
        title: 'Passing Audit C',
        category: 'docs',
        severity: 'info',
        rollbackHint: 'n/a',
        remediationCmd: 'n/a',
        run: () => [],
      });

      const telemetryOutPath = join(dir, 'out', 'violations.jsonl');
      const pushOutPath = join(dir, 'out', 'audit-push.json');

      const res = await reg.run({
        cwd: dir,
        repo: 'awesome-os/exhaust-demo',
        mode: 'exhaust',
        telemetryOutPath,
        pushOutPath,
      });

      assert.equal(res.ok, false);
      assert.equal(res.ratified, false);
      assert.equal(res.failedFast, false);
      assert.equal(res.totalAudits, 3);
      assert.equal(res.passedAudits, 1);
      assert.equal(res.failedAudits, 2);
      assert.equal(res.abortedAudits, 0);
      assert.equal(res.violationCount, 3);
      assert.equal(existsSync(telemetryOutPath), true);
      assert.equal(existsSync(pushOutPath), true);

      const jsonlLines = readFileSync(telemetryOutPath, 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as HoloRuleViolation);
      assert.equal(jsonlLines.length, 3);
      for (const v of jsonlLines) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.repo, 'awesome-os/exhaust-demo');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }
      assert.deepEqual(
        jsonlLines.map((v) => v.ruleId),
        ['custom.abi.drift', 'custom.abi.magic', 'B8G016'],
      );

      // Verify JSONL append semantics on second run
      await reg.run({
        cwd: dir,
        repo: 'awesome-os/exhaust-demo',
        mode: 'exhaust',
        telemetryOutPath,
        pushOutPath,
      });
      const appendedLines = readFileSync(telemetryOutPath, 'utf8').trim().split('\n');
      assert.equal(appendedLines.length, 6);

      const pushDoc = JSON.parse(readFileSync(pushOutPath, 'utf8')) as HoloAuditPushPayload;
      assert.equal(pushDoc.schema, HOLO_AUDIT_PUSH_SCHEMA);
      assert.equal(pushDoc.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(pushDoc.repo, 'awesome-os/exhaust-demo');
      assert.equal(pushDoc.mode, 'exhaust');
      assert.equal(pushDoc.ok, false);
      assert.equal(pushDoc.ratified, false);
      assert.equal(pushDoc.failedFast, false);
      assert.equal(pushDoc.violationCount, 3);
      assert.equal(pushDoc.audits.length, 3);
      assert.equal(pushDoc.violations.length, 3);
      assert.equal(pushDoc.fingerprints.length, 3);
      assert.deepEqual(pushDoc.violationCountsByRule, {
        'custom.abi.drift': 1,
        'custom.abi.magic': 1,
        B8G016: 1,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches custom non-awesome-os.github.io CNAME files and allows canonical awesome-os.github.io', async () => {
    const dir = makeTempDir('holo-audit-cname-');
    try {
      seedCleanRepo(dir);
      writeFileSync(join(dir, 'CNAME'), 'custom.awesome-os.com\n', 'utf8');

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/cname-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/non-github-io-cname'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 1);
      assert.equal(failRes.violations[0]?.schema, HOLO_RULE_VIOLATION_SCHEMA);
      assert.equal(failRes.violations[0]?.ruleId, 'holo.pages.non-github-io-cname');
      assert.equal(failRes.violations[0]?.file, 'CNAME');
      assert.equal(failRes.violations[0]?.line, 1);
      assert.equal(failRes.violations[0]?.snippet, 'custom.awesome-os.com');
      assert.equal(failRes.violations[0]?.autofixable, true);

      // Canonical awesome-os.github.io CNAME is allowed
      writeFileSync(join(dir, 'CNAME'), 'awesome-os.github.io\n', 'utf8');
      const canonicalRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/cname-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/non-github-io-cname'],
      });
      assert.equal(canonicalRes.ok, true);
      assert.equal(canonicalRes.violationCount, 0);

      // Removing CNAME completely also passes
      rmSync(join(dir, 'CNAME'));
      const removedRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/cname-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/non-github-io-cname'],
      });
      assert.equal(removedRes.ok, true);
      assert.equal(removedRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('triggers all 13 built-in holo-ci audits simultaneously on a dirty repo in exhaust mode', async () => {
    const dir = makeTempDir('holo-audit-dirty-');
    try {
      mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
      mkdirSync(join(dir, 'src'), { recursive: true });
      mkdirSync(join(dir, 'dist'), { recursive: true });

      const badGhost = ['b8g', 'ghost'].join('-');
      const badCasV1 = ['cas', 'v1'].join('-');
      const badHttp = ['http', '://', '127.0.0.1:9999'].join('');
      const badToken = ['ghp', 'dirtyrepo1234567890'].join('_');
      const badWrite = ['writeFileSync(', "'leaky.txt', 'dirty');"].join('');

      // Missing LICENSE, .gitattributes, CODEOWNERS -> holo-ci/governance + holo-ci/spdx-header fail
      // Unhardened workflow + guard tokens -> holo-ci/wf-harden + holo-ci/guards fail
      writeFileSync(
        join(dir, '.github', 'workflows', 'bad.yml'),
        [
          'name: Bad Workflow',
          'on: [push]',
          'jobs:',
          '  test:',
          '    runs-on: ubuntu-latest',
          '    steps:',
          '      - uses: actions/checkout@v4',
          `      - run: echo ${badGhost} ${badCasV1} && curl ${badHttp}`,
          '',
        ].join('\n'),
        'utf8',
      );

      // Boundary violation -> holo-ci/boundary fails
      // Non-erasable enum -> holo-ci/erasable-syntax fails
      // Leaked token -> holo-ci/secret-scan fails
      // Dead barrel export -> holo-ci/dead-exports fails
      writeFileSync(
        join(dir, 'boundary.json'),
        JSON.stringify(
          {
            schema: HOLO_BOUNDARY_SCHEMA,
            plane: 2,
            forbiddenImports: ['forbidden-layer'],
            maxParentTraversals: 1,
            scanSourceHttpIpc: true,
          },
          null,
          2,
        ),
        'utf8',
      );
      writeFileSync(
        join(dir, 'src', 'bad.mts'),
        [
          "import { x } from 'forbidden-layer';",
          "export * from './missing-barrel.mts';",
          'export enum BadMode { Off = 0 }',
          `export const leaked = '${badToken}';`,
          'export const val = x;',
          '',
        ].join('\n'),
        'utf8',
      );

      // Oversized artifact -> holo-ci/binary-budget fails
      writeFileSync(join(dir, 'dist', 'oversized.wasm'), Buffer.alloc(600 * 1024));

      // Non-hermetic test -> holo-ci/test-hermeticity fails
      writeFileSync(join(dir, 'src', 'leaky.test.mts'), `${badWrite}\n`, 'utf8');

      // Invalid ABI golden -> holo-ci/abi-surface fails
      writeFileSync(
        join(dir, 'abi-golden.json'),
        JSON.stringify({ abiMagic: '0x00000000', header: 'missing.h' }),
        'utf8',
      );

      // Broken local link -> holo-ci/no-broken-local-links fails
      writeFileSync(join(dir, 'README.md'), '# Dirty Repo\n\nSee [Missing](./docs/does-not-exist.md).\n', 'utf8');

      // Custom CNAME -> holo-ci/non-github-io-cname fails
      writeFileSync(join(dir, 'CNAME'), 'legacy.example.org\n', 'utf8');

      const res = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/dirty-repo',
        mode: 'exhaust',
      });

      assert.equal(res.ok, false);
      assert.equal(res.ratified, false);
      assert.equal(res.failedFast, false);
      assert.equal(res.totalAudits, 13);
      assert.equal(res.passedAudits, 0);
      assert.equal(res.failedAudits, 13);
      assert.equal(res.abortedAudits, 0);

      for (const id of BUILTIN_HOLO_CI_AUDIT_IDS) {
        const entry = res.entries.find((e) => e.id === id);
        assert.ok(entry, `Expected entry for ${id}`);
        assert.equal(entry.status, 'failed', `Expected ${id} to fail`);
        assert.ok(entry.violationCount > 0, `Expected violations for ${id}`);
      }
      assert.ok(res.violations.every((v) => v.schema === HOLO_RULE_VIOLATION_SCHEMA));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('captures thrown exceptions from custom audits as failed entries with synthesized violation', async () => {
    const reg = createAuditStackRegistry();
    reg.register({
      id: 'custom/throwing',
      title: 'Throwing Audit',
      category: 'telemetry',
      severity: 'error',
      rollbackHint: 'Inspect audit error',
      remediationCmd: 'fix-audit',
      run: () => {
        throw new Error('simulated audit crash');
      },
    });

    const res = await reg.run({ cwd: REPO_ROOT, repo: 'awesome-os/crash-test', mode: 'exhaust' });
    assert.equal(res.ok, false);
    assert.equal(res.failedAudits, 1);
    assert.equal(res.entries[0]?.status, 'failed');
    assert.equal(res.entries[0]?.error, 'simulated audit crash');
    assert.equal(res.violationCount, 1);
    assert.match(res.violations[0]?.message ?? '', /simulated audit crash/);
  });

  it('exposes holo-ci audit-stack CLI subcommand with holo-ci.receipt.v1 JSON, telemetry, push output & exit codes', () => {
    const helpRes = spawnSync(process.execPath, [CLI_PATH, '--help'], { encoding: 'utf8' });
    assert.equal(helpRes.status, 0);
    assert.match(helpRes.stdout, /audit-stack/);
    assert.match(helpRes.stdout, /--mode/);
    assert.match(helpRes.stdout, /--telemetry-out/);
    assert.match(helpRes.stdout, /--repo/);

    const outDir = makeTempDir('holo-audit-cli-');
    try {
      // 1. Passing run on maintenance-workflows
      const passPushPath = join(outDir, 'pass-push.json');
      const passRes = spawnSync(
        process.execPath,
        [
          CLI_PATH,
          'audit-stack',
          '--cwd',
          REPO_ROOT,
          '--repo',
          'awesome-os/maintenance-workflows',
          '--mode',
          'exhaust',
          '--out',
          passPushPath,
          '--json',
        ],
        { encoding: 'utf8' },
      );
      assert.equal(passRes.status, 0, passRes.stderr || passRes.stdout);
      const passReceipt = JSON.parse(passRes.stdout) as HoloCiReceipt;
      assert.equal(passReceipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(passReceipt.abiMagic, B8G_ABI_MAGIC_V3);
      assert.equal(passReceipt.phase, 'audit-stack');
      assert.equal(passReceipt.ok, true);
      assert.equal(passReceipt.auditStack?.ratified, true);
      assert.equal(passReceipt.auditStack?.passedAudits, 13);
      assert.equal(existsSync(passPushPath), true);

      // 2. Failing run on temp repo with custom CNAME returns non-zero exit code + telemetry + push file
      const failRepo = join(outDir, 'fail-repo');
      seedCleanRepo(failRepo);
      writeFileSync(join(failRepo, 'CNAME'), 'bad.awesome-os.com\n', 'utf8');
      const telemetryFile = join(outDir, 'fail-telemetry.jsonl');
      const failPushPath = join(outDir, 'fail-push.json');

      const failRes = spawnSync(
        process.execPath,
        [
          CLI_PATH,
          'audit-stack',
          '--cwd',
          failRepo,
          '--repo',
          'awesome-os/fail-repo',
          '--mode',
          'exhaust',
          '--telemetry-out',
          telemetryFile,
          '--out',
          failPushPath,
          '--json',
        ],
        { encoding: 'utf8' },
      );
      assert.equal(failRes.status, 1);
      const failReceipt = JSON.parse(failRes.stdout) as HoloCiReceipt;
      assert.equal(failReceipt.schema, HOLO_CI_RECEIPT_SCHEMA);
      assert.equal(failReceipt.phase, 'audit-stack');
      assert.equal(failReceipt.ok, false);
      assert.equal(failReceipt.auditStack?.ok, false);
      assert.equal(failReceipt.auditStack?.violationCount, 1);
      assert.equal(failReceipt.auditStack?.violations[0]?.ruleId, 'holo.pages.non-github-io-cname');

      const telemetryRecords = readFileSync(telemetryFile, 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as HoloRuleViolation);
      assert.equal(telemetryRecords.length, 1);
      assert.equal(telemetryRecords[0]?.ruleId, 'holo.pages.non-github-io-cname');

      const failPushDoc = JSON.parse(readFileSync(failPushPath, 'utf8')) as HoloAuditPushPayload;
      assert.equal(failPushDoc.schema, HOLO_AUDIT_PUSH_SCHEMA);
      assert.equal(failPushDoc.ok, false);
      assert.equal(failPushDoc.violationCount, 1);

      // 3. Invalid --mode rejects cleanly with non-zero exit code
      const badModeRes = spawnSync(
        process.execPath,
        [CLI_PATH, 'audit-stack', '--mode', 'invalid-mode'],
        { encoding: 'utf8' },
      );
      assert.equal(badModeRes.status, 1);
      assert.match(badModeRes.stderr, /Invalid --mode/);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  it('holo-ci/erasable-syntax detects enum, namespace, and constructor parameter properties while ignoring comments/strings/skipDirs', async () => {
    const dir = makeTempDir('holo-audit-erasable-');
    try {
      seedCleanRepo(dir);

      // Positive cases in src/non-erasable.ts
      writeFileSync(
        join(dir, 'src', 'non-erasable.ts'),
        [
          'export enum Status {',
          '  Ok = 1,',
          '}',
          'namespace Internal {',
          '  export const v = 1;',
          '}',
          'export class Box {',
          '  constructor(private readonly id: string) {}',
          '}',
          '',
        ].join('\n'),
        'utf8',
      );

      // Negative cases: skipped directories, .d.ts, comments, string literals, and clean erasable TS
      mkdirSync(join(dir, 'node_modules', 'pkg'), { recursive: true });
      mkdirSync(join(dir, 'dist'), { recursive: true });
      writeFileSync(join(dir, 'node_modules', 'pkg', 'index.ts'), 'export enum Ignored { A = 1 }\n', 'utf8');
      writeFileSync(join(dir, 'dist', 'out.ts'), 'export enum BuiltIgnored { A = 1 }\n', 'utf8');
      writeFileSync(join(dir, 'src', 'types.d.ts'), 'export declare enum AmbientOk { A = 1 }\n', 'utf8');
      writeFileSync(
        join(dir, 'src', 'clean.mts'),
        [
          '// enum CommentEnum { A = 1 }',
          '/* namespace CommentNs { export const x = 1; } */',
          "export const example = 'enum StringEnum { A = 1 }';",
          'export const Status = { Ok: 1 } as const;',
          'export class CleanBox {',
          '  readonly id: string;',
          '  constructor(id: string) { this.id = id; }',
          '}',
          '',
        ].join('\n'),
        'utf8',
      );

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/erasable-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/erasable-syntax'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 3);
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-ERASABLE-SYNTAX');
        assert.equal(v.category, 'abi');
        assert.equal(v.file, 'src/non-erasable.ts');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      rmSync(join(dir, 'src', 'non-erasable.ts'));
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/erasable-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/erasable-syntax'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/secret-scan detects leaked token prefixes and private keys while honoring allow/fixture markers', async () => {
    const dir = makeTempDir('holo-audit-secret-');
    try {
      seedCleanRepo(dir);

      const ghpToken = ['ghp', '1234567890abcdef'].join('_');
      const patToken = ['github', 'pat', '11AAAAAA00000000'].join('_');
      const aizaToken = ['AIza', 'SyDummyKey1234567890'].join('');
      const akiaToken = ['AKIA', 'IOSFODNN7EXAMPLE12'].join('');
      const pemHeader = ['-----BEGIN ', 'RSA PRIVATE KEY-----'].join('');

      writeFileSync(
        join(dir, 'src', 'leaked.mts'),
        [
          `export const a = '${ghpToken}';`,
          `export const b = '${patToken}';`,
          `export const c = '${aizaToken}';`,
          `export const d = '${akiaToken}';`,
          `export const e = '${pemHeader}';`,
          '',
        ].join('\n'),
        'utf8',
      );

      // Negative cases: allow-secret marker, test-fixture marker, and skipped directories
      writeFileSync(
        join(dir, 'src', 'allowed.mts'),
        [
          `export const allowed = '${ghpToken}'; // holo-ci-allow-secret`,
          `export const fixture = '${akiaToken}'; // holo-ci-test-fixture`,
          '',
        ].join('\n'),
        'utf8',
      );
      mkdirSync(join(dir, '.holo-ci-runtime'), { recursive: true });
      writeFileSync(join(dir, '.holo-ci-runtime', 'cache.txt'), `${ghpToken}\n`, 'utf8');

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/secret-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/secret-scan'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 5);
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-SECRET-SCAN');
        assert.equal(v.category, 'security');
        assert.equal(v.file, 'src/leaked.mts');
        assert.match(v.snippet, /\*\*\*REDACTED\*\*\*/);
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      rmSync(join(dir, 'src', 'leaked.mts'));
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/secret-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/secret-scan'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/no-broken-local-links catches missing relative links in README.md and docs/*.md and allows valid/fenced links', async () => {
    const dir = makeTempDir('holo-audit-links-');
    try {
      seedCleanRepo(dir);
      mkdirSync(join(dir, 'docs'), { recursive: true });
      writeFileSync(join(dir, 'docs', 'guide.md'), '# Guide\n\nBack to [Root](../README.md#top) or [Missing](../nope.md).\n', 'utf8');
      writeFileSync(
        join(dir, 'README.md'),
        [
          '# Clean Repo',
          '',
          'Valid: [Guide](./docs/guide.md?raw=1#intro) and [External](https://awesome-os.github.io/).',
          'Inline code ignored: `[Ghost](./ghost.md)`.',
          '```markdown',
          '[FencedGhost](./fenced-ghost.md)',
          '```',
          'Broken: [Missing](./docs/missing.md).',
          '',
        ].join('\n'),
        'utf8',
      );

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/links-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/no-broken-local-links'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 2);
      assert.deepEqual(
        failRes.violations.map((v) => v.file).sort(),
        ['README.md', 'docs/guide.md'],
      );
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-BROKEN-LOCAL-LINK');
        assert.equal(v.category, 'docs');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      // Fix both broken links -> passes
      writeFileSync(join(dir, 'docs', 'guide.md'), '# Guide\n\nBack to [Root](../README.md#top).\n', 'utf8');
      writeFileSync(join(dir, 'README.md'), '# Clean Repo\n\nValid: [Guide](./docs/guide.md#intro).\n', 'utf8');
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/links-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/no-broken-local-links'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/dead-exports catches broken barrel re-exports and allows valid local module re-exports', async () => {
    const dir = makeTempDir('holo-audit-dead-exports-');
    try {
      seedCleanRepo(dir);
      writeFileSync(join(dir, 'src', 'real.mts'), 'export const real = 1;\n', 'utf8');
      writeFileSync(
        join(dir, 'src', 'index.mts'),
        [
          "export { real } from './real.mts';",
          "export * from './missing.mts';",
          "export type { Ghost } from './missing-type.mts';",
          '',
        ].join('\n'),
        'utf8',
      );

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/dead-exports-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/dead-exports'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 2);
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-DEAD-EXPORT');
        assert.equal(v.category, 'geometry');
        assert.equal(v.file, 'src/index.mts');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      writeFileSync(join(dir, 'src', 'index.mts'), "export { real } from './real.mts';\n", 'utf8');
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/dead-exports-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/dead-exports'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/binary-budget rejects oversized dist/ and sections/*/dist/ artifacts and honors manifest budget', async () => {
    const dir = makeTempDir('holo-audit-binary-budget-');
    try {
      seedCleanRepo(dir);
      mkdirSync(join(dir, 'dist'), { recursive: true });
      mkdirSync(join(dir, 'sections', 'kernel', 'dist'), { recursive: true });
      writeFileSync(join(dir, 'dist', 'ok.wasm'), Buffer.alloc(64 * 1024));
      writeFileSync(join(dir, 'dist', 'too-big.dll'), Buffer.alloc(600 * 1024));
      writeFileSync(join(dir, 'sections', 'kernel', 'dist', 'cp.so'), Buffer.alloc(550 * 1024));

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/binary-budget-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/binary-budget'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 2);
      assert.deepEqual(
        failRes.violations.map((v) => v.file).sort(),
        ['dist/too-big.dll', 'sections/kernel/dist/cp.so'],
      );
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-BINARY-BUDGET');
        assert.equal(v.category, 'abi');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      // Shrink artifacts under default 512 KB budget -> passes
      writeFileSync(join(dir, 'dist', 'too-big.dll'), Buffer.alloc(128 * 1024));
      writeFileSync(join(dir, 'sections', 'kernel', 'dist', 'cp.so'), Buffer.alloc(16 * 1024));
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/binary-budget-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/binary-budget'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/test-hermeticity catches unisolated fixture writes in *.test.mts and allows tmpdir+rmSync tests', async () => {
    const dir = makeTempDir('holo-audit-hermeticity-');
    try {
      seedCleanRepo(dir);
      const badCall = ['writeFileSync(', "'leaky-fixture.txt', 'data');"].join('');
      writeFileSync(
        join(dir, 'src', 'unisolated.test.mts'),
        [
          "import { writeFileSync } from 'node:fs';",
          badCall,
          '',
        ].join('\n'),
        'utf8',
      );
      writeFileSync(
        join(dir, 'src', 'clean.test.mts'),
        [
          "import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';",
          "import { tmpdir } from 'node:os';",
          "import { join } from 'node:path';",
          "const d = mkdtempSync(join(tmpdir(), 'ok-'));",
          "try { writeFileSync(join(d, 'ok.txt'), 'ok'); } finally { rmSync(d, { recursive: true, force: true }); }",
          '',
        ].join('\n'),
        'utf8',
      );

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/hermeticity-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/test-hermeticity'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 1);
      assert.equal(failRes.violations[0]?.schema, HOLO_RULE_VIOLATION_SCHEMA);
      assert.equal(failRes.violations[0]?.ruleId, 'B8G-TEST-HERMETICITY');
      assert.equal(failRes.violations[0]?.category, 'governance');
      assert.equal(failRes.violations[0]?.file, 'src/unisolated.test.mts');
      assert.match(failRes.violations[0]?.fingerprint ?? '', /^[0-9a-f]{16}$/);

      rmSync(join(dir, 'src', 'unisolated.test.mts'));
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/hermeticity-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/test-hermeticity'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/spdx-header verifies package.json license and root LICENSE SPDX consistency', async () => {
    const dir = makeTempDir('holo-audit-spdx-');
    try {
      seedCleanRepo(dir);
      // seedCleanRepo writes MIT LICENSE; mismatch package.json to Apache-2.0 -> fails
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: 'spdx-test', license: 'Apache-2.0' }, null, 2),
        'utf8',
      );

      const mismatchRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/spdx-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/spdx-header'],
      });
      assert.equal(mismatchRes.ok, false);
      assert.equal(mismatchRes.failedAudits, 1);
      assert.equal(mismatchRes.violationCount, 1);
      assert.equal(mismatchRes.violations[0]?.schema, HOLO_RULE_VIOLATION_SCHEMA);
      assert.equal(mismatchRes.violations[0]?.ruleId, 'B8G-SPDX-LICENSE');
      assert.equal(mismatchRes.violations[0]?.category, 'governance');
      assert.equal(mismatchRes.violations[0]?.file, 'package.json');
      assert.match(mismatchRes.violations[0]?.fingerprint ?? '', /^[0-9a-f]{16}$/);

      // Align package.json to MIT -> passes
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: 'spdx-test', license: 'MIT' }, null, 2),
        'utf8',
      );
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/spdx-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/spdx-header'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('holo-ci/abi-surface checks abi-golden.json for B8G_ABI_MAGIC_V3 (0x33564742) and existing header', async () => {
    const dir = makeTempDir('holo-audit-abi-');
    try {
      seedCleanRepo(dir);
      mkdirSync(join(dir, 'sections', 'cp'), { recursive: true });
      writeFileSync(
        join(dir, 'sections', 'cp', 'abi-golden.json'),
        JSON.stringify({ abiMagic: '0xDEADBEEF', header: 'sections/cp/missing.h' }, null, 2),
        'utf8',
      );

      const failRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/abi-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/abi-surface'],
      });
      assert.equal(failRes.ok, false);
      assert.equal(failRes.failedAudits, 1);
      assert.equal(failRes.violationCount, 2);
      for (const v of failRes.violations) {
        assert.equal(v.schema, HOLO_RULE_VIOLATION_SCHEMA);
        assert.equal(v.ruleId, 'B8G-ABI-SURFACE');
        assert.equal(v.category, 'abi');
        assert.equal(v.file, 'sections/cp/abi-golden.json');
        assert.match(v.fingerprint, /^[0-9a-f]{16}$/);
      }

      // Fix abiMagic to B8G_ABI_MAGIC_V3 and create referenced header -> passes
      writeFileSync(join(dir, 'sections', 'cp', 'cp_abi.h'), '#define B8G_ABI_MAGIC_V3 0x33564742\n', 'utf8');
      writeFileSync(
        join(dir, 'sections', 'cp', 'abi-golden.json'),
        JSON.stringify({ abiMagic: B8G_ABI_MAGIC_V3, header: 'sections/cp/cp_abi.h' }, null, 2),
        'utf8',
      );
      const passRes = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/abi-test',
        mode: 'exhaust',
        onlyIds: ['holo-ci/abi-surface'],
      });
      assert.equal(passRes.ok, true);
      assert.equal(passRes.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('skips heavy monorepo/vendor/mirror/CAS directories (third_party/, v8/, github-mirror/, node_modules/) cleanly', async () => {
    const dir = makeTempDir('holo-audit-skip-dirs-');
    try {
      seedCleanRepo(dir);
      const skippedDirs = ['third_party', 'v8', 'github-mirror', 'node_modules'];
      for (const skipDir of skippedDirs) {
        const base = join(dir, skipDir, 'nested');
        mkdirSync(base, { recursive: true });
        writeFileSync(join(base, 'bad.mts'), 'export enum BadEnum { A = 1 }\n', 'utf8');
        writeFileSync(join(base, 'secret.ts'), `export const tok = "${'ghp_'}1234567890abcdefghij1234567890abcd";\n`, 'utf8');
        writeFileSync(join(base, 'index.mts'), 'export { missing } from "./nonexistent.mts";\n', 'utf8');
        writeFileSync(
          join(base, 'bad.test.mts'),
          'import { writeFileSync } from "node:fs";\nwriteFileSync("leaked.txt", "x");\n',
          'utf8',
        );
        writeFileSync(
          join(base, 'abi-golden.json'),
          JSON.stringify({ abiMagic: '0xDEADBEEF', header: 'missing.h' }),
          'utf8',
        );
      }

      const docsSkipped = join(dir, 'docs', 'third_party');
      mkdirSync(docsSkipped, { recursive: true });
      writeFileSync(join(docsSkipped, 'broken.md'), '[broken](./does-not-exist.md)\n', 'utf8');

      const res = await runBuiltinAuditStack({
        cwd: dir,
        repo: 'awesome-os/skip-dirs-test',
        mode: 'exhaust',
        onlyIds: [
          'holo-ci/erasable-syntax',
          'holo-ci/secret-scan',
          'holo-ci/no-broken-local-links',
          'holo-ci/dead-exports',
          'holo-ci/test-hermeticity',
          'holo-ci/abi-surface',
        ],
      });
      assert.equal(res.ok, true);
      assert.equal(res.passedAudits, 6);
      assert.equal(res.failedAudits, 0);
      assert.equal(res.violationCount, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
