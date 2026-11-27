import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseCliArgs } from './cli.mts';
import {
  B8G_ABI_MAGIC_V3,
  collectFleetForensics,
  FLEET_FORENSICS_SCHEMA,
  formatForensicsSummaryMarkdown,
  parseFleetForensicsCliArgs,
  runFleetForensicsCli,
  stripAnsi,
} from './fleet-forensics.mts';
import { createGithubClient } from './gh-client.mts';
import { createRuleViolation, HOLO_CI_SCHEMA } from './schema.mts';
import { buildReceipt, formatStepSummaryMarkdown } from './telemetry.mts';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('holo-ci/fleet-forensics single-process scanner', () => {
  it('strips CSI, OSC, and 2-byte ANSI escape sequences cleanly', () => {
    const raw = '\x1b[31mFAIL\x1b[0m: \x1b[1;33mBuild\x1b[0m \x1b]8;;https://example.com\x07link\x1b]8;;\x07 ok';
    assert.equal(stripAnsi(raw), 'FAIL: Build link ok');
    assert.equal(stripAnsi('plain text 123'), 'plain text 123');
    assert.equal(stripAnsi(''), '');
  });

  it('collects failed, cancelled, and slow runs/jobs via mocked fetchImpl with zero network calls', async () => {
    const nowMs = Date.parse('2026-11-27T12:00:00Z');
    const requestedUrls: string[] = [];

    const fetchImpl: typeof fetch = async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      requestedUrls.push(url);

      if (url.includes('/orgs/awesome-os/repos')) {
        return jsonResponse([
          { name: 'repo-green', archived: false },
          { name: 'repo-broken', archived: false },
          { name: 'repo-archived', archived: true },
        ]);
      }

      if (url.includes('/repos/awesome-os/repo-green/actions/runs')) {
        return jsonResponse({
          workflow_runs: [
            {
              id: 101,
              workflow_id: 1,
              name: 'CI Verify',
              status: 'completed',
              conclusion: 'success',
              head_branch: 'main',
              event: 'push',
              html_url: 'https://github.com/awesome-os/repo-green/actions/runs/101',
              created_at: '2026-11-27T11:30:00Z',
              run_started_at: '2026-11-27T11:30:00Z',
              updated_at: '2026-11-27T11:31:00Z',
            },
            {
              // Outside 4h window -> must be excluded from window alerts
              id: 99,
              workflow_id: 2,
              name: 'Old Nightly',
              status: 'completed',
              conclusion: 'failure',
              head_branch: 'main',
              event: 'schedule',
              html_url: 'https://github.com/awesome-os/repo-green/actions/runs/99',
              created_at: '2026-11-27T02:00:00Z',
              run_started_at: '2026-11-27T02:00:00Z',
              updated_at: '2026-11-27T02:10:00Z',
            },
          ],
        });
      }

      if (url.includes('/repos/awesome-os/repo-broken/actions/runs/201/jobs')) {
        return jsonResponse({
          jobs: [
            {
              id: 5001,
              name: '\x1b[31mBuild Win64\x1b[0m',
              status: 'completed',
              conclusion: 'failure',
              html_url: 'https://github.com/awesome-os/repo-broken/actions/runs/201/job/5001',
              started_at: '2026-11-27T11:00:00Z',
              completed_at: '2026-11-27T11:07:30Z', // 450s > 300s slow threshold
              steps: [
                { name: 'Checkout', conclusion: 'success' },
                { name: '\x1b[1;31mCompile Zig\x1b[0m', conclusion: 'failure' },
              ],
            },
          ],
        });
      }

      if (url.includes('/repos/awesome-os/repo-broken/actions/runs')) {
        return jsonResponse({
          workflow_runs: [
            {
              id: 201,
              workflow_id: 10,
              name: '\x1b[33mRelease Build\x1b[0m',
              status: 'completed',
              conclusion: 'failure',
              head_branch: 'main',
              event: 'push',
              html_url: 'https://github.com/awesome-os/repo-broken/actions/runs/201',
              created_at: '2026-11-27T11:00:00Z',
              run_started_at: '2026-11-27T11:00:00Z',
              updated_at: '2026-11-27T11:07:30Z',
            },
            {
              id: 202,
              workflow_id: 11,
              name: 'PR Check',
              status: 'completed',
              conclusion: 'cancelled',
              head_branch: 'feat/test',
              event: 'pull_request',
              html_url: 'https://github.com/awesome-os/repo-broken/actions/runs/202',
              created_at: '2026-11-27T11:40:00Z',
              run_started_at: '2026-11-27T11:40:00Z',
              updated_at: '2026-11-27T11:41:00Z',
            },
          ],
        });
      }

      return jsonResponse({ message: 'Not Found' }, 404);
    };

    const client = createGithubClient({
      token: 'test-token',
      allowCliTokenFallback: false,
      fetchImpl,
      sleepImpl: async () => {},
    });

    const report = await collectFleetForensics({
      owner: 'awesome-os',
      hours: 4,
      slowThresholdSec: 300,
      nowMs,
      client,
    });

    assert.equal(report.schema, FLEET_FORENSICS_SCHEMA);
    assert.equal(report.abiMagic, B8G_ABI_MAGIC_V3);
    assert.equal(report.ok, false);
    assert.equal(report.reposScanned, 2);
    assert.equal(report.greenOnLatest, 0);
    assert.equal(report.failedRuns.length, 1);
    assert.equal(report.cancelledRuns.length, 1);
    assert.equal(report.slowJobs.length, 1);

    assert.equal(report.failedRuns[0]?.repo, 'repo-broken');
    assert.equal(report.failedRuns[0]?.workflowName, 'Release Build');
    assert.deepEqual(report.failedRuns[0]?.failedSteps, ['Build Win64 :: Compile Zig']);

    assert.equal(report.cancelledRuns[0]?.repo, 'repo-broken');
    assert.equal(report.cancelledRuns[0]?.runId, 202);

    assert.equal(report.slowJobs[0]?.jobName, 'Build Win64');
    assert.equal(report.slowJobs[0]?.durationSec, 450);

    // Ensure archived repo was skipped
    assert.ok(!requestedUrls.some((u) => u.includes('repo-archived')));

    const md = formatForensicsSummaryMarkdown(report);
    assert.match(md, /## Fleet Forensics — `awesome-os` \(4h window\) \[FAIL\]/);
    assert.match(md, /### Failed Runs \(1\)/);
    assert.match(md, /### Cancelled Runs \(1\)/);
    assert.match(md, /### Slow Jobs \(> 300s\) \(1\)/);
    assert.match(md, /Build Win64 :: Compile Zig/);
    assert.ok(!md.includes('\x1b['));
  });

  it('supports standalone CLI and holo-ci CLI argument parsing for fleet-forensics and wf-harden --fleet', async () => {
    const standalone = parseFleetForensicsCliArgs([
      '--owner',
      'awesome-os',
      '--repos',
      'alpha,beta',
      '--hours',
      '6',
      '--slow-sec',
      '180',
      '--json',
    ]);
    assert.equal(standalone.owner, 'awesome-os');
    assert.deepEqual(standalone.repos, ['alpha', 'beta']);
    assert.equal(standalone.hours, 6);
    assert.equal(standalone.slowThresholdSec, 180);
    assert.equal(standalone.json, true);

    const holoCli = parseCliArgs([
      'fleet-forensics',
      '--owner',
      'awesome-os',
      '--repos',
      'a,b',
      '--hours',
      '4',
      '--slow-sec',
      '300',
      '--json',
    ]);
    assert.equal(holoCli.phase, 'fleet-forensics');
    assert.equal(holoCli.owner, 'awesome-os');
    assert.deepEqual(holoCli.repos, ['a', 'b']);
    assert.equal(holoCli.hours, 4);
    assert.equal(holoCli.slowSec, 300);

    const fleetCli = parseCliArgs(['wf-harden', '--fleet', 'github-mirror/awesome-os', '--check', '--json']);
    assert.equal(fleetCli.phase, 'wf-harden');
    assert.ok(fleetCli.fleetRoot?.endsWith('awesome-os'));
    assert.equal(fleetCli.check, true);

    const mockClient = createGithubClient({
      token: 'test-token',
      allowCliTokenFallback: false,
      fetchImpl: async () => jsonResponse({ workflow_runs: [] }),
      sleepImpl: async () => {},
    });

    const originalWrite = process.stdout.write.bind(process.stdout);
    const chunks: string[] = [];
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    }) as typeof process.stdout.write;

    try {
      const res = await runFleetForensicsCli(['--owner', 'awesome-os', '--repos', 'clean-repo', '--json'], mockClient);
      assert.equal(res.exitCode, 0);
      const parsed = JSON.parse(chunks.join('')) as { schema: string; ok: boolean; greenOnLatest: number };
      assert.equal(parsed.schema, FLEET_FORENSICS_SCHEMA);
      assert.equal(parsed.ok, true);
      assert.equal(parsed.greenOnLatest, 1);
    } finally {
      process.stdout.write = originalWrite;
    }
  });

  it('supports --gate none|latest|window for superseded failures vs green-on-latest', async () => {
    const nowMs = Date.parse('2026-06-15T12:00:00.000Z');
    const mockClient = createGithubClient({
      token: 'test-token',
      allowCliTokenFallback: false,
      fetchImpl: async (url) => {
        if (url.includes('/actions/runs?')) {
          return jsonResponse({
            workflow_runs: [
              // Latest run on main is green, but an earlier run in the window failed
              {
                id: 302,
                workflow_id: 1,
                name: 'CI',
                status: 'completed',
                conclusion: 'success',
                head_branch: 'main',
                event: 'push',
                created_at: '2026-06-15T11:30:00.000Z',
                run_started_at: '2026-06-15T11:30:05.000Z',
                updated_at: '2026-06-15T11:31:00.000Z',
              },
              {
                id: 301,
                workflow_id: 1,
                name: 'CI',
                status: 'completed',
                conclusion: 'failure',
                head_branch: 'main',
                event: 'push',
                created_at: '2026-06-15T10:30:00.000Z',
                run_started_at: '2026-06-15T10:30:05.000Z',
                updated_at: '2026-06-15T10:31:00.000Z',
              },
            ],
          });
        }
        return jsonResponse({ jobs: [] });
      },
      sleepImpl: async () => {},
    });

    const windowReport = await collectFleetForensics({
      owner: 'awesome-os',
      repos: ['healed-repo'],
      hours: 4,
      nowMs,
      client: mockClient,
      gate: 'window',
    });
    assert.equal(windowReport.gate, 'window');
    assert.equal(windowReport.greenOnLatest, 1);
    assert.equal(windowReport.failedRuns.length, 1);
    assert.equal(windowReport.ok, false);

    const latestReport = await collectFleetForensics({
      owner: 'awesome-os',
      repos: ['healed-repo'],
      hours: 4,
      nowMs,
      client: mockClient,
      gate: 'latest',
    });
    assert.equal(latestReport.gate, 'latest');
    assert.equal(latestReport.greenOnLatest, 1);
    assert.equal(latestReport.reposScanned, 1);
    assert.equal(latestReport.ok, true);

    const noneReport = await collectFleetForensics({
      owner: 'awesome-os',
      repos: ['healed-repo'],
      hours: 4,
      nowMs,
      client: mockClient,
      gate: 'none',
    });
    assert.equal(noneReport.gate, 'none');
    assert.equal(noneReport.ok, true);

    const cliParsed = parseCliArgs(['fleet-forensics', '--gate', 'latest', '--json']);
    assert.equal(cliParsed.gate, 'latest');
    const standaloneParsed = parseFleetForensicsCliArgs(['--gate', 'none']);
    assert.equal(standaloneParsed.gate, 'none');
  });
});

describe('holo-ci/telemetry structured violation tables for GITHUB_STEP_SUMMARY', () => {
  const manifest = {
    schema: HOLO_CI_SCHEMA,
    name: 'demo-repo',
    kind: 'control-plane' as const,
  };

  it('renders structured Rule / Guard | File:Line | Snippet / Message tables for verify, boundary-audit, wf-harden, and audit-stack failures', () => {
    const verifyMd = formatStepSummaryMarkdown(
      buildReceipt({
        manifest,
        phase: 'verify',
        ok: false,
        durationMs: 12,
        verify: {
          ok: false,
          tests: [],
          nativeGates: [],
          docs: [{ path: 'README.md', exists: true }],
          guardViolations: [
            {
              guard: 'zeroHttpIpc',
              file: 'src/server.mts',
              line: 42,
              snippet: 'http.createServer() | listen',
            },
          ],
        },
      }),
    );
    assert.match(verifyMd, /\| Rule \/ Guard \| File:Line \| Snippet \/ Message \|/);
    assert.match(verifyMd, /\| `zeroHttpIpc` \| `src\/server\.mts:42` \| http\.createServer\(\) \\\| listen \|/);

    const boundaryMd = formatStepSummaryMarkdown(
      buildReceipt({
        manifest,
        phase: 'boundary-audit',
        ok: false,
        durationMs: 8,
        boundaryAudit: {
          ok: false,
          score: 80,
          manifestFound: true,
          boundaryPath: 'boundary.json',
          scannedFiles: 10,
          axes: {
            dependencyPurity: 20,
            encapsulation: 20,
            ipcCompliance: 0,
            abiContract: 20,
            governance: 20,
          },
          violations: [
            {
              rule: 'httpIpc',
              file: 'src/ipc.mts',
              line: 9,
              snippet: '127.0.0.1:8080',
              message: 'Loopback HTTP IPC forbidden',
            },
          ],
        },
      }),
    );
    assert.match(boundaryMd, /### Boundary Violations \(1\)/);
    assert.match(boundaryMd, /\| `httpIpc` \| `src\/ipc\.mts:9` \| Loopback HTTP IPC forbidden/);

    const wfHardenMd = formatStepSummaryMarkdown(
      buildReceipt({
        manifest,
        phase: 'wf-harden',
        ok: false,
        durationMs: 5,
        wfHarden: {
          schema: 'holo-ci.wf-harden.v1',
          abiMagic: B8G_ABI_MAGIC_V3,
          repoDir: '/tmp/demo',
          mode: 'check',
          ok: false,
          workflowsScanned: 2,
          totalFindings: 1,
          remainingFindings: 1,
          totalFixesApplied: 0,
          modifiedFiles: [],
          files: [
            {
              fileName: '.github/workflows/pages.yml',
              ok: false,
              changed: false,
              content: '',
              findings: [],
              remainingFindings: [
                {
                  rule: 'duplicate-pages-workflow',
                  ruleId: 'duplicate-pages-workflow',
                  severity: 'error',
                  file: '.github/workflows/pages.yml',
                  line: 14,
                  message: 'Duplicate actions/deploy-pages workflow',
                  snippet: '- uses: actions/deploy-pages@v5',
                },
              ],
              fixesApplied: [],
            },
          ],
        },
      }),
    );
    assert.match(wfHardenMd, /### Workflow Hardening Violations \(1\)/);
    assert.match(wfHardenMd, /\| `duplicate-pages-workflow` \| `\.github\/workflows\/pages\.yml:14` \| Duplicate actions\/deploy-pages workflow \|/);

    const violation = createRuleViolation({
      ruleId: 'B8G016',
      severity: 'error',
      category: 'ipc',
      repo: 'demo-repo',
      file: 'src/bus.mts',
      line: 17,
      snippet: 'http://127.0.0.1',
      message: 'B8G016 loopback HTTP violation',
    });
    const auditStackMd = formatStepSummaryMarkdown(
      buildReceipt({
        manifest,
        phase: 'audit-stack',
        ok: false,
        durationMs: 20,
        auditStack: {
          schema: 'b8g.audit-stack-run.v1',
          abiMagic: B8G_ABI_MAGIC_V3,
          generatedAt: '2026-11-27T12:00:00Z',
          repo: 'demo-repo',
          mode: 'exhaust',
          ok: false,
          ratified: false,
          failedFast: false,
          totalAudits: 1,
          passedAudits: 0,
          failedAudits: 1,
          abortedAudits: 0,
          violationCount: 1,
          durationMs: 20,
          entries: [],
          violations: [violation],
          pushPayload: {
            schema: 'b8g.audit-push.v1',
            abiMagic: B8G_ABI_MAGIC_V3,
            generatedAt: '2026-11-27T12:00:00Z',
            repo: 'demo-repo',
            mode: 'exhaust',
            ok: false,
            ratified: false,
            failedFast: false,
            totalAudits: 1,
            passedAudits: 0,
            failedAudits: 1,
            abortedAudits: 0,
            violationCount: 1,
            durationMs: 20,
            audits: [],
            violations: [violation],
            violationCountsByRule: { B8G016: 1 },
            fingerprints: [violation.fingerprint],
          },
        },
      }),
    );
    assert.match(auditStackMd, /### Audit Stack Violations \(1\)/);
    assert.match(auditStackMd, /\| `B8G016` \| `src\/bus\.mts:17` \| B8G016 loopback HTTP violation/);
  });
});
