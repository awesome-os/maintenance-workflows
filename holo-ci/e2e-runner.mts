#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  accessSync,
  appendFileSync,
  constants,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface E2eImageSpec {
  targetImage: string;
  defaultImage: string;
  fallbackTarball: string;
  fallbackSums: string;
  runnerTier: string;
}

export interface ResolveE2eImageOptions {
  runnerImage?: string;
  runnerTier?: string;
  githubToken?: string;
  githubActor?: string;
  envFile?: string;
  workDir?: string;
  fetchFn?: typeof fetch;
  execFn?: typeof execFileSync;
}

export interface ResolveE2eImageResult {
  resolvedImage: string;
  runnerTier: string;
  imageSource: string;
}

export interface DockerRunOptions {
  workspace: string;
  artifactsPath: string;
  workingDirectory?: string;
  configPath?: string;
  runnerImage: string;
  runnerTier?: string;
  e2eCmd?: string;
  githubToken?: string;
  homeDir?: string;
}

export interface ContainerExecOptions {
  artifactsDir: string;
  configPath: string;
  runnerTier?: string;
  e2eCmd?: string;
  probePath?: string;
  cliPath?: string;
  execFn?: typeof execFileSync;
}

export function resolveImageSpec(
  runnerImage = 'ghcr.io/awesome-os/holo-e2e-runner:latest',
  runnerTier = 'gpu',
): E2eImageSpec {
  let targetImage = runnerImage || 'ghcr.io/awesome-os/holo-e2e-runner:latest';
  let defaultImage = 'ghcr.io/awesome-os/holo-e2e-runner:latest';
  let fallbackTarball = 'holo-e2e-runner-linux-amd64.oci.tar.gz';
  let fallbackSums = 'SHA512SUMS-holo-e2e-runner.txt';

  if (runnerTier === 'lite') {
    defaultImage = 'ghcr.io/awesome-os/holo-e2e-lite:latest';
    if (targetImage === 'ghcr.io/awesome-os/holo-e2e-runner:latest') {
      targetImage = 'ghcr.io/awesome-os/holo-e2e-lite:latest';
    }
    fallbackTarball = 'holo-e2e-lite-linux-amd64.oci.tar.gz';
    fallbackSums = 'SHA512SUMS-holo-e2e-lite.txt';
  }

  return {
    targetImage,
    defaultImage,
    fallbackTarball,
    fallbackSums,
    runnerTier,
  };
}

export function parseDockerLoadedImage(output: string): string {
  const lines = output.split(/\r?\n/);
  let loadedImg = '';
  for (const line of lines) {
    if (line.startsWith('Loaded image: ')) {
      loadedImg = line.slice('Loaded image: '.length).trim();
    }
  }
  if (!loadedImg) {
    for (const line of lines) {
      if (line.startsWith('Loaded image ID: ')) {
        loadedImg = line.slice('Loaded image ID: '.length).trim();
      }
    }
  }
  return loadedImg;
}

export function verifySha512SumsContent(
  sumsContent: string,
  targetFilename: string,
  actualSha512: string,
): boolean {
  const normalizedActual = actualSha512.trim().toLowerCase();
  for (const rawLine of sumsContent.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = /^([0-9a-f]{128})\s+\*?(.+)$/i.exec(line);
    if (!match) continue;
    const expectedHash = match[1].toLowerCase();
    const fileField = match[2].trim().replace(/^\.\//, '');
    if (fileField === targetFilename || fileField.endsWith(`/${targetFilename}`)) {
      return expectedHash === normalizedActual;
    }
  }
  return false;
}

export async function resolveE2eImage(options: ResolveE2eImageOptions = {}): Promise<ResolveE2eImageResult> {
  const spec = resolveImageSpec(options.runnerImage, options.runnerTier ?? 'gpu');
  const execFn = options.execFn ?? execFileSync;
  const fetchFn = options.fetchFn ?? fetch;
  const actor = options.githubActor || 'github-actions';
  const token = options.githubToken || '';

  let resolvedImage = '';
  let imageSource = '';
  let ghcrOk = false;

  if (token) {
    try {
      execFn('docker', ['login', 'ghcr.io', '-u', actor, '--password-stdin'], {
        input: `${token}\n`,
        stdio: ['pipe', 'ignore', 'ignore'],
        shell: false,
      });
      execFn('docker', ['pull', spec.targetImage], {
        stdio: 'ignore',
        shell: false,
      });
      resolvedImage = spec.targetImage;
      imageSource = `ghcr:${spec.targetImage}`;
      ghcrOk = true;
    } catch {
      ghcrOk = false;
    }
  }

  if (!ghcrOk) {
    process.stdout.write(
      `GHCR pull unavailable for ${spec.targetImage}; falling back to sovereign OCI release tarball.\n`,
    );
    const ociDir = options.workDir ?? join(tmpdir(), 'holo-oci');
    rmSync(ociDir, { recursive: true, force: true });
    mkdirSync(ociDir, { recursive: true });

    const baseUrl = 'https://github.com/awesome-os/dockerimages/releases/download/v11-oci-latest';
    const [tarRes, sumsRes] = await Promise.all([
      fetchFn(`${baseUrl}/${spec.fallbackTarball}`),
      fetchFn(`${baseUrl}/${spec.fallbackSums}`),
    ]);
    if (!tarRes.ok) {
      throw new Error(`Failed to download ${spec.fallbackTarball}: HTTP ${tarRes.status}`);
    }
    if (!sumsRes.ok) {
      throw new Error(`Failed to download ${spec.fallbackSums}: HTTP ${sumsRes.status}`);
    }

    const tarBuf = Buffer.from(await tarRes.arrayBuffer());
    const sumsText = await sumsRes.text();
    const actualSha512 = createHash('sha512').update(tarBuf).digest('hex');

    if (!verifySha512SumsContent(sumsText, spec.fallbackTarball, actualSha512)) {
      throw new Error(`SHA-512 verification failed for ${spec.fallbackTarball} (actual: ${actualSha512})`);
    }

    const tarballPath = join(ociDir, spec.fallbackTarball);
    writeFileSync(tarballPath, tarBuf);
    writeFileSync(join(ociDir, spec.fallbackSums), sumsText, 'utf8');

    const loadOut = String(
      execFn('docker', ['load', '-i', tarballPath], {
        encoding: 'utf8',
        shell: false,
      }) ?? '',
    );
    if (loadOut) process.stdout.write(`${loadOut}\n`);

    const loadedImg = parseDockerLoadedImage(loadOut);
    resolvedImage = loadedImg || spec.defaultImage;
    imageSource = `release:v11-oci-latest (${resolvedImage})`;
  }

  if (options.envFile) {
    const lines = [
      `RUNNER_IMAGE=${resolvedImage}`,
      `RUNNER_TIER=${spec.runnerTier}`,
      `HOLO_E2E_IMAGE_SOURCE=${imageSource}`,
      '',
    ].join('\n');
    appendFileSync(options.envFile, lines, 'utf8');
  }

  process.stdout.write(`Resolved runner image: ${resolvedImage} (${imageSource})\n`);
  return { resolvedImage, runnerTier: spec.runnerTier, imageSource };
}

export function buildDockerRunArgs(options: DockerRunOptions): string[] {
  const home = options.homeDir ?? homedir();
  const workingDirectory = options.workingDirectory?.trim() || '.';
  const workdir = workingDirectory !== '.' ? `/workspace/${workingDirectory}` : '/workspace';
  const artifactsPath = options.artifactsPath || 'holo-e2e-artifacts';
  const configPath = options.configPath || 'holo-ci.json';
  const runnerTier = options.runnerTier || 'gpu';

  return [
    'run',
    '--rm',
    '-v',
    `${options.workspace}:/workspace`,
    '-v',
    `${home}/.b8g/cas:/var/lib/b8g/cas`,
    '-w',
    workdir,
    '-e',
    `HOLO_E2E_ARTIFACTS=/workspace/${artifactsPath}`,
    '-e',
    `HOLO_CONFIG_PATH=${configPath}`,
    '-e',
    `RUNNER_TIER=${runnerTier}`,
    '-e',
    `E2E_CMD=${options.e2eCmd ?? ''}`,
    '-e',
    `GITHUB_TOKEN=${options.githubToken ?? ''}`,
    options.runnerImage,
    'node',
    '/workspace/.holo-ci-runtime/holo-ci/e2e-runner.mts',
    'container-exec',
  ];
}

export function runContainerizedE2e(
  options: DockerRunOptions & { execFn?: typeof execFileSync },
): void {
  const home = options.homeDir ?? homedir();
  const artifactsDir = resolve(options.workspace, options.artifactsPath || 'holo-e2e-artifacts');
  mkdirSync(artifactsDir, { recursive: true });
  mkdirSync(join(home, '.b8g', 'cas', 'v11'), { recursive: true });

  const execFn = options.execFn ?? execFileSync;
  const args = buildDockerRunArgs(options);
  execFn('docker', args, { stdio: 'inherit', shell: false });
}

export function runInContainer(options: ContainerExecOptions): void {
  const execFn = options.execFn ?? execFileSync;
  const probePath = options.probePath ?? '/usr/local/bin/holo-e2e-probe';
  const cliPath = options.cliPath ?? '/workspace/.holo-ci-runtime/holo-ci/cli.mts';
  const runnerTier = options.runnerTier || 'gpu';
  const probeOutBmp = join(options.artifactsDir, 'offscreen-probe.bmp');
  const probeOutJson = join(options.artifactsDir, 'offscreen-probe.json');
  const receiptPath = join(options.artifactsDir, 'holo-e2e-receipt.ndjson');

  mkdirSync(options.artifactsDir, { recursive: true });

  let probeExecutable = false;
  if (existsSync(probePath)) {
    try {
      accessSync(probePath, constants.X_OK);
      probeExecutable = true;
    } catch {
      probeExecutable = false;
    }
  }

  if (probeExecutable) {
    const probeJson = String(
      execFn(probePath, ['--out', probeOutBmp], {
        encoding: 'utf8',
        shell: false,
      }) ?? '',
    );
    process.stdout.write(probeJson);
    writeFileSync(probeOutJson, probeJson, 'utf8');
  } else if (runnerTier === 'lite') {
    writeFileSync(
      probeOutJson,
      `${JSON.stringify({ tier: 'lite', lavapipeIcd: 'skipped-lite', bmpSha512: 'skipped-lite' })}\n`,
      'utf8',
    );
  } else {
    throw new Error(`Missing ${probePath} in gpu runner tier`);
  }

  execFn(
    process.execPath,
    [cliPath, 'verify', '--config', options.configPath, '--receipt', receiptPath],
    { stdio: 'inherit', shell: false },
  );

  if (options.e2eCmd && options.e2eCmd.trim().length > 0) {
    execFn('bash', ['-euo', 'pipefail', '-c', options.e2eCmd], {
      stdio: 'inherit',
      shell: false,
    });
  }
}

export function formatE2eSummaryMarkdown(artifactsDir: string, imageSource: string): string {
  let lavapipeIcd = 'n/a';
  let bmpSha512 = 'n/a';
  const probePath = join(artifactsDir, 'offscreen-probe.json');
  if (existsSync(probePath)) {
    try {
      const probe = JSON.parse(readFileSync(probePath, 'utf8')) as {
        lavapipeIcd?: string;
        icd?: string;
        bmpSha512?: string;
        sha512?: string;
      };
      lavapipeIcd = probe.lavapipeIcd || probe.icd || 'n/a';
      bmpSha512 = probe.bmpSha512 || probe.sha512 || 'n/a';
    } catch {
      // ignore malformed probe JSON
    }
  }

  let verifyStatus = 'missing';
  const receiptPath = join(artifactsDir, 'holo-e2e-receipt.ndjson');
  if (existsSync(receiptPath)) {
    const lines = readFileSync(receiptPath, 'utf8')
      .trim()
      .split(/\r?\n/)
      .filter(Boolean);
    const lastLine = lines[lines.length - 1];
    if (lastLine) {
      try {
        const receipt = JSON.parse(lastLine) as { ok?: boolean };
        verifyStatus = receipt.ok ? 'pass' : 'fail';
      } catch {
        verifyStatus = 'invalid-receipt';
      }
    }
  }

  return [
    '### Holo-E2E Offscreen Lavapipe + Zero-X11 Summary',
    '',
    '| Field | Value |',
    '| :--- | :--- |',
    `| Container Source | \`${imageSource}\` |`,
    `| \`lavapipeIcd\` | \`${lavapipeIcd}\` |`,
    `| \`bmpSha512\` | \`${bmpSha512}\` |`,
    `| \`holo-ci verify\` | \`${verifyStatus}\` |`,
    '',
  ].join('\n');
}

export function writeE2eSummary(options: {
  artifactsDir: string;
  imageSource?: string;
  summaryPath?: string;
}): boolean {
  const summaryPath = options.summaryPath ?? process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return false;
  const md = formatE2eSummaryMarkdown(options.artifactsDir, options.imageSource || 'unknown');
  mkdirSync(dirname(resolve(summaryPath)), { recursive: true });
  appendFileSync(summaryPath, md, 'utf8');
  return true;
}

async function main(argv: string[]): Promise<void> {
  const subcommand = argv[0] ?? 'run';
  if (subcommand === 'resolve-image') {
    await resolveE2eImage({
      runnerImage: process.env.RUNNER_IMAGE_INPUT || process.env.RUNNER_IMAGE,
      runnerTier: process.env.RUNNER_TIER_INPUT || process.env.RUNNER_TIER || 'gpu',
      githubToken: process.env.GITHUB_TOKEN || process.env.GH_TOKEN,
      githubActor: process.env.GITHUB_ACTOR,
      envFile: process.env.GITHUB_ENV,
    });
    return;
  }

  if (subcommand === 'run') {
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    runContainerizedE2e({
      workspace,
      artifactsPath: process.env.HOLO_ARTIFACTS_PATH || 'holo-e2e-artifacts',
      workingDirectory: process.env.HOLO_WORKING_DIRECTORY || '.',
      configPath: process.env.HOLO_CONFIG_PATH || 'holo-ci.json',
      runnerImage: process.env.RUNNER_IMAGE || 'ghcr.io/awesome-os/holo-e2e-runner:latest',
      runnerTier: process.env.RUNNER_TIER || 'gpu',
      e2eCmd: process.env.E2E_CMD || '',
      githubToken: process.env.GITHUB_TOKEN || '',
    });
    return;
  }

  if (subcommand === 'container-exec') {
    runInContainer({
      artifactsDir: process.env.HOLO_E2E_ARTIFACTS || '/workspace/holo-e2e-artifacts',
      configPath: process.env.HOLO_CONFIG_PATH || 'holo-ci.json',
      runnerTier: process.env.RUNNER_TIER || 'gpu',
      e2eCmd: process.env.E2E_CMD || '',
    });
    return;
  }

  if (subcommand === 'summary') {
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    const artifactsPath = argv[1] || process.env.HOLO_ARTIFACTS_PATH || 'holo-e2e-artifacts';
    const artifactsDir = resolve(workspace, artifactsPath);
    const imageSource = process.env.HOLO_E2E_IMAGE_SOURCE || process.env.RUNNER_IMAGE || 'unknown';
    writeE2eSummary({ artifactsDir, imageSource });
    return;
  }

  throw new Error(`Unknown e2e-runner subcommand "${subcommand}"`);
}

const isDirectEntry =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`[holo-e2e-runner] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
