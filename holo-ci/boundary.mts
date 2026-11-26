import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';
import {
  HOLO_BOUNDARY_SCHEMA,
  loadManifest,
  type HoloBoundaryManifest,
  type HoloCiBoundaryAxes,
  type HoloCiBoundaryResult,
  type HoloCiBoundaryViolation,
} from './schema.mts';
import { scanGuardViolations } from './verify.mts';

export { HOLO_BOUNDARY_SCHEMA, type HoloBoundaryManifest };

const LOCALHOST_HTTP_PREFIX = ['http', '://'].join('');
const HTTP_IPC_REGEX = new RegExp(`${LOCALHOST_HTTP_PREFIX}(?:127\\.0\\.0\\.1|localhost)(?::\\d+)?`, 'i');

const EXCLUDED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'target',
  'out',
  'archive',
  'third_party',
  'deps',
  'v8',
  'v8_monolith',
  'github-mirror',
  'github-releases-mirror',
  'repository',
  't2-release',
  '.b8g-cas',
  '.awesome-oci',
  '.tmp-snapshots',
  'models',
  'electron-docs',
  'fdir',
  '.holo-ci-runtime',
]);
const SOURCE_EXT_REGEX = /\.(?:mts|ts|mjs|js|c|cc|h)$/i;
const TEST_SPEC_REGEX = /\.(?:test|spec)\.[^.]+$/i;

const FROM_IMPORT_REGEX = /\bfrom\s+(['"])([^'"]+)\1/g;
const SIDE_EFFECT_IMPORT_REGEX = /(?:^|[;\s])import\s+(['"])([^'"]+)\1/g;
const CALL_IMPORT_REGEX = /\b(?:import|require)\s*\(\s*(['"])([^'"]+)\1\s*\)/g;
const C_INCLUDE_REGEX = /^\s*#\s*include\s*(?:"([^"]+)"|<([^>]+)>)/;

export interface RunBoundaryAuditOptions {
  cwd?: string;
  boundaryPath?: string;
  configPath?: string;
  manifest?: HoloBoundaryManifest;
}

function collectSourceFiles(cwd: string, manifest?: HoloBoundaryManifest): string[] {
  const excludedDirs = new Set(EXCLUDED_DIRS);
  for (const dir of manifest?.excludeDirs ?? []) {
    if (dir) excludedDirs.add(dir);
  }

  const results: string[] = [];
  const seen = new Set<string>();

  const addFile = (filePath: string, fileName: string): void => {
    if (!SOURCE_EXT_REGEX.test(fileName)) return;
    if (TEST_SPEC_REGEX.test(fileName)) return;
    if (!seen.has(filePath)) {
      seen.add(filePath);
      results.push(filePath);
    }
  };

  function walk(dir: string): void {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name)) continue;
        walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        addFile(join(dir, entry.name), entry.name);
      }
    }
  }

  const includePaths = manifest?.includePaths?.filter((p) => p.trim().length > 0) ?? [];
  if (includePaths.length > 0) {
    for (const relPath of includePaths) {
      const target = resolve(cwd, relPath);
      if (!existsSync(target)) continue;
      const stat = statSync(target);
      if (stat.isDirectory()) {
        walk(target);
      } else if (stat.isFile()) {
        addFile(target, basename(target));
      }
    }
    return results;
  }

  if (existsSync(cwd)) {
    walk(cwd);
  }
  return results;
}

function extractLineSpecifiers(lineText: string): string[] {
  const trimmed = lineText.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
    return [];
  }

  const found: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string | undefined): void => {
    if (!raw) return;
    if (!seen.has(raw)) {
      seen.add(raw);
      found.push(raw);
    }
  };

  for (const regex of [FROM_IMPORT_REGEX, SIDE_EFFECT_IMPORT_REGEX, CALL_IMPORT_REGEX]) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(lineText)) !== null) {
      add(match[2]);
    }
  }

  const incMatch = C_INCLUDE_REGEX.exec(lineText);
  if (incMatch) {
    add(incMatch[1] ?? incMatch[2]);
  }

  return found;
}

function matchesImportPattern(specifier: string, pattern: string): boolean {
  const normalized = specifier.replace(/\\/g, '/');
  if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
    const lastSlash = pattern.lastIndexOf('/');
    const body = pattern.slice(1, lastSlash);
    const flags = pattern.slice(lastSlash + 1);
    try {
      return new RegExp(body, flags).test(normalized);
    } catch {
      return normalized.includes(pattern);
    }
  }

  if (normalized.includes(pattern)) {
    return true;
  }

  if (/[\^$*+?()[\]{}|\\]/.test(pattern)) {
    try {
      return new RegExp(pattern).test(normalized);
    } catch {
      return false;
    }
  }

  return false;
}

function countParentTraversals(specifier: string): number {
  const normalized = specifier.replace(/\\/g, '/');
  return (normalized.match(/(?:^|\/)\.\.(?=\/|$)/g) ?? []).length;
}

function loadBoundaryConfig(
  cwd: string,
  boundaryRel: string,
): { manifestFound: boolean; manifest?: HoloBoundaryManifest; error?: string } {
  const fullPath = resolve(cwd, boundaryRel);
  if (!existsSync(fullPath)) {
    return { manifestFound: false };
  }
  try {
    const parsed: unknown = JSON.parse(readFileSync(fullPath, 'utf8'));
    if (!parsed || typeof parsed !== 'object') {
      return { manifestFound: true, error: 'Boundary manifest must be a JSON object' };
    }
    const obj = parsed as Record<string, unknown>;
    if (obj.schema !== HOLO_BOUNDARY_SCHEMA) {
      return {
        manifestFound: true,
        error: `Unsupported boundary schema "${String(obj.schema)}" (expected "${HOLO_BOUNDARY_SCHEMA}")`,
      };
    }
    return { manifestFound: true, manifest: parsed as HoloBoundaryManifest };
  } catch (err) {
    return {
      manifestFound: true,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function evaluateAbiContract(
  cwd: string,
  manifest: HoloBoundaryManifest | undefined,
  configPath: string,
  violations: HoloCiBoundaryViolation[],
): number {
  const goldenFiles = manifest?.abiGoldenFiles ?? [];
  if (goldenFiles.length > 0) {
    let validCount = 0;
    for (const rel of goldenFiles) {
      const fullPath = resolve(cwd, rel);
      const normRel = rel.replace(/\\/g, '/');
      if (!existsSync(fullPath)) {
        violations.push({
          rule: 'abiGolden',
          file: normRel,
          line: 1,
          snippet: 'Missing ABI golden file',
          message: `Declared ABI golden file "${normRel}" does not exist`,
        });
        continue;
      }
      try {
        const parsed: unknown = JSON.parse(readFileSync(fullPath, 'utf8'));
        if (!parsed || typeof parsed !== 'object') {
          violations.push({
            rule: 'abiGolden',
            file: normRel,
            line: 1,
            snippet: 'Invalid ABI golden JSON root',
            message: `ABI golden file "${normRel}" must contain a JSON object or array`,
          });
          continue;
        }
        validCount++;
      } catch (err) {
        violations.push({
          rule: 'abiGolden',
          file: normRel,
          line: 1,
          snippet: 'Malformed JSON',
          message: `Failed to parse ABI golden file "${normRel}": ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
    return validCount === goldenFiles.length
      ? 20
      : Math.floor((20 * validCount) / goldenFiles.length);
  }

  const holoCiFullPath = resolve(cwd, configPath);
  if (existsSync(holoCiFullPath)) {
    try {
      const holoManifest = loadManifest(configPath, cwd);
      const guards = holoManifest.guards;
      if (guards && Object.values(guards).some((enabled) => enabled === true)) {
        const guardViolations = scanGuardViolations(cwd, guards);
        return guardViolations.length === 0 ? 20 : 0;
      }
    } catch {
      return 0;
    }
  }

  return 10;
}

function evaluateGovernance(cwd: string): number {
  const hasLicense = scanGuardViolations(cwd, { spdxLicense: true }).length === 0;
  const hasGitattributes = scanGuardViolations(cwd, { gitattributes: true }).length === 0;
  const hasCodeowners = scanGuardViolations(cwd, { codeowners: true }).length === 0;
  return (hasLicense ? 7 : 0) + (hasGitattributes ? 7 : 0) + (hasCodeowners ? 6 : 0);
}

export function runBoundaryAudit(options: RunBoundaryAuditOptions = {}): HoloCiBoundaryResult {
  const cwd = options.cwd ?? process.cwd();
  const boundaryRel = options.boundaryPath ?? 'boundary.json';
  const configPath = options.configPath ?? 'holo-ci.json';
  const violations: HoloCiBoundaryViolation[] = [];

  let manifestFound = false;
  let manifest: HoloBoundaryManifest | undefined;

  if (options.manifest) {
    manifestFound = true;
    manifest = options.manifest;
  } else {
    const loaded = loadBoundaryConfig(cwd, boundaryRel);
    manifestFound = loaded.manifestFound;
    manifest = loaded.manifest;
    if (loaded.error) {
      violations.push({
        rule: 'boundaryManifest',
        file: boundaryRel.replace(/\\/g, '/'),
        line: 1,
        snippet: boundaryRel,
        message: loaded.error,
      });
    }
  }

  const maxParentTraversals = manifest?.maxParentTraversals ?? 3;
  const scanSourceHttpIpc = manifest?.scanSourceHttpIpc ?? true;
  const forbiddenImports = manifest?.forbiddenImports ?? [];
  const allowedImports = manifest?.allowedImports ?? [];

  const sourceFiles = collectSourceFiles(cwd, manifest);
  let forbiddenCount = 0;
  let traversalCount = 0;
  let httpIpcCount = 0;

  for (const filePath of sourceFiles) {
    const relPath = relative(cwd, filePath).replace(/\\/g, '/');
    const lines = readFileSync(filePath, 'utf8').split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      if (lineText.includes('holo-ci-allow-guard')) continue;

      const specifiers = extractLineSpecifiers(lineText);
      for (const spec of specifiers) {
        const isExplicitlyAllowed = allowedImports.some((pat) => matchesImportPattern(spec, pat));
        if (isExplicitlyAllowed) continue;

        let matchedForbidden = false;
        for (const pattern of forbiddenImports) {
          if (matchesImportPattern(spec, pattern)) {
            matchedForbidden = true;
            forbiddenCount++;
            violations.push({
              rule: 'forbiddenImport',
              file: relPath,
              line: i + 1,
              snippet: lineText.trim().slice(0, 160),
              message: `Forbidden import/include "${spec}" matches pattern "${pattern}"`,
            });
            break;
          }
        }

        if (!matchedForbidden) {
          const traversals = countParentTraversals(spec);
          if (traversals > maxParentTraversals) {
            traversalCount++;
            violations.push({
              rule: 'parentTraversal',
              file: relPath,
              line: i + 1,
              snippet: lineText.trim().slice(0, 160),
              message: `Import "${spec}" traverses ${traversals} parent directories (max ${maxParentTraversals})`,
            });
          }
        }
      }

      if (scanSourceHttpIpc && HTTP_IPC_REGEX.test(lineText)) {
        httpIpcCount++;
        violations.push({
          rule: 'httpIpc',
          file: relPath,
          line: i + 1,
          snippet: lineText.trim().slice(0, 160),
          message: 'B8G016 violation: illegal loopback HTTP IPC binding in source file',
        });
      }
    }
  }

  const dependencyPurity = Math.max(0, 20 - (forbiddenCount * 5 + traversalCount * 5));
  const encapBase = manifestFound ? 20 : 12;
  const encapsulation = Math.max(0, encapBase - traversalCount * (manifestFound ? 5 : 4));
  const ipcCompliance = httpIpcCount === 0 ? 20 : 0;
  const abiContract = evaluateAbiContract(cwd, manifest, configPath, violations);
  const governance = evaluateGovernance(cwd);

  const axes: HoloCiBoundaryAxes = {
    dependencyPurity,
    encapsulation,
    ipcCompliance,
    abiContract,
    governance,
  };
  const score =
    axes.dependencyPurity +
    axes.encapsulation +
    axes.ipcCompliance +
    axes.abiContract +
    axes.governance;

  return {
    ok: violations.length === 0,
    score,
    manifestFound,
    ...(manifestFound ? { boundaryPath: boundaryRel.replace(/\\/g, '/') } : {}),
    ...(manifest?.plane !== undefined ? { plane: manifest.plane } : {}),
    scannedFiles: sourceFiles.length,
    axes,
    violations,
  };
}
