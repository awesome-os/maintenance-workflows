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
import { checkRepoGovernance, scanGuardViolations } from './verify.mts';

export { HOLO_BOUNDARY_SCHEMA, type HoloBoundaryManifest };

const LOCALHOST_HTTP_PREFIX = ['http', '://'].join('');
export const HTTP_IPC_REGEX = new RegExp(`${LOCALHOST_HTTP_PREFIX}(?:127\\.0\\.0\\.1|localhost)(?::\\d+)?`, 'i');

export const DEFAULT_HTTP_IPC_ALLOW_MARKERS = ['b8g-allow-http-ipc', 'holo-ci-allow-guard'] as const;

export interface HttpIpcScanMatch {
  file: string;
  line: number;
  match: string;
  snippet: string;
}

export interface ScanHttpIpcOptions {
  allowMarkers?: readonly string[];
}

const HASH_COMMENT_FILE_REGEX = /\.(?:ya?ml|sh|bash|zsh|ps1|py|rb|toml|ini|conf|cfg|env)$/i;
const SLASH_COMMENT_FILE_REGEX = /\.(?:mts|ts|tsx|cts|mjs|js|jsx|cjs|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|go|java|kt|cs|zig)$/i;
const REGEX_DEF_LINE_REGEX = /\bnew\s+RegExp\s*\(/;

function hasAnyAllowMarker(text: string, allowMarkers: readonly string[]): boolean {
  for (const marker of allowMarkers) {
    if (marker.length > 0 && text.includes(marker)) return true;
  }
  return false;
}

function isCommentOnlyAllowLine(prevLine: string, allowMarkers: readonly string[]): boolean {
  const trimmed = prevLine.trim();
  if (
    !trimmed.startsWith('//') &&
    !trimmed.startsWith('/*') &&
    !trimmed.startsWith('*') &&
    !trimmed.startsWith('#')
  ) {
    return false;
  }
  return hasAnyAllowMarker(prevLine, allowMarkers);
}

function stripCommentsFromLine(
  line: string,
  state: { inBlockComment: boolean },
  supportsSlashComments: boolean,
  supportsHashComments: boolean,
): string {
  let out = '';
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;

  while (i < line.length) {
    const ch = line[i]!;
    const next = line[i + 1];

    if (state.inBlockComment) {
      if (ch === '*' && next === '/') {
        state.inBlockComment = false;
        i += 2;
      } else {
        i += 1;
      }
      continue;
    }

    if (inSingle) {
      out += ch;
      if (ch === '\\' && next !== undefined) {
        out += next;
        i += 2;
        continue;
      }
      if (ch === "'") inSingle = false;
      i += 1;
      continue;
    }

    if (inDouble) {
      out += ch;
      if (ch === '\\' && next !== undefined) {
        out += next;
        i += 2;
        continue;
      }
      if (ch === '"') inDouble = false;
      i += 1;
      continue;
    }

    if (inTemplate) {
      out += ch;
      if (ch === '\\' && next !== undefined) {
        out += next;
        i += 2;
        continue;
      }
      if (ch === '`') inTemplate = false;
      i += 1;
      continue;
    }

    if (supportsSlashComments && ch === '/' && next === '*') {
      state.inBlockComment = true;
      i += 2;
      continue;
    }

    if (supportsSlashComments && ch === '/' && next === '/' && (i === 0 || line[i - 1] !== ':')) {
      break;
    }

    if (supportsHashComments && ch === '#' && (i === 0 || /\s/.test(line[i - 1]!))) {
      break;
    }

    if (ch === "'") {
      inSingle = true;
    } else if (ch === '"') {
      inDouble = true;
    } else if (supportsSlashComments && ch === '`') {
      inTemplate = true;
    }

    out += ch;
    i += 1;
  }

  return out;
}

/**
 * Canonical `B8G016` loopback HTTP IPC scanner across Awesome-OS.
 * Respects inline and preceding-comment allow markers (`b8g-allow-http-ipc`, `holo-ci-allow-guard`)
 * and skips pure comments and regex definitions cleanly.
 */
export function scanHttpIpcSource(
  content: string,
  filePath: string,
  options: ScanHttpIpcOptions = {},
): HttpIpcScanMatch[] {
  const allowMarkers = options.allowMarkers ?? DEFAULT_HTTP_IPC_ALLOW_MARKERS;
  const normalizedFile = filePath.replace(/\\/g, '/');
  const supportsHashComments = HASH_COMMENT_FILE_REGEX.test(normalizedFile);
  const supportsSlashComments = !supportsHashComments && (SLASH_COMMENT_FILE_REGEX.test(normalizedFile) || !normalizedFile.includes('.'));
  const lines = content.split(/\r?\n/);
  const matches: HttpIpcScanMatch[] = [];
  const commentState = { inBlockComment: false };

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i]!;
    const prevLine = i > 0 ? lines[i - 1]! : '';

    // Always advance block comment state even for allowlisted lines
    const stripped = stripCommentsFromLine(lineText, commentState, supportsSlashComments, supportsHashComments);
    const trimmedCode = stripped.trim();
    if (trimmedCode.length === 0) continue;

    if (hasAnyAllowMarker(lineText, allowMarkers) || isCommentOnlyAllowLine(prevLine, allowMarkers)) {
      continue;
    }

    if (REGEX_DEF_LINE_REGEX.test(trimmedCode)) {
      continue;
    }

    const hit = HTTP_IPC_REGEX.exec(stripped);
    if (hit) {
      matches.push({
        file: normalizedFile,
        line: i + 1,
        match: hit[0],
        snippet: lineText.trim().slice(0, 160),
      });
    }
  }

  return matches;
}

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
      return normalized === pattern;
    }
  }

  if (/[\^$*+?()[\]{}|\\]/.test(pattern)) {
    try {
      return new RegExp(pattern).test(normalized);
    } catch {
      return false;
    }
  }

  const normPat = pattern.replace(/\\/g, '/');
  if (normalized === normPat) return true;
  if (normPat.endsWith('/')) {
    return normalized.includes(normPat);
  }
  const escaped = normPat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|/|\\\\)${escaped}(?:$|/|\\\\)`).test(normalized);
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
        const goldenObj = parsed as { header?: unknown };
        if (typeof goldenObj.header === 'string' && goldenObj.header.trim().length > 0) {
          const headerRel = goldenObj.header.trim();
          const headerFull = resolve(cwd, headerRel);
          const headerRelativeToManifest = resolve(fullPath, '..', headerRel);
          const headerProjectedSibling =
            headerRel.includes('/') || headerRel.includes('\\')
              ? resolve(fullPath, '..', basename(headerRel))
              : headerRelativeToManifest;
          if (
            !existsSync(headerFull) &&
            !existsSync(headerRelativeToManifest) &&
            !existsSync(headerProjectedSibling)
          ) {
            violations.push({
              rule: 'abiGolden',
              file: normRel,
              line: 1,
              snippet: `header: ${headerRel}`,
              message: `ABI golden file "${normRel}" references missing header "${headerRel}"`,
            });
            continue;
          }
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
  const gov = checkRepoGovernance(cwd, {
    spdxLicense: true,
    gitattributes: true,
    codeowners: true,
    noBrokenBadges: false,
  });
  return (gov.checks.spdxLicense ? 7 : 0) + (gov.checks.gitattributes ? 7 : 0) + (gov.checks.codeowners ? 6 : 0);
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
  const enforceDag = manifest?.enforceDag === true;
  const enforceLayers = manifest?.enforceLayers === true;
  const layerRules = manifest?.layerRules ?? [];
  const allowedGeometryEdges = new Set(manifest?.allowedGeometryEdges ?? []);

  const sourceFiles = collectSourceFiles(cwd, manifest);
  let forbiddenCount = 0;
  let traversalCount = 0;
  let httpIpcCount = 0;
  let geometryViolations = 0;

  const unitOfRel = (relPath: string): string => {
    const parts = relPath.split('/');
    if (parts[0] === 'packages' && parts[1] === '@awesome-os' && parts[2]) {
      return `packages/@awesome-os/${parts[2]}`;
    }
    if ((parts[0] === 'sections' || parts[0] === 'intersections' || parts[0] === 'packages') && parts[1]) {
      return `${parts[0]}/${parts[1]}`;
    }
    return parts[0] ?? 'root';
  };
  const rankOfUnit = (unit: string): number | undefined => {
    for (const r of layerRules) {
      if (unit === r.prefix || unit.startsWith(`${r.prefix}/`) || unit.startsWith(r.prefix)) {
        return r.rank;
      }
    }
    return undefined;
  };
  const runtimeAdj = new Map<string, Set<string>>();

  for (const filePath of sourceFiles) {
    const relPath = relative(cwd, filePath).replace(/\\/g, '/');
    const content = readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const srcUnit = unitOfRel(relPath);
    if (!runtimeAdj.has(srcUnit)) runtimeAdj.set(srcUnit, new Set());
    const isHostFile =
      relPath.startsWith('scripts/') ||
      /\.host\.(mts|ts|mjs|js)$/.test(relPath) ||
      /\/(?:cli|server|maintenance)\.(mts|ts)$/.test(relPath);

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const prevLine = i > 0 ? lines[i - 1] : '';
      const hasLineAllowGuard =
        lineText.includes('holo-ci-allow-guard') ||
        lineText.includes('b8g-allow-http-ipc') ||
        ((prevLine.trim().startsWith('//') || prevLine.trim().startsWith('*')) &&
          (prevLine.includes('holo-ci-allow-guard') || prevLine.includes('b8g-allow-http-ipc')));
      if (hasLineAllowGuard) continue;

      const specifiers = extractLineSpecifiers(lineText);
      const isTypeOnlyImport = /^\s*(?:import|export)\s+type\b/.test(lineText);
      for (const spec of specifiers) {
        if ((enforceDag || enforceLayers) && spec.startsWith('.') && !isTypeOnlyImport && !isHostFile) {
          const targetAbs = resolve(filePath, '..', spec);
          const dstRel = relative(cwd, targetAbs).replace(/\\/g, '/');
          const dstUnit = unitOfRel(dstRel);
          if (dstUnit !== srcUnit && !dstRel.startsWith('..')) {
            runtimeAdj.get(srcUnit)!.add(dstUnit);
            const edgeKey = `${srcUnit} -> ${dstUnit}`;
            if (enforceLayers && !allowedGeometryEdges.has(edgeKey)) {
              const srcRank = rankOfUnit(srcUnit);
              const dstRank = rankOfUnit(dstUnit);
              if (srcRank !== undefined && dstRank !== undefined && srcRank < dstRank) {
                geometryViolations++;
                violations.push({
                  rule: 'layerInversion',
                  file: relPath,
                  line: i + 1,
                  snippet: lineText.trim().slice(0, 160),
                  message: `Layer inversion (${edgeKey}): rank ${srcRank} cannot depend upward on rank ${dstRank}`,
                });
              }
            }
          }
        }

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
    }

    if (scanSourceHttpIpc) {
      for (const hit of scanHttpIpcSource(content, relPath)) {
        httpIpcCount++;
        violations.push({
          rule: 'httpIpc',
          file: hit.file,
          line: hit.line,
          snippet: hit.snippet,
          message: 'B8G016 violation: illegal loopback HTTP IPC binding in source file',
        });
      }
    }
  }

  if (enforceDag) {
    let idx = 0;
    const indices = new Map<string, number>();
    const lowlink = new Map<string, number>();
    const stack: string[] = [];
    const onStack = new Set<string>();
    const sc = (v: string): void => {
      indices.set(v, idx);
      lowlink.set(v, idx);
      idx++;
      stack.push(v);
      onStack.add(v);
      for (const w of runtimeAdj.get(v) ?? []) {
        if (!indices.has(w)) {
          sc(w);
          lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
        } else if (onStack.has(w)) {
          lowlink.set(v, Math.min(lowlink.get(v)!, indices.get(w)!));
        }
      }
      if (lowlink.get(v) === indices.get(v)) {
        const scc: string[] = [];
        while (true) {
          const w = stack.pop()!;
          onStack.delete(w);
          scc.push(w);
          if (w === v) break;
        }
        if (scc.length > 1) {
          scc.sort();
          const sccSet = new Set(scc);
          const unallowlisted = scc.some((u) =>
            [...(runtimeAdj.get(u) ?? [])].some((w) => sccSet.has(w) && !allowedGeometryEdges.has(`${u} -> ${w}`)),
          );
          if (unallowlisted) {
            geometryViolations++;
            violations.push({
              rule: 'cyclicImport',
              file: scc[0]!,
              line: 1,
              snippet: scc.join(' <-> '),
              message: `Strongly connected import cycle detected (${scc.length} units): [${scc.join(', ')}]`,
            });
          }
        }
      }
    };
    for (const u of [...runtimeAdj.keys()].sort()) {
      if (!indices.has(u)) sc(u);
    }
  }

  const dependencyPurity = Math.max(0, 20 - (forbiddenCount * 5 + traversalCount * 5 + geometryViolations * 5));
  const encapBase = manifestFound ? 20 : 12;
  const encapsulation = Math.max(0, encapBase - (traversalCount + geometryViolations) * (manifestFound ? 5 : 4));
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
