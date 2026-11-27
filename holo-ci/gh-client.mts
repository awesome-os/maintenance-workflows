/**
 * @file holo-ci/gh-client.mts
 * @description Cloud-first zero-subprocess GitHub REST + GraphQL API client for Awesome-OS.
 *
 * Replaces duplicated `execFile('gh', ...)` loops across the org with native `fetch`
 * (automatic 429/5xx exponential backoff with `Retry-After` support, `Link` pagination,
 * GraphQL error surfacing, and bounded concurrency fan-out).
 *
 * Strictly `erasableSyntaxOnly: true`, Node built-ins only, `shell: false`.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export const DEFAULT_GITHUB_API_BASE = 'https://api.github.com' as const;
export const GITHUB_API_VERSION = '2022-11-28' as const;
export const DEFAULT_GITHUB_USER_AGENT = 'holo-ci/1.4' as const;

export interface GithubGraphqlError {
  readonly message: string;
  readonly type?: string;
  readonly path?: readonly (string | number)[];
}

export class GithubApiError extends Error {
  readonly status: number;
  readonly method: string;
  readonly url: string;
  readonly body?: string;
  readonly graphqlErrors?: readonly GithubGraphqlError[];

  constructor(
    message: string,
    details: {
      status: number;
      method: string;
      url: string;
      body?: string;
      graphqlErrors?: readonly GithubGraphqlError[];
    },
  ) {
    super(message);
    this.name = 'GithubApiError';
    this.status = details.status;
    this.method = details.method;
    this.url = details.url;
    if (details.body !== undefined) this.body = details.body;
    if (details.graphqlErrors !== undefined) this.graphqlErrors = details.graphqlErrors;
  }
}

export interface ResolveGithubTokenOptions {
  readonly allowCliFallback?: boolean;
  readonly cwd?: string;
  readonly execFn?: typeof execFileSync;
  readonly bypassCache?: boolean;
}

export interface GithubClientOptions {
  readonly token?: string;
  readonly apiBase?: string;
  readonly fetchImpl?: typeof fetch;
  readonly maxRetries?: number;
  readonly maxConcurrency?: number;
  readonly baseRetryDelayMs?: number;
  readonly maxRetryDelayMs?: number;
  readonly userAgent?: string;
  readonly allowCliTokenFallback?: boolean;
  readonly env?: Record<string, string | undefined>;
  readonly sleepImpl?: (ms: number) => Promise<void>;
}

export interface RestPaginateOptions {
  readonly perPage?: number;
  readonly maxPages?: number;
}

export interface GithubClient {
  readonly apiBase: string;
  readonly hasToken: boolean;
  rest<T = unknown>(method: string, path: string, body?: unknown): Promise<T>;
  restPaginate<T = unknown>(path: string, options?: RestPaginateOptions): Promise<T[]>;
  graphql<T = unknown>(query: string, variables?: Record<string, unknown>): Promise<T>;
  mapConcurrent<T, R>(
    items: readonly T[],
    fn: (item: T, index: number) => Promise<R>,
    concurrency?: number,
  ): Promise<R[]>;
}

let cachedCliToken: string | null | undefined;

/**
 * Resets the cached `gh auth token` fallback value (primarily for hermetic tests).
 */
export function resetGithubTokenCache(): void {
  cachedCliToken = undefined;
}

function findNearestBinDir(startCwd: string): string | null {
  let current = resolve(startCwd);
  for (let depth = 0; depth < 6; depth++) {
    const candidate = join(current, 'bin');
    if (
      existsSync(join(candidate, 'b8g-shim.exe')) ||
      existsSync(join(candidate, 'gh.ps1')) ||
      existsSync(join(candidate, 'gh'))
    ) {
      return candidate;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function probeGhAuthToken(
  cwd: string,
  execFn: typeof execFileSync,
): string | undefined {
  const isWin = process.platform === 'win32';
  const binDir = findNearestBinDir(cwd);
  const candidates: Array<{ cmd: string; args: string[] }> = [];

  if (binDir) {
    const b8gShimExe = join(binDir, 'b8g-shim.exe');
    const ghPs1 = join(binDir, 'gh.ps1');
    const ghPosix = join(binDir, 'gh');
    if (isWin && existsSync(b8gShimExe)) {
      candidates.push({ cmd: b8gShimExe, args: ['gh', 'auth', 'token'] });
    }
    if (isWin && existsSync(ghPs1)) {
      candidates.push({
        cmd: 'pwsh',
        args: ['-NoProfile', '-NonInteractive', '-File', ghPs1, 'auth', 'token'],
      });
    }
    if (!isWin && existsSync(ghPosix)) {
      candidates.push({ cmd: ghPosix, args: ['auth', 'token'] });
    }
  }

  candidates.push({ cmd: 'gh', args: ['auth', 'token'] });

  for (const candidate of candidates) {
    try {
      const out = execFn(candidate.cmd, candidate.args, {
        encoding: 'utf8',
        shell: false,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
      });
      const token = String(out ?? '').trim();
      if (token.length > 0) {
        return token;
      }
    } catch {
      // Try next candidate
    }
  }

  return undefined;
}

/**
 * Resolves a GitHub token from `GH_TOKEN`, `GITHUB_TOKEN`, or a cached one-time `gh auth token`
 * fallback (`b8g-shim.exe gh`, `bin/gh.ps1`, or `gh`).
 */
export function resolveGithubToken(
  env: Record<string, string | undefined> = process.env,
  options: ResolveGithubTokenOptions = {},
): string | undefined {
  const ghToken = env.GH_TOKEN?.trim();
  if (ghToken && ghToken.length > 0) return ghToken;

  const githubToken = env.GITHUB_TOKEN?.trim();
  if (githubToken && githubToken.length > 0) return githubToken;

  if (options.allowCliFallback === false) {
    return undefined;
  }

  const useCache = !options.bypassCache && !options.execFn;
  if (useCache && cachedCliToken !== undefined) {
    return cachedCliToken ?? undefined;
  }

  const resolved = probeGhAuthToken(options.cwd ?? process.cwd(), options.execFn ?? execFileSync);
  if (useCache) {
    cachedCliToken = resolved ?? null;
  }
  return resolved;
}

/**
 * Parses the RFC 5988 `Link` response header and returns the URL for `rel="next"`, if present.
 */
export function parseNextLinkHeader(linkHeader: string | null | undefined): string | null {
  if (!linkHeader) return null;
  const parts = linkHeader.split(',');
  for (const part of parts) {
    const match = /<([^>]+)>[^,]*;\s*rel=["']?next["']?/i.exec(part.trim());
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}

/**
 * Runs an async mapper over `items` with bounded concurrency while preserving output order.
 */
export async function mapConcurrent<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<R>,
  concurrency = 4,
): Promise<R[]> {
  if (items.length === 0) return [];
  const limit = Math.max(1, Math.floor(Number.isFinite(concurrency) ? concurrency : 4));
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      const idx = nextIndex++;
      if (idx >= items.length) return;
      results[idx] = await fn(items[idx]!, idx);
    }
  };

  const workers: Promise<void>[] = [];
  const workerCount = Math.min(limit, items.length);
  for (let i = 0; i < workerCount; i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, ms);
  });
}

function parseRetryAfterMs(headerValue: string | null): number | null {
  if (!headerValue) return null;
  const trimmed = headerValue.trim();
  if (!trimmed) return null;
  const numericSeconds = Number(trimmed);
  if (Number.isFinite(numericSeconds) && numericSeconds >= 0) {
    return Math.round(numericSeconds * 1000);
  }
  const dateMs = Date.parse(trimmed);
  if (Number.isFinite(dateMs)) {
    return Math.max(0, dateMs - Date.now());
  }
  return null;
}

function isRetriableStatus(status: number, headers: Headers): boolean {
  if (status === 429) return true;
  if (status >= 500 && status <= 599) return true;
  if (status === 403 && headers.get('retry-after') !== null) return true;
  return false;
}

function createSemaphore(maxConcurrency: number): {
  run<T>(task: () => Promise<T>): Promise<T>;
} {
  const limit = Math.max(1, Math.floor(maxConcurrency));
  let active = 0;
  const queue: Array<() => void> = [];

  const acquire = async (): Promise<void> => {
    if (active < limit) {
      active += 1;
      return;
    }
    await new Promise<void>((resolveWait) => {
      queue.push(resolveWait);
    });
    active += 1;
  };

  const release = (): void => {
    active -= 1;
    const next = queue.shift();
    if (next) next();
  };

  return {
    async run<T>(task: () => Promise<T>): Promise<T> {
      await acquire();
      try {
        return await task();
      } finally {
        release();
      }
    },
  };
}

function appendPerPageQuery(path: string, perPage: number): string {
  const qIdx = path.indexOf('?');
  if (qIdx === -1) {
    return `${path}?per_page=${perPage}`;
  }
  const query = path.slice(qIdx + 1);
  if (/(?:^|&)per_page=/.test(query)) {
    return path;
  }
  return query.length > 0 ? `${path}&per_page=${perPage}` : `${path}per_page=${perPage}`;
}

/**
 * Creates a reusable cloud-first GitHub REST & GraphQL client with retry, pagination,
 * and concurrency control.
 */
export function createGithubClient(options: GithubClientOptions = {}): GithubClient {
  const apiBase = (options.apiBase ?? DEFAULT_GITHUB_API_BASE).replace(/\/+$/, '');
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxRetries =
    typeof options.maxRetries === 'number' && Number.isInteger(options.maxRetries) && options.maxRetries >= 0
      ? options.maxRetries
      : 3;
  const maxConcurrency =
    typeof options.maxConcurrency === 'number' && Number.isFinite(options.maxConcurrency) && options.maxConcurrency >= 1
      ? Math.floor(options.maxConcurrency)
      : 4;
  const baseRetryDelayMs =
    typeof options.baseRetryDelayMs === 'number' && options.baseRetryDelayMs >= 0
      ? options.baseRetryDelayMs
      : 250;
  const maxRetryDelayMs =
    typeof options.maxRetryDelayMs === 'number' && options.maxRetryDelayMs >= 0
      ? options.maxRetryDelayMs
      : 60_000;
  const userAgent = options.userAgent ?? DEFAULT_GITHUB_USER_AGENT;
  const sleepImpl = options.sleepImpl ?? defaultSleep;

  const resolvedToken =
    options.token !== undefined
      ? options.token.trim() || undefined
      : resolveGithubToken(options.env, { allowCliFallback: options.allowCliTokenFallback });

  const semaphore = createSemaphore(maxConcurrency);

  const buildUrl = (path: string): string => {
    if (/^https?:\/\//i.test(path)) return path;
    return `${apiBase}${path.startsWith('/') ? path : `/${path}`}`;
  };

  const buildHeaders = (hasBody: boolean): Record<string, string> => {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': GITHUB_API_VERSION,
      'User-Agent': userAgent,
    };
    if (resolvedToken) {
      headers.Authorization = `Bearer ${resolvedToken}`;
    }
    if (hasBody) {
      headers['Content-Type'] = 'application/json';
    }
    return headers;
  };

  const requestWithRetry = async (
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ response: Response; url: string }> => {
    const upperMethod = method.toUpperCase();
    const url = buildUrl(path);
    const hasBody = body !== undefined;
    const init: RequestInit = {
      method: upperMethod,
      headers: buildHeaders(hasBody),
      ...(hasBody ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}),
    };

    return semaphore.run(async () => {
      let attempt = 0;
      while (true) {
        let response: Response;
        try {
          response = await fetchImpl(url, init);
        } catch (err) {
          if (attempt >= maxRetries) {
            throw err;
          }
          const delayMs = Math.min(maxRetryDelayMs, baseRetryDelayMs * 2 ** attempt);
          attempt += 1;
          await sleepImpl(delayMs);
          continue;
        }

        if (response.ok) {
          return { response, url };
        }

        if (attempt < maxRetries && isRetriableStatus(response.status, response.headers)) {
          const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after'));
          const expDelayMs = baseRetryDelayMs * 2 ** attempt;
          const delayMs = Math.min(maxRetryDelayMs, retryAfterMs !== null ? retryAfterMs : expDelayMs);
          attempt += 1;
          await sleepImpl(delayMs);
          continue;
        }

        const errorText = await response.text().catch(() => '');
        throw new GithubApiError(
          `GitHub API ${upperMethod} ${url} failed with HTTP ${response.status}${errorText ? `: ${errorText.slice(0, 240)}` : ''}`,
          {
            status: response.status,
            method: upperMethod,
            url,
            body: errorText,
          },
        );
      }
    });
  };

  const parseResponseBody = async <T>(response: Response): Promise<T> => {
    if (response.status === 204) {
      return undefined as T;
    }
    const text = await response.text();
    if (text.trim().length === 0) {
      return undefined as T;
    }
    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('json') || /^[\s]*[{["0-9tfn-]/.test(text)) {
      return JSON.parse(text) as T;
    }
    return text as unknown as T;
  };

  return {
    apiBase,
    hasToken: Boolean(resolvedToken),

    async rest<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
      const { response } = await requestWithRetry(method, path, body);
      return parseResponseBody<T>(response);
    },

    async restPaginate<T = unknown>(path: string, paginateOpts: RestPaginateOptions = {}): Promise<T[]> {
      const perPage =
        typeof paginateOpts.perPage === 'number' && paginateOpts.perPage > 0
          ? Math.min(100, Math.floor(paginateOpts.perPage))
          : 100;
      const maxPages =
        typeof paginateOpts.maxPages === 'number' && paginateOpts.maxPages > 0
          ? Math.floor(paginateOpts.maxPages)
          : 100;

      const results: T[] = [];
      let nextPath: string | null = appendPerPageQuery(path, perPage);
      let pagesFetched = 0;

      while (nextPath && pagesFetched < maxPages) {
        const { response } = await requestWithRetry('GET', nextPath);
        pagesFetched += 1;

        const payload = await parseResponseBody<unknown>(response);
        if (Array.isArray(payload)) {
          results.push(...(payload as T[]));
        } else if (
          payload &&
          typeof payload === 'object' &&
          Array.isArray((payload as { items?: unknown }).items)
        ) {
          results.push(...((payload as { items: T[] }).items));
        } else if (payload !== undefined) {
          results.push(payload as T);
        }

        nextPath = parseNextLinkHeader(response.headers.get('link'));
      }

      return results;
    },

    async graphql<T = unknown>(query: string, variables?: Record<string, unknown>): Promise<T> {
      const { response, url } = await requestWithRetry('POST', '/graphql', {
        query,
        ...(variables ? { variables } : {}),
      });
      const payload = await parseResponseBody<{
        data?: T;
        errors?: GithubGraphqlError[];
      }>(response);

      if (payload && Array.isArray(payload.errors) && payload.errors.length > 0) {
        const summary = payload.errors.map((e) => e.message).join('; ');
        throw new GithubApiError(`GitHub GraphQL error: ${summary}`, {
          status: response.status,
          method: 'POST',
          url,
          graphqlErrors: payload.errors,
        });
      }

      return payload?.data as T;
    },

    mapConcurrent<T, R>(
      items: readonly T[],
      fn: (item: T, index: number) => Promise<R>,
      concurrency = maxConcurrency,
    ): Promise<R[]> {
      return mapConcurrent(items, fn, concurrency);
    },
  };
}
