import assert from 'node:assert/strict';
import type { execFileSync } from 'node:child_process';
import { describe, it } from 'node:test';
import {
  GITHUB_API_VERSION,
  GithubApiError,
  createGithubClient,
  mapConcurrent,
  parseNextLinkHeader,
  resetGithubTokenCache,
  resolveGithubToken,
} from './gh-client.mts';

describe('holo-ci/gh-client.mts', () => {
  it('resolveGithubToken prioritizes GH_TOKEN > GITHUB_TOKEN and caches single CLI fallback', () => {
    resetGithubTokenCache();

    assert.equal(resolveGithubToken({ GH_TOKEN: '  gh-primary  ', GITHUB_TOKEN: 'gh-secondary' }), 'gh-primary');
    assert.equal(resolveGithubToken({ GITHUB_TOKEN: 'gh-secondary' }), 'gh-secondary');
    assert.equal(resolveGithubToken({}, { allowCliFallback: false }), undefined);

    let execCalls = 0;
    const mockExec = ((_cmd: string, args: string[], opts?: { shell?: unknown }) => {
      execCalls += 1;
      assert.equal(opts?.shell, false);
      assert.ok(args.includes('auth') && args.includes('token'));
      return 'cli-fallback-token\n';
    }) as unknown as typeof execFileSync;

    assert.equal(resolveGithubToken({}, { execFn: mockExec }), 'cli-fallback-token');
    assert.equal(execCalls, 1);

    // Non-token failure returns undefined gracefully
    const failingExec = (() => {
      throw new Error('gh not logged in');
    }) as unknown as typeof execFileSync;
    assert.equal(resolveGithubToken({}, { execFn: failingExec }), undefined);
  });

  it('sends standard GitHub REST auth/version headers and parses JSON & 204 responses', async () => {
    const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method ?? 'GET',
        headers: (init?.headers ?? {}) as Record<string, string>,
        body: typeof init?.body === 'string' ? init.body : undefined,
      });
      if (url.endsWith('/repos/awesome-os/holo-v11')) {
        return new Response(JSON.stringify({ full_name: 'awesome-os/holo-v11', private: false }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.endsWith('/repos/awesome-os/holo-v11/labels/old')) {
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    }) as typeof fetch;

    const client = createGithubClient({
      token: 'secret-pat-123',
      fetchImpl: mockFetch,
      baseRetryDelayMs: 1,
    });

    assert.equal(client.hasToken, true);
    const repo = await client.rest<{ full_name: string }>('GET', '/repos/awesome-os/holo-v11');
    assert.equal(repo.full_name, 'awesome-os/holo-v11');

    assert.equal(calls[0]!.headers.Authorization, 'Bearer secret-pat-123');
    assert.equal(calls[0]!.headers.Accept, 'application/vnd.github+json');
    assert.equal(calls[0]!.headers['X-GitHub-Api-Version'], GITHUB_API_VERSION);

    const deleted = await client.rest<undefined>('DELETE', '/repos/awesome-os/holo-v11/labels/old');
    assert.equal(deleted, undefined);

    await assert.rejects(
      () => client.rest('GET', '/repos/awesome-os/missing'),
      (err: unknown) => err instanceof GithubApiError && err.status === 404,
    );
  });

  it('restPaginate follows RFC 5988 Link rel="next" headers and respects maxPages', async () => {
    assert.equal(
      parseNextLinkHeader(
        '<https://api.github.com/orgs/awesome-os/repos?per_page=2&page=2>; rel="next", <https://api.github.com/orgs/awesome-os/repos?per_page=2&page=3>; rel="last"',
      ),
      'https://api.github.com/orgs/awesome-os/repos?per_page=2&page=2',
    );
    assert.equal(
      parseNextLinkHeader('<https://api.github.com/orgs/awesome-os/repos?page=1>; rel="prev"'),
      null,
    );

    const requestedUrls: string[] = [];
    const mockFetch = (async (input: string | URL | Request) => {
      const url = String(input);
      requestedUrls.push(url);
      const pageParam = new URL(url).searchParams.get('page');
      if (pageParam === '3') {
        return new Response(JSON.stringify([{ id: 5 }]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (pageParam === '2') {
        return new Response(JSON.stringify([{ id: 3 }, { id: 4 }]), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            link: '<https://api.github.com/orgs/awesome-os/repos?per_page=2&page=3>; rel="next"',
          },
        });
      }
      return new Response(JSON.stringify([{ id: 1 }, { id: 2 }]), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          link: '<https://api.github.com/orgs/awesome-os/repos?per_page=2&page=2>; rel="next"',
        },
      });
    }) as typeof fetch;

    const client = createGithubClient({ token: 'tok', fetchImpl: mockFetch });
    const allRepos = await client.restPaginate<{ id: number }>('/orgs/awesome-os/repos', { perPage: 2 });
    assert.deepEqual(
      allRepos.map((r) => r.id),
      [1, 2, 3, 4, 5],
    );
    assert.equal(requestedUrls.length, 3);
    assert.ok(requestedUrls[0]!.includes('per_page=2'));

    // Respect maxPages bound
    const capped = await client.restPaginate<{ id: number }>('/orgs/awesome-os/repos', {
      perPage: 2,
      maxPages: 2,
    });
    assert.deepEqual(
      capped.map((r) => r.id),
      [1, 2, 3, 4],
    );
  });

  it('retries 429 (with Retry-After) and 5xx exponentially, without retrying 404', async () => {
    const sleepDurations: number[] = [];
    let attempt = 0;
    const mockFetch = (async () => {
      attempt += 1;
      if (attempt === 1) {
        return new Response('rate limited', {
          status: 429,
          headers: { 'retry-after': '2' },
        });
      }
      if (attempt === 2) {
        return new Response('bad gateway', { status: 502 });
      }
      if (attempt === 3) {
        return new Response('service unavailable', { status: 503 });
      }
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    const client = createGithubClient({
      token: 'tok',
      fetchImpl: mockFetch,
      maxRetries: 3,
      baseRetryDelayMs: 100,
      sleepImpl: async (ms) => {
        sleepDurations.push(ms);
      },
    });

    const data = await client.rest<{ ok: boolean }>('GET', '/rate_limit');
    assert.equal(data.ok, true);
    assert.equal(attempt, 4);
    // 1st retry uses Retry-After: 2 -> 2000ms; 2nd uses 100*2^1=200ms; 3rd uses 100*2^2=400ms
    assert.deepEqual(sleepDurations, [2000, 200, 400]);

    // Exhausted retries should throw GithubApiError
    let failCalls = 0;
    const always500 = (async () => {
      failCalls += 1;
      return new Response('internal error', { status: 500 });
    }) as typeof fetch;
    const strictClient = createGithubClient({
      token: 'tok',
      fetchImpl: always500,
      maxRetries: 2,
      baseRetryDelayMs: 1,
      sleepImpl: async () => {},
    });
    await assert.rejects(
      () => strictClient.rest('GET', '/broken'),
      (err: unknown) => err instanceof GithubApiError && err.status === 500,
    );
    assert.equal(failCalls, 3);
  });

  it('graphql posts query + variables and throws clear GithubApiError when errors[] is present', async () => {
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      assert.equal(String(input), 'https://api.github.com/graphql');
      assert.equal(init?.method, 'POST');
      const body = JSON.parse(String(init?.body)) as { query: string; variables?: { org?: string } };
      if (body.variables?.org === 'bad-org') {
        return new Response(
          JSON.stringify({
            data: null,
            errors: [
              { message: 'Could not resolve to an Organization with the login of bad-org.', type: 'NOT_FOUND' },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          data: { organization: { name: 'Awesome-OS', repositories: { totalCount: 17 } } },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    const client = createGithubClient({ token: 'tok', fetchImpl: mockFetch });
    const res = await client.graphql<{ organization: { name: string; repositories: { totalCount: number } } }>(
      'query($org: String!) { organization(login: $org) { name repositories { totalCount } } }',
      { org: 'awesome-os' },
    );
    assert.equal(res.organization.name, 'Awesome-OS');
    assert.equal(res.organization.repositories.totalCount, 17);

    await assert.rejects(
      () => client.graphql('query($org: String!) { organization(login: $org) { name } }', { org: 'bad-org' }),
      (err: unknown) =>
        err instanceof GithubApiError &&
        /Could not resolve to an Organization/.test(err.message) &&
        err.graphqlErrors?.length === 1,
    );
  });

  it('mapConcurrent and client maxConcurrency strictly bound in-flight parallelism while preserving order', async () => {
    let active = 0;
    let peak = 0;
    const inputs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    const outputs = await mapConcurrent(
      inputs,
      async (n) => {
        active += 1;
        if (active > peak) peak = active;
        await new Promise((r) => setTimeout(r, (11 - n) * 2));
        active -= 1;
        return n * 10;
      },
      3,
    );

    assert.equal(peak, 3);
    assert.deepEqual(outputs, [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
    assert.deepEqual(await mapConcurrent([], async (x) => x, 4), []);

    // Also verify createGithubClient enforces maxConcurrency across simultaneous rest() calls
    let inflightFetch = 0;
    let peakFetch = 0;
    const throttledFetch = (async (input: string | URL | Request) => {
      inflightFetch += 1;
      if (inflightFetch > peakFetch) peakFetch = inflightFetch;
      await new Promise((r) => setTimeout(r, 5));
      inflightFetch -= 1;
      return new Response(JSON.stringify({ url: String(input) }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    const client = createGithubClient({
      token: 'tok',
      fetchImpl: throttledFetch,
      maxConcurrency: 2,
    });

    const parallel = await Promise.all(
      [1, 2, 3, 4, 5, 6].map((i) => client.rest<{ url: string }>('GET', `/items/${i}`)),
    );
    assert.equal(peakFetch, 2);
    assert.equal(parallel.length, 6);
  });
});
