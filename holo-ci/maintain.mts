import { createHash, verify as cryptoVerify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type {
  HoloCiEndpointCheck,
  HoloCiEndpointResult,
  HoloCiMaintainResult,
  HoloCiManifest,
} from './schema.mts';

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export function verifySha512Digest(
  data: Buffer | Uint8Array | string,
  expectedSha512: string,
): { ok: boolean; actual: string } {
  const actual = createHash('sha512').update(data).digest('hex');
  return {
    ok: actual.toLowerCase() === expectedSha512.trim().toLowerCase(),
    actual,
  };
}

export function verifyEd25519Signature(
  data: Buffer | Uint8Array | string,
  publicKeyPem: string,
  signatureBase64: string,
): boolean {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  const sig = Buffer.from(signatureBase64.trim(), 'base64');
  return cryptoVerify(null, payload, publicKeyPem, sig);
}

export async function checkEndpoint(
  endpoint: HoloCiEndpointCheck,
  fetchFn: FetchLike = fetch,
): Promise<HoloCiEndpointResult> {
  const expectedStatus = endpoint.expectedStatus ?? 200;
  const label = endpoint.name ?? endpoint.url;
  try {
    const response = await fetchFn(endpoint.url);
    const bytesBuf = Buffer.from(await response.arrayBuffer());
    const shaActual = createHash('sha512').update(bytesBuf).digest('hex');

    let statusOk = response.status === expectedStatus;
    let sha512Verified: boolean | undefined;
    if (endpoint.sha512) {
      sha512Verified = shaActual.toLowerCase() === endpoint.sha512.trim().toLowerCase();
    }

    let ed25519Verified: boolean | undefined;
    const headerSig = response.headers.get('x-holo-signature-ed25519');
    const sigB64 = endpoint.signatureBase64 ?? headerSig ?? undefined;
    if (endpoint.publicKeyPem && sigB64) {
      try {
        ed25519Verified = verifyEd25519Signature(bytesBuf, endpoint.publicKeyPem, sigB64);
      } catch {
        ed25519Verified = false;
      }
    } else if (endpoint.publicKeyPem && !sigB64) {
      ed25519Verified = false;
    }

    const ok =
      statusOk &&
      (sha512Verified === undefined || sha512Verified) &&
      (ed25519Verified === undefined || ed25519Verified);

    return {
      name: label,
      url: endpoint.url,
      ok,
      status: response.status,
      expectedStatus,
      bytes: bytesBuf.byteLength,
      sha512Actual: shaActual,
      ...(sha512Verified !== undefined ? { sha512Verified } : {}),
      ...(ed25519Verified !== undefined ? { ed25519Verified } : {}),
    };
  } catch (err) {
    return {
      name: label,
      url: endpoint.url,
      ok: false,
      status: 0,
      expectedStatus,
      bytes: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export function verifyBundleManifest(
  cwd: string,
  sumsFile = 'SHA512SUMS.txt',
): { checked: number; mismatches: string[] } {
  const sumsPath = resolve(cwd, sumsFile);
  if (!existsSync(sumsPath)) {
    return { checked: 0, mismatches: [] };
  }
  const lines = readFileSync(sumsPath, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  let checked = 0;
  const mismatches: string[] = [];

  for (const line of lines) {
    const match = /^([0-9a-f]{128})\s+\*?(.+)$/i.exec(line);
    if (!match) {
      mismatches.push(`malformed-line:${line}`);
      continue;
    }
    const expected = match[1];
    const relPath = match[2].trim();
    const target = resolve(cwd, relPath);
    if (!existsSync(target)) {
      mismatches.push(`missing:${relPath}`);
      continue;
    }
    checked++;
    const check = verifySha512Digest(readFileSync(target), expected);
    if (!check.ok) {
      mismatches.push(`sha512-mismatch:${relPath}`);
    }
  }

  return { checked, mismatches };
}

export async function runMaintain(
  manifest: HoloCiManifest,
  options: { cwd?: string; fetchFn?: FetchLike; sumsFile?: string } = {},
): Promise<HoloCiMaintainResult> {
  const cwd = options.cwd ?? process.cwd();
  const fetchFn = options.fetchFn ?? fetch;
  const endpoints: HoloCiEndpointResult[] = [];

  for (const ep of manifest.endpoints ?? []) {
    endpoints.push(await checkEndpoint(ep, fetchFn));
  }

  const bundle = verifyBundleManifest(cwd, options.sumsFile ?? manifest.casRelease?.sumsPath ?? 'SHA512SUMS.txt');
  const ok = endpoints.every((e) => e.ok) && bundle.mismatches.length === 0;

  return {
    ok,
    endpoints,
    bundleChecked: bundle.checked,
    bundleMismatches: bundle.mismatches,
  };
}
