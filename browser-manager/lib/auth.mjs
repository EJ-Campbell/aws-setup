import { createRemoteJWKSet, jwtVerify } from 'jose';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export function readConfig(env = process.env) {
  const baseUrl = new URL(env.BM_BASE_URL || 'https://browsers.cc-games.dev');
  const issuer = new URL(env.BM_ACCESS_ISSUER || 'https://ejc3.cloudflareaccess.com');
  const audience = env.BM_ACCESS_AUD || '';
  const owner = (env.BM_OWNER_EMAIL || 'ej.campbell@gmail.com').toLowerCase();
  const port = Number(env.BM_PORT || 3210);
  if (baseUrl.protocol !== 'https:' || baseUrl.pathname !== '/' || baseUrl.search ||
      baseUrl.hash || baseUrl.username || baseUrl.password ||
      issuer.protocol !== 'https:' || !issuer.hostname.endsWith('.cloudflareaccess.com') ||
      issuer.pathname !== '/' || issuer.search || issuer.hash || issuer.username || issuer.password ||
      !audience || !owner.includes('@') || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Set BM_BASE_URL, BM_ACCESS_AUD, BM_ACCESS_ISSUER, and BM_OWNER_EMAIL to the Terraform outputs');
  }
  return { baseUrl: baseUrl.origin, issuer: issuer.origin, audience, owner, port };
}

/** Trust the signed identity, never the unverified email header. No token/session cache. */
export function createAuthorizer(config, key = createRemoteJWKSet(
  new URL(`${config.issuer}/cdn-cgi/access/certs`), { timeoutDuration: 5000 },
)) {
  return async (request) => {
    const token = request.headers['cf-access-jwt-assertion'];
    if (typeof token !== 'string' || token.length > 16384) throw new HttpError(401, 'Sign in through Cloudflare Access');
    try {
      const { payload } = await jwtVerify(token, key, {
        issuer: config.issuer, audience: config.audience, algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub', 'email'],
      });
      if (typeof payload.email !== 'string' || payload.email.toLowerCase() !== config.owner) throw new Error('owner mismatch');
      return { expiresAt: payload.exp * 1000 };
    } catch {
      throw new HttpError(403, 'Cloudflare Access session is invalid or expired');
    }
  };
}

export function requireOrigin(request, baseUrl) {
  if (request.headers.origin !== baseUrl) throw new HttpError(403, 'Request origin is not allowed');
}

export function instanceName(value) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(value)) {
    throw new HttpError(400, 'Use a name of 1–48 lowercase letters, numbers, or hyphens');
  }
  return value;
}

export function startUrl(value) {
  if (value === undefined) return undefined;
  try {
    if (typeof value !== 'string' || value.length > 2048) throw new Error();
    const url = new URL(value);
    if (!['http:', 'https:', 'about:'].includes(url.protocol) || url.username || url.password ||
        (url.protocol === 'about:' && value !== 'about:blank')) throw new Error();
    return url.href;
  } catch { throw new HttpError(400, 'Use an http(s) URL or about:blank'); }
}
