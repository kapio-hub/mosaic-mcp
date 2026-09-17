'use strict';

/**
 * Access-token check against the one Mosaic instance that issues tokens.
 *
 * Rules (ticket 188b, shared with the agent template in 188d through
 * fixtures/verify-cases.json):
 *   - algorithm EdDSA (Ed25519) only, the key is picked by `kid`
 *   - `iss` equals the configured issuer exactly — one issuer, no list
 *   - `aud` (string or array) contains the configured resource
 *   - `exp` required, `exp` and `nbf` with 60 s leeway
 *   - JWKS cached for ten minutes; an unknown `kid` reloads once, at most
 *     once per minute, and is refused if still unknown
 *
 * Only `node:crypto`; no dependency.
 */

const crypto = require('node:crypto');

const LEEWAY_SECONDS = 60;
const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_MIN_REFRESH_MS = 60 * 1000;

class TokenError extends Error {
  /**
   * @param {string} reason machine-readable: malformed | alg | kid | signature | iss | aud | exp | nbf | jwks
   * @param {string} message
   */
  constructor(reason, message) {
    super(message);
    this.name = 'TokenError';
    this.reason = reason;
  }
}

function decodeSegment(segment, what) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new TokenError('malformed', `${what} is not base64url`);
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new TokenError('malformed', `${what} is not JSON`);
  }
}

/** True when a string has the shape of a compact JWS; says nothing about validity. */
function looksLikeJwt(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}

function keyFromJwk(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
  try {
    return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  } catch {
    return null;
  }
}

/**
 * JWKS client with cache and a throttled reload for unknown key ids.
 *
 * @param {{ uri: string, fetch?: typeof fetch, now?: () => number, ttlMs?: number, minRefreshMs?: number }} options
 */
function createJwksClient(options) {
  const uri = options && options.uri;
  if (!uri) throw new Error('createJwksClient: uri is required');
  const doFetch = options.fetch || globalThis.fetch;
  const now = options.now || Date.now;
  const ttlMs = options.ttlMs ?? JWKS_TTL_MS;
  const minRefreshMs = options.minRefreshMs ?? JWKS_MIN_REFRESH_MS;

  let keys = new Map();
  let loadedAt = -Infinity;
  let lastAttempt = -Infinity;
  let pending = null;

  async function load() {
    if (pending) return pending;
    lastAttempt = now();
    pending = (async () => {
      try {
        const res = await doFetch(uri, { headers: { accept: 'application/json' } });
        if (!res.ok) throw new TokenError('jwks', `JWKS answered ${res.status}`);
        const body = await res.json();
        const next = new Map();
        for (const jwk of (body && Array.isArray(body.keys) ? body.keys : [])) {
          if (typeof jwk.kid !== 'string') continue;
          if (jwk.alg && jwk.alg !== 'EdDSA') continue;
          const key = keyFromJwk(jwk);
          if (key) next.set(jwk.kid, key);
        }
        keys = next;
        loadedAt = now();
      } finally {
        pending = null;
      }
    })();
    return pending;
  }

  return {
    uri,
    /** Public key for `kid`, or null when the issuer does not know it (after at most one reload). */
    async getKey(kid) {
      if (now() - loadedAt >= ttlMs) {
        try {
          await load();
        } catch (err) {
          // A stale cache still verifies known keys; with nothing cached the check cannot run.
          if (keys.size === 0) throw err instanceof TokenError ? err : new TokenError('jwks', `JWKS not reachable: ${err.message}`);
        }
      }
      if (keys.has(kid)) return keys.get(kid);
      if (now() - lastAttempt < minRefreshMs) return null;
      try {
        await load();
      } catch {
        return null;
      }
      return keys.get(kid) || null;
    }
  };
}

/** Accepts a JWKS client, or a plain `{ keys: [...] }` document for tests and fixtures. */
function asKeySource(jwks) {
  if (jwks && typeof jwks.getKey === 'function') return jwks;
  if (jwks && Array.isArray(jwks.keys)) {
    const map = new Map();
    for (const jwk of jwks.keys) {
      if (jwk.alg && jwk.alg !== 'EdDSA') continue;
      const key = keyFromJwk(jwk);
      if (key && typeof jwk.kid === 'string') map.set(jwk.kid, key);
    }
    return { getKey: async (kid) => map.get(kid) || null };
  }
  throw new Error('verifyAccessToken: jwks must be a JWKS client or a { keys } document');
}

/**
 * Verify a Mosaic access token for one protected resource.
 *
 * @param {string} token compact JWS
 * @param {{ issuer: string, resource: string, jwks: object, now?: () => number }} options `now` in milliseconds
 * @returns {Promise<{ sub: string|undefined, email: string|undefined, azp: string|undefined, exp: number, scope: string|undefined }>}
 * @throws {TokenError}
 */
async function verifyAccessToken(token, options) {
  const { issuer, resource, jwks } = options || {};
  if (!issuer || !resource) throw new Error('verifyAccessToken: issuer and resource are required');
  const nowSeconds = Math.floor((options.now ? options.now() : Date.now()) / 1000);

  if (!looksLikeJwt(token)) throw new TokenError('malformed', 'token is not a compact JWS');
  const [h, p, s] = token.split('.');
  const header = decodeSegment(h, 'header');
  if (header.alg !== 'EdDSA') throw new TokenError('alg', `algorithm ${String(header.alg)} is not accepted`);
  if (typeof header.kid !== 'string' || !header.kid) throw new TokenError('kid', 'token has no kid');

  const key = await asKeySource(jwks).getKey(header.kid);
  if (!key) throw new TokenError('kid', 'kid is not known to the issuer');

  const signature = Buffer.from(s, 'base64url');
  const valid = crypto.verify(null, Buffer.from(`${h}.${p}`), key, signature);
  if (!valid) throw new TokenError('signature', 'signature does not verify');

  const claims = decodeSegment(p, 'payload');
  if (claims.iss !== issuer) throw new TokenError('iss', 'issuer does not match');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(resource)) throw new TokenError('aud', 'token is not issued for this resource');
  if (typeof claims.exp !== 'number') throw new TokenError('exp', 'token has no exp');
  if (claims.exp + LEEWAY_SECONDS < nowSeconds) throw new TokenError('exp', 'token has expired');
  if (typeof claims.nbf === 'number' && claims.nbf - LEEWAY_SECONDS > nowSeconds) {
    throw new TokenError('nbf', 'token is not valid yet');
  }

  return {
    sub: typeof claims.sub === 'string' ? claims.sub : undefined,
    email: typeof claims.email === 'string' ? claims.email : undefined,
    azp: typeof claims.azp === 'string' ? claims.azp : undefined,
    exp: claims.exp,
    scope: typeof claims.scope === 'string' ? claims.scope : undefined
  };
}

module.exports = {
  LEEWAY_SECONDS,
  TokenError,
  createJwksClient,
  looksLikeJwt,
  verifyAccessToken
};
