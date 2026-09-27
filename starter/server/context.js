// Per-request context: turn a bearer token into an authenticated caller.
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries
// { userId, orgId, role, membership, claims }.
//
// The token's org claim IS the only org the caller may address. A request that
// names a different org is INVISIBLE — 404, never 403.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated } from './http.js';

export function authenticate(db, secret) {
  // Prepare statements once per server lifetime — not per request
  const getMembership = db.prepare(
    `SELECT id, org_id, user_id, role, status, perm_version
     FROM memberships
     WHERE user_id = ? AND org_id = ?`
  );

  return function buildContext(req, _params) {
    // Extract the bearer token
    const auth = req.headers?.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      throw unauthenticated('missing bearer token');
    }
    const token = auth.slice(7);

    // Verify the JWT (signature, algorithm, expiry, issuer, audience, jti)
    const claims = verifyAccessToken(token, secret);

    // Look up the membership for this user in this org
    const membership = getMembership.get(claims.sub, claims.org);

    // No membership at all → unauthenticated (token is invalid for this org)
    if (!membership) {
      throw unauthenticated('not a member of this org');
    }

    // Removed members → unauthenticated
    if (membership.status === 'removed') {
      throw unauthenticated('membership removed');
    }

    // Check freshness: perm_version must match exactly (not <, because future is suspect too)
    assertFresh(claims, membership);

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
