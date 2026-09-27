// Auth routes: login, refresh, token switch, me
//
// POST /v1/auth/login    — public
// POST /v1/auth/refresh   — valid refresh cookie
// POST /v1/auth/token     — authenticated, switch org
// GET  /v1/auth/me        — authenticated

import { randomUUID } from 'node:crypto';
import { send, badRequest, unauthenticated, notFound } from '../http.js';
import {
  verifyAccessToken, verifyPassword, issueAccessToken,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { newId } from '../db.js';
import { resolve } from '../permissions.js';

export function registerAuthRoutes(router, { db, secret }) {
  // POST /v1/auth/login — public
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password, orgId } = ctx.body;
    if (!email || !password) throw badRequest('email and password are required');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid credentials');
    }

    // Get all active memberships for this user
    const memberships = db.prepare(
      `SELECT m.*, o.name as org_name, o.theme, o.id as org_id
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
       ORDER BY m.joined_at ASC`
    ).all(user.id);

    if (memberships.length === 0) {
      throw unauthenticated('no active memberships');
    }

    // Pick the org: explicitly requested, or the first active membership
    let membership;
    if (orgId) {
      membership = memberships.find(m => m.org_id === orgId);
      if (!membership) throw unauthenticated('not a member of requested org');
    } else {
      membership = memberships[0];
    }

    // Issue access token
    const accessToken = issueAccessToken({
      userId: user.id,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    // Issue refresh token
    const rawRefresh = newRefreshToken();
    const familyId = randomUUID();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rtk'),
      user.id,
      hashRefreshToken(rawRefresh),
      familyId,
      new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
    );

    // Set refresh token as httpOnly cookie
    res.setHeader('Set-Cookie',
      `refreshToken=${rawRefresh}; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`
    );

    // Resolve org-level permissions for the /me endpoint
    const { permissions } = resolve(db, { userId: user.id, orgId: membership.org_id });

    send(res, 200, {
      token: accessToken,
      userId: user.id,
      name: user.name,
      email: user.email,
      orgId: membership.org_id,
      role: membership.role,
      permissions,
      orgs: memberships.map(m => ({
        id: m.org_id,
        name: m.org_name,
        theme: m.theme,
        role: m.role,
      })),
    });
  });

  // POST /v1/auth/refresh — valid refresh cookie
  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    // Parse the cookie
    const cookieHeader = ctx.req.headers.cookie || '';
    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(c => c.trim().split('=').map(s => s.trim()))
    );
    const rawToken = cookies.refreshToken;
    if (!rawToken) throw unauthenticated('missing refresh token');

    const tokenHash = hashRefreshToken(rawToken);
    const existing = db.prepare(
      'SELECT * FROM refresh_tokens WHERE token_hash = ?'
    ).get(tokenHash);

    if (!existing) throw unauthenticated('invalid refresh token');
    if (existing.revoked_at) {
      // Replay detected — revoke the entire family (D12)
      db.prepare(
        'UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL'
      ).run(new Date().toISOString(), existing.family_id);
      throw unauthenticated('refresh token reuse detected');
    }
    if (new Date(existing.expires_at) <= new Date()) {
      throw unauthenticated('refresh token expired');
    }

    // Revoke the old token
    db.prepare(
      'UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?'
    ).run(new Date().toISOString(), existing.id);

    // Find user's first active membership
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(existing.user_id);
    if (!user) throw unauthenticated('user not found');

    // If orgId was provided in body, use that; otherwise pick the first active
    const requestedOrg = ctx.body?.orgId;
    let membership;
    if (requestedOrg) {
      membership = db.prepare(
        `SELECT m.*, o.name as org_name, o.theme
         FROM memberships m JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
      ).get(user.id, requestedOrg);
    }
    if (!membership) {
      membership = db.prepare(
        `SELECT m.*, o.name as org_name, o.theme
         FROM memberships m JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
         ORDER BY m.joined_at ASC LIMIT 1`
      ).get(user.id);
    }
    if (!membership) throw unauthenticated('no active memberships');

    // Issue new tokens
    const accessToken = issueAccessToken({
      userId: user.id,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    const newRaw = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rtk'),
      user.id,
      hashRefreshToken(newRaw),
      existing.family_id, // same family
      new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
    );

    res.setHeader('Set-Cookie',
      `refreshToken=${newRaw}; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`
    );

    const allMemberships = db.prepare(
      `SELECT m.org_id, m.role, o.name as org_name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(user.id);

    const { permissions } = resolve(db, { userId: user.id, orgId: membership.org_id });

    send(res, 200, {
      token: accessToken,
      userId: user.id,
      name: user.name,
      email: user.email,
      orgId: membership.org_id,
      role: membership.role,
      permissions,
      orgs: allMemberships.map(m => ({
        id: m.org_id,
        name: m.org_name,
        theme: m.theme,
        role: m.role,
      })),
    });
  });

  // POST /v1/auth/token — switch org (D18: mints a new token scoped to the new org)
  router.post('/v1/auth/token', async (ctx, params, res) => {
    const { orgId } = ctx.body;
    if (!orgId) throw badRequest('orgId is required');

    const membership = db.prepare(
      `SELECT m.*, o.name as org_name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).get(ctx.userId, orgId);

    if (!membership) throw notFound('not a member of this org');

    const accessToken = issueAccessToken({
      userId: ctx.userId,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    const { permissions } = resolve(db, { userId: ctx.userId, orgId: membership.org_id });

    send(res, 200, {
      token: accessToken,
      userId: ctx.userId,
      orgId: membership.org_id,
      role: membership.role,
      permissions,
    });
  });

  // GET /v1/auth/me — authenticated
  router.get('/v1/auth/me', async (ctx, params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);
    if (!user) throw unauthenticated('user not found');

    const memberships = db.prepare(
      `SELECT m.org_id, m.role, o.name as org_name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.userId);

    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId });

    send(res, 200, {
      userId: user.id,
      name: user.name,
      email: user.email,
      orgId: ctx.orgId,
      role: ctx.role,
      permissions,
      orgs: memberships.map(m => ({
        id: m.org_id,
        name: m.org_name,
        theme: m.theme,
        role: m.role,
      })),
    });
  });
}
