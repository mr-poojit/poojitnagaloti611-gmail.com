// Invite routes
//
// POST   /v1/orgs/{org}/invites        — create invite (user:invite)
// GET    /v1/orgs/{org}/invites        — list invites (user:invite)
// DELETE /v1/orgs/{org}/invites/{id}   — revoke invite (user:invite)
// GET    /v1/invites/{token}           — public peek
// POST   /v1/invites/{token}/accept    — public accept

import { send, badRequest, notFound, forbidden, conflict, gone, unauthenticated } from '../http.js';
import { assertCan } from '../permissions.js';
import { assertRoleExists, assertCanModify, roleRanks } from '../lifecycle.js';
import { audit } from '../audit.js';
import { newId, nowIso } from '../db.js';
import {
  newInviteToken, hashInviteToken, hashPassword,
  issueAccessToken, newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';
import { randomUUID } from 'node:crypto';

const INVITE_TTL_DAYS = 7;

export function registerInviteRoutes(router, { db, secret }) {

  // POST /v1/orgs/{org}/invites — create invite
  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || typeof email !== 'string') throw badRequest('email is required');
    if (!role) throw badRequest('role is required');

    const normalizedEmail = email.toLowerCase().trim();
    assertRoleExists(db, role);

    // Only owners may confer owner
    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only owners can invite as owner', 'insufficient_rank');
    }
    // Caller must be able to assign this role (outranks it)
    if (role !== 'owner') {
      const ranks = roleRanks(db);
      if (ranks[ctx.role] <= ranks[role]) {
        throw forbidden('cannot invite at a role equal to or above your own', 'insufficient_rank');
      }
    }

    // Check for existing active membership
    const existingMember = db.prepare(
      `SELECT 1 FROM memberships WHERE org_id = ? AND user_id IN (SELECT id FROM users WHERE email = ?) AND status = 'active'`
    ).get(ctx.orgId, normalizedEmail);
    if (existingMember) throw conflict('user already has an active membership');

    // one_live_invite_per_email unique index prevents duplicates — let the DB enforce it
    const rawToken = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const inviteId = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();

    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(inviteId, ctx.orgId, normalizedEmail, role, tokenHash, ctx.userId, expiresAt);
    } catch (e) {
      if (e.message?.includes('UNIQUE constraint failed')) {
        throw conflict('an active invite already exists for this email');
      }
      throw e;
    }



    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.create',
      targetType: 'invite', targetId: inviteId, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 201, { id: inviteId, inviteToken: rawToken, email: normalizedEmail, role, expiresAt });
  });

  // GET /v1/orgs/{org}/invites — list invites
  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
       FROM invites WHERE org_id = ? ORDER BY created_at DESC`
    ).all(ctx.orgId);

    send(res, 200, { invites });
  });

  // DELETE /v1/orgs/{org}/invites/{id} — revoke invite
  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const invite = db.prepare(
      'SELECT * FROM invites WHERE id = ? AND org_id = ?'
    ).get(params.id, ctx.orgId);
    if (!invite) throw notFound();
    if (invite.revoked_at || invite.accepted_at) throw notFound();

    db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.revoke',
      targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { revoked: true });
  });

  // GET /v1/invites/{token} — public peek
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const tokenHash = hashInviteToken(params.token);
    const invite = db.prepare(
      `SELECT i.email, i.role, i.expires_at, o.name as org_name
       FROM invites i JOIN organizations o ON o.id = i.org_id
       WHERE i.token_hash = ?`
    ).get(tokenHash);

    if (!invite) throw notFound();

    // Check if expired or revoked
    const raw = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(tokenHash);
    if (raw.revoked_at) throw gone('invite has been revoked');
    if (new Date(raw.expires_at) <= new Date()) throw gone('invite has expired');
    if (raw.accepted_at) throw conflict('invite has already been accepted');

    send(res, 200, {
      orgName: invite.org_name,
      role: invite.role,
      email: invite.email,
      expiresAt: invite.expires_at,
    });
  });

  // POST /v1/invites/{token}/accept — public accept
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const tokenHash = hashInviteToken(params.token);
    const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(tokenHash);

    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('invite has already been accepted');
    if (invite.revoked_at) throw gone('invite has been revoked');
    if (new Date(invite.expires_at) <= new Date()) throw gone('invite has expired');

    const { name, password } = ctx.body;
    if (!password || typeof password !== 'string') throw badRequest('password is required');

    const accept = db.transaction(() => {
      // Upsert user: find by email or create
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        if (!name || typeof name !== 'string') throw badRequest('name is required for new users');
        const userId = newId('usr');
        db.prepare(
          'INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)'
        ).run(userId, invite.email, name, hashPassword(password));
        user = { id: userId, email: invite.email, name };
      } else {
        // Existing user — update password
        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
          .run(hashPassword(password), user.id);
      }

      // Create or update membership
      const existing = db.prepare(
        'SELECT * FROM memberships WHERE org_id = ? AND user_id = ?'
      ).get(invite.org_id, user.id);

      if (existing) {
        if (existing.status === 'active') throw conflict('already a member');
        // Reactivate: invited, suspended, or removed
        db.prepare(
          `UPDATE memberships SET role = ?, status = 'active', perm_version = perm_version + 1, joined_at = ?
           WHERE org_id = ? AND user_id = ?`
        ).run(invite.role, nowIso(), invite.org_id, user.id);
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at, created_at)
           VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`
        ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso(), nowIso());
      }

      // Mark invite as accepted
      db.prepare(
        'UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?'
      ).run(nowIso(), user.id, invite.id);

      // Issue tokens
      const membership = db.prepare(
        'SELECT * FROM memberships WHERE org_id = ? AND user_id = ?'
      ).get(invite.org_id, user.id);

      const accessToken = issueAccessToken({
        userId: user.id,
        orgId: invite.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      }, secret);

      const rawRefresh = newRefreshToken();
      db.prepare(
        `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
         VALUES (?, ?, ?, ?, ?)`
      ).run(newId('rtk'), user.id, hashRefreshToken(rawRefresh), randomUUID(),
        new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());

      audit(db, {
        orgId: invite.org_id, actorId: user.id, action: 'invite.accept',
        targetType: 'invite', targetId: invite.id, result: 'allow',
      });

      return { user, membership, accessToken, rawRefresh };
    });

    const { user, membership, accessToken, rawRefresh } = accept();

    res.setHeader('Set-Cookie',
      `refreshToken=${rawRefresh}; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`
    );

    // Get all orgs for this user
    const orgs = db.prepare(
      `SELECT m.org_id as id, m.role, o.name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(user.id);

    send(res, 200, {
      token: accessToken,
      userId: user.id,
      name: user.name,
      email: user.email,
      orgId: invite.org_id,
      role: membership.role,
      orgs,
    });
  });
}
