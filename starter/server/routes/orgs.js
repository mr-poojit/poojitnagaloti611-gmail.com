// Org, member, and audit routes
//
// Orgs: GET /v1/orgs, POST /v1/orgs, PATCH /v1/orgs/{org}, DELETE /v1/orgs/{org}
// Members: GET /v1/orgs/{org}/members, PATCH /v1/orgs/{org}/members/{userId},
//   POST /v1/orgs/{org}/members/{userId}/suspend, DELETE /v1/orgs/{org}/members/{userId}/suspend,
//   DELETE /v1/orgs/{org}/members/{userId}, DELETE /v1/orgs/{org}/members/me
// Effective: GET /v1/orgs/{org}/users/{userId}/effective
// Audit: GET /v1/orgs/{org}/audit

import { send, badRequest, notFound, forbidden, selfRoleChange, conflict } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions, roleRanks } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { newId, bumpPermVersion, nowIso } from '../db.js';

export function registerOrgRoutes(router, { db, secret }) {

  // GET /v1/orgs — list all orgs the caller belongs to
  router.get('/v1/orgs', async (ctx, params, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create a new org (creator becomes owner)
  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      throw badRequest('name is required');
    }

    const orgId = newId('org');
    const memId = newId('mem');
    const now = nowIso();

    const create = db.transaction(() => {
      db.prepare(
        'INSERT INTO organizations (id, name, theme, created_at) VALUES (?, ?, ?, ?)'
      ).run(orgId, name.trim(), 'slate', now);

      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at, created_at)
         VALUES (?, ?, ?, 'owner', 'active', ?, ?)`
      ).run(memId, orgId, ctx.userId, now, now);

      audit(db, {
        orgId, actorId: ctx.userId, action: 'org.create',
        targetType: 'org', targetId: orgId, result: 'allow', requestId: ctx.requestId,
      });
    });
    create();

    send(res, 201, { id: orgId, name: name.trim(), theme: 'slate', role: 'owner' });
  });

  // PATCH /v1/orgs/{org} — update org settings
  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'org:update');

    const { name, theme, maxSessionMinutes } = ctx.body;
    const org = db.prepare('SELECT * FROM organizations WHERE id = ? AND deleted_at IS NULL').get(ctx.orgId);
    if (!org) throw notFound();

    const updates = [];
    const vals = [];
    if (name !== undefined) { updates.push('name = ?'); vals.push(name); }
    if (theme !== undefined) { updates.push('theme = ?'); vals.push(theme); }
    if (maxSessionMinutes !== undefined) { updates.push('max_session_minutes = ?'); vals.push(maxSessionMinutes); }

    if (updates.length === 0) throw badRequest('nothing to update');

    vals.push(ctx.orgId);
    db.prepare(`UPDATE organizations SET ${updates.join(', ')} WHERE id = ?`).run(...vals);

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'org.update',
      targetType: 'org', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId,
    });

    const updated = db.prepare('SELECT * FROM organizations WHERE id = ?').get(ctx.orgId);
    send(res, 200, { id: updated.id, name: updated.name, theme: updated.theme, maxSessionMinutes: updated.max_session_minutes });
  });

  // DELETE /v1/orgs/{org} — delete org
  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'org:delete');

    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'org.delete',
      targetType: 'org', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { deleted: true });
  });

  // GET /v1/orgs/{org}/members — list members
  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:read');

    const members = db.prepare(
      `SELECT m.id as membership_id, m.user_id, m.role, m.status, m.joined_at,
              u.email, u.name
       FROM memberships m JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ? AND m.status != 'removed'
       ORDER BY m.joined_at ASC`
    ).all(ctx.orgId);

    send(res, 200, { members });
  });

  // PATCH /v1/orgs/{org}/members/{userId} — change role
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:role:update');

    const targetUserId = params.userId;
    if (targetUserId === ctx.userId) throw selfRoleChange();

    const { role: newRole } = ctx.body;
    if (!newRole) throw badRequest('role is required');
    assertRoleExists(db, newRole);

    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    // Rank checks: caller must outrank target's current role AND the new role
    assertCanModify(db, ctx.role, target.role);
    // Only owners can assign owner
    if (newRole === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only owners can confer owner', 'insufficient_rank');
    }
    // Check we can modify to the new role too (i.e. caller outranks new role)
    if (newRole !== 'owner') {
      assertCanModify(db, ctx.role, newRole);
    }

    // Last-owner protection: if demoting from owner
    if (target.role === 'owner' && newRole !== 'owner') {
      assertNotLastOwner(db, ctx.orgId, targetUserId);
    }

    const update = db.transaction(() => {
      db.prepare(
        'UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?'
      ).run(newRole, ctx.orgId, targetUserId);

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_change',
        targetType: 'user', targetId: targetUserId, result: 'allow', requestId: ctx.requestId,
      });
    });
    update();

    send(res, 200, { userId: targetUserId, role: newRole });
  });

  // POST /v1/orgs/{org}/members/{userId}/suspend
  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;
    if (targetUserId === ctx.userId) throw forbidden('cannot suspend yourself');

    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    assertCanModify(db, ctx.role, target.role);

    const suspend = db.transaction(() => {
      db.prepare(
        `UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1
         WHERE org_id = ? AND user_id = ?`
      ).run(ctx.orgId, targetUserId);

      // Suspension ends active sessions (D20)
      endActiveSessions(db, { orgId: ctx.orgId, userId: targetUserId, reason: 'user_suspended' });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.suspend',
        targetType: 'user', targetId: targetUserId, result: 'allow', requestId: ctx.requestId,
      });
    });
    suspend();

    send(res, 200, { userId: targetUserId, status: 'suspended' });
  });

  // DELETE /v1/orgs/{org}/members/{userId}/suspend — reinstate
  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;
    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'suspended'`
    ).get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    const reinstate = db.transaction(() => {
      db.prepare(
        `UPDATE memberships SET status = 'active', perm_version = perm_version + 1
         WHERE org_id = ? AND user_id = ?`
      ).run(ctx.orgId, targetUserId);

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.reinstate',
        targetType: 'user', targetId: targetUserId, result: 'allow', requestId: ctx.requestId,
      });
    });
    reinstate();

    send(res, 200, { userId: targetUserId, status: 'active' });
  });

  // DELETE /v1/orgs/{org}/members/me — self leave
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    assertNotLastOwner(db, ctx.orgId, ctx.userId);

    const leave = db.transaction(() => {
      db.prepare(
        `UPDATE memberships SET status = 'removed', perm_version = perm_version + 1
         WHERE org_id = ? AND user_id = ?`
      ).run(ctx.orgId, ctx.userId);

      endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.leave',
        targetType: 'user', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId,
      });
    });
    leave();

    send(res, 200, { left: true });
  });

  // DELETE /v1/orgs/{org}/members/{userId} — remove member
  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;
    if (targetUserId === ctx.userId) throw forbidden('cannot remove yourself; use leave');

    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')`
    ).get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    assertCanModify(db, ctx.role, target.role);

    // Last-owner protection
    if (target.role === 'owner') {
      assertNotLastOwner(db, ctx.orgId, targetUserId);
    }

    const remove = db.transaction(() => {
      db.prepare(
        `UPDATE memberships SET status = 'removed', perm_version = perm_version + 1
         WHERE org_id = ? AND user_id = ?`
      ).run(ctx.orgId, targetUserId);

      endActiveSessions(db, { orgId: ctx.orgId, userId: targetUserId, reason: 'membership_removed' });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.remove',
        targetType: 'user', targetId: targetUserId, result: 'allow', requestId: ctx.requestId,
      });
    });
    remove();

    send(res, 200, { userId: targetUserId, status: 'removed' });
  });

  // GET /v1/orgs/{org}/users/{userId}/effective — effective permissions
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    // Self or user:read
    if (params.userId !== ctx.userId) {
      assertCan(db, ctx, 'user:read');
    }

    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')`
    ).get(ctx.orgId, params.userId);
    if (!target) throw notFound();

    const { role, permissions } = resolve(db, { userId: params.userId, orgId: ctx.orgId });
    send(res, 200, { role, permissions });
  });

  // GET /v1/orgs/{org}/audit — audit log
  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'audit:read');

    const limit = parseInt(ctx.query.get('limit') ?? '50', 10);
    const offset = parseInt(ctx.query.get('offset') ?? '0', 10);

    if (isNaN(limit) || limit < 1 || limit > 1000) throw badRequest('limit must be between 1 and 1000');
    if (isNaN(offset) || offset < 0) throw badRequest('offset must be >= 0');

    const events = db.prepare(
      `SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);

    send(res, 200, { events });
  });
}
