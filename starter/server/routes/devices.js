// Device and grant routes
//
// Devices: GET/POST/PATCH/DELETE /v1/orgs/{org}/devices[/{id}]
//          POST /v1/orgs/{org}/devices/{id}/transfer
// Grants:  POST /v1/orgs/{org}/grants, GET /v1/orgs/{org}/grants,
//          DELETE /v1/orgs/{org}/grants/{id}

import { send, badRequest, notFound, forbidden, conflict } from '../http.js';
import { assertCan, resolve, assertMayGrant } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { newId, bumpPermVersion, nowIso } from '../db.js';
import { normalizeTs } from '../http.js';

export function registerDeviceRoutes(router, { db, secret }) {

  // GET /v1/orgs/{org}/devices — list devices with per-device permissions
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'device:list');

    const devices = db.prepare(
      `SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY created_at ASC`
    ).all(ctx.orgId);

    // Resolve permissions per device for the caller, filtering out devices
    // the caller can't see (device:view denied)
    const result = [];
    for (const d of devices) {
      const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: d.id });
      // device:view denied → row is absent (not redacted)
      if (permissions['device:view']?.effect !== 'allow') continue;

      result.push({
        id: d.id,
        name: d.name,
        kind: d.kind,
        online: !!d.online,
        permissions,
      });
    }

    send(res, 200, { devices: result });
  });

  // GET /v1/orgs/{org}/devices/{id} — single device
  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = db.prepare(
      'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(params.id, ctx.orgId);
    if (!device) throw notFound();

    assertCan(db, ctx, 'device:view', device.id);

    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });

    send(res, 200, {
      id: device.id,
      name: device.name,
      kind: device.kind,
      online: !!device.online,
      permissions,
    });
  });

  // POST /v1/orgs/{org}/devices — provision new device
  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'device:provision');

    const { name, kind } = ctx.body;
    if (!name || typeof name !== 'string') throw badRequest('name is required');
    if (!kind || !['macos', 'windows', 'linux', 'android', 'ios'].includes(kind)) {
      throw badRequest('kind must be one of macos, windows, linux, android, ios');
    }

    const deviceId = newId('dev');
    db.prepare(
      'INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)'
    ).run(deviceId, ctx.orgId, name, kind);

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'device.provision',
      targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 201, { id: deviceId, name, kind, online: false });
  });

  // PATCH /v1/orgs/{org}/devices/{id} — update device
  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = db.prepare(
      'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(params.id, ctx.orgId);
    if (!device) throw notFound();

    assertCan(db, ctx, 'device:update', device.id);

    const { name, kind } = ctx.body;
    const updates = [];
    const vals = [];
    if (name !== undefined) { updates.push('name = ?'); vals.push(name); }
    if (kind !== undefined) {
      if (!['macos', 'windows', 'linux', 'android', 'ios'].includes(kind)) {
        throw badRequest('invalid kind');
      }
      updates.push('kind = ?'); vals.push(kind);
    }
    if (updates.length === 0) throw badRequest('nothing to update');

    vals.push(device.id);
    db.prepare(`UPDATE devices SET ${updates.join(', ')} WHERE id = ?`).run(...vals);

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update',
      targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId,
    });

    const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
    send(res, 200, { id: updated.id, name: updated.name, kind: updated.kind, online: !!updated.online });
  });

  // DELETE /v1/orgs/{org}/devices/{id} — decommission device
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = db.prepare(
      'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(params.id, ctx.orgId);
    if (!device) throw notFound();

    assertCan(db, ctx, 'device:provision', device.id);

    const remove = db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), device.id);
      endActiveSessions(db, { deviceId: device.id, reason: 'device_transferred' });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.decommission',
        targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    remove();

    send(res, 200, { deleted: true });
  });

  // POST /v1/orgs/{org}/devices/{id}/transfer — transfer device to another org
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = db.prepare(
      'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(params.id, ctx.orgId);
    if (!device) throw notFound();

    assertCan(db, ctx, 'device:provision', device.id);

    const { targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    // Check caller has device:provision in the target org
    const targetMembership = db.prepare(
      `SELECT * FROM memberships WHERE user_id = ? AND org_id = ? AND status = 'active'`
    ).get(ctx.userId, targetOrgId);
    if (!targetMembership) throw notFound('target org not found');

    const targetPerms = resolve(db, { userId: ctx.userId, orgId: targetOrgId });
    if (targetPerms.permissions['device:provision']?.effect !== 'allow') {
      throw forbidden('missing device:provision in target org', 'missing_permission');
    }

    const transfer = db.transaction(() => {
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, device.id);
      endActiveSessions(db, { deviceId: device.id, reason: 'device_transferred' });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer',
        targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    transfer();

    send(res, 200, { transferred: true, newOrgId: targetOrgId });
  });

  // POST /v1/orgs/{org}/grants — create grant
  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'grant:create');

    const { userId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body;

    if (!userId) throw badRequest('userId is required');
    if (!effect || !['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');
    if (!permissions || !Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }

    // No self-grants (D9)
    if (userId === ctx.userId) throw forbidden('cannot grant permissions to yourself', 'self_grant');

    // Target must be an active member
    const target = db.prepare(
      `SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, userId);
    if (!target) throw notFound('user is not an active member');

    // Device must belong to this org
    if (deviceId) {
      const device = db.prepare(
        'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
      ).get(deviceId, ctx.orgId);
      if (!device) throw notFound('device not found in this org');
    }

    // Validate permissions against permission_patterns (D19)
    for (const perm of permissions) {
      const exists = db.prepare('SELECT 1 FROM permission_patterns WHERE pattern = ?').get(perm);
      if (!exists) {
        throw Object.assign(
          badRequest(`unknown permission: ${perm}`),
          { reason: 'unknown_permission' }
        );
      }
    }

    // Half-open time window validation (D7)
    const normalizedStartsAt = normalizeTs(startsAt, 'startsAt');
    const normalizedExpiresAt = normalizeTs(expiresAt, 'expiresAt');
    if (normalizedExpiresAt && new Date(normalizedExpiresAt) <= new Date()) {
      throw Object.assign(
        badRequest('expiresAt must be in the future'),
        { status: 400, code: 'GRANT_EXPIRED', reason: 'grant_expired' }
      );
    }

    // No privilege laundering (D9): caller must hold every permission being granted
    if (effect === 'allow') {
      assertMayGrant(db, ctx, permissions, deviceId || null);
    }

    const grantId = newId('grt');

    const create = db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(grantId, ctx.orgId, userId, deviceId || null, effect,
        normalizedStartsAt, normalizedExpiresAt, ctx.userId);

      for (const perm of permissions) {
        db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(grantId, perm);
      }

      bumpPermVersion(db, { orgId: ctx.orgId, userId });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create',
        targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId,
      });
    });
    create();

    send(res, 201, { id: grantId, effect, permissions, userId, deviceId: deviceId || null });
  });

  // GET /v1/orgs/{org}/grants — list grants
  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:read');

    const grants = db.prepare(
      `SELECT g.*, GROUP_CONCAT(gp.permission) as permissions
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       WHERE g.org_id = ? AND g.revoked_at IS NULL
       GROUP BY g.id
       ORDER BY g.created_at DESC`
    ).all(ctx.orgId);

    send(res, 200, {
      grants: grants.map(g => ({
        id: g.id,
        userId: g.user_id,
        deviceId: g.device_id,
        effect: g.effect,
        permissions: g.permissions.split(','),
        startsAt: g.starts_at,
        expiresAt: g.expires_at,
        createdBy: g.created_by,
        createdAt: g.created_at,
      })),
    });
  });

  // DELETE /v1/orgs/{org}/grants/{id} — revoke grant
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(
      'SELECT * FROM grants WHERE id = ? AND org_id = ?'
    ).get(params.id, ctx.orgId);
    if (!grant || grant.revoked_at) throw notFound();

    const revoke = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });

      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke',
        targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    revoke();

    send(res, 200, { revoked: true });
  });
}
