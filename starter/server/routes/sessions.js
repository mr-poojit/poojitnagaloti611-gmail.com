// Session routes
//
// POST   /v1/orgs/{org}/sessions     — start session (session:start + mode permission)
// GET    /v1/orgs/{org}/sessions     — list sessions (session:view)
// GET    /v1/sessions/{id}           — get session (participant or session:view)
// DELETE /v1/sessions/{id}           — end session (own or session:terminate)

import { send, badRequest, notFound, forbidden, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession, can } from '../permissions.js';
import { endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { newId, nowIso } from '../db.js';

export function registerSessionRoutes(router, { db, secret }) {

  // POST /v1/orgs/{org}/sessions — start a session
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const { deviceId, mode } = ctx.body;
    if (!deviceId) throw badRequest('deviceId is required');
    if (!mode || !['view', 'control', 'terminal'].includes(mode)) {
      throw badRequest('mode must be view, control, or terminal');
    }

    // Device must exist in this org
    const device = db.prepare(
      'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(deviceId, ctx.orgId);
    if (!device) throw notFound();

    // Compound permission check: session:start AND mode permission (D9)
    // This will throw with the appropriate reason (missing_permission vs missing_device_permission)
    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () => {
      assertCanStartSession(db, ctx, mode, deviceId);
    });

    const sessionId = newId('ses');
    const now = nowIso();
    const expiresAt = sessionExpiry(db, ctx.orgId);
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
      ).run(sessionId, ctx.orgId, ctx.userId, deviceId, mode, authorizedBy, now, expiresAt);
    } catch (e) {
      // Exclusive session constraint: one_exclusive_session_per_device
      if (e.message?.includes('UNIQUE constraint failed')) {
        throw deviceBusy();
      }
      throw e;
    }

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'session.start',
      targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId,
    });

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);

    send(res, 201, {
      id: session.id,
      org_id: session.org_id,
      user_id: session.user_id,
      device_id: session.device_id,
      mode: session.mode,
      state: session.state,
      authorized_by: JSON.parse(session.authorized_by),
      started_at: session.started_at,
      expires_at: session.expires_at,
      end_reason: session.end_reason,
    });
  });

  // GET /v1/orgs/{org}/sessions — list sessions
  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare(
      `SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC`
    ).all(ctx.orgId);

    send(res, 200, {
      sessions: sessions.map(s => ({
        id: s.id,
        org_id: s.org_id,
        user_id: s.user_id,
        device_id: s.device_id,
        mode: s.mode,
        state: s.state,
        end_reason: s.end_reason,
        authorized_by: JSON.parse(s.authorized_by),
        started_at: s.started_at,
        expires_at: s.expires_at,
        ended_at: s.ended_at,
      })),
    });
  });

  // GET /v1/sessions/{id} — get single session
  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(params.id);
    if (!session) throw notFound();

    // Check: must be in caller's org
    if (session.org_id !== ctx.orgId) throw notFound();

    // Participant or session:view
    if (session.user_id !== ctx.userId && !can(db, ctx, 'session:view')) {
      throw forbidden('not a participant and missing session:view', 'missing_permission');
    }

    send(res, 200, {
      id: session.id,
      org_id: session.org_id,
      user_id: session.user_id,
      device_id: session.device_id,
      mode: session.mode,
      state: session.state,
      end_reason: session.end_reason,
      authorized_by: JSON.parse(session.authorized_by),
      started_at: session.started_at,
      expires_at: session.expires_at,
      ended_at: session.ended_at,
    });
  });

  // DELETE /v1/sessions/{id} — end session
  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(params.id);
    if (!session) throw notFound();

    if (session.org_id !== ctx.orgId) throw notFound();

    // Own session or session:terminate
    const isOwn = session.user_id === ctx.userId;
    if (!isOwn && !can(db, ctx, 'session:terminate')) {
      throw forbidden('not your session and missing session:terminate', 'missing_permission');
    }

    if (session.state === 'ended') throw notFound('session already ended');

    const reason = isOwn ? 'user_stopped' : 'admin_terminated';

    db.prepare(
      `UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? WHERE id = ?`
    ).run(nowIso(), reason, session.id);

    audit(db, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'session.end',
      targetType: 'session', targetId: session.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { id: session.id, state: 'ended', end_reason: reason });
  });
}
