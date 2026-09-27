// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
// question. operator and auditor are unordered by permission.

import { randomUUID } from 'node:crypto';
import { forbidden, selfRoleChange, lastOwner } from './http.js';
import { resolve } from './permissions.js';

// Returns a map of role -> rank from the database
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  const map = {};
  for (const row of rows) map[row.key] = row.rank;
  return map;
}

// Throws 400 if the role key doesn't exist in the database
export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!row) {
    throw Object.assign(new Error(`unknown role: ${role}`), { status: 400, code: 'VALIDATION', reason: 'unknown_role' });
  }
}

// Modification authority: caller must have strictly higher rank than target,
// except owners who can modify any role (subject to last-owner and no-self-change rules).
// Equal rank for non-owners (admin → admin) is 403. Only owners may confer owner.
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  const callerRank = ranks[callerRole];
  const targetRank = ranks[targetRole];
  if (callerRank === undefined || targetRank === undefined) {
    throw forbidden('unknown role', 'invalid_role');
  }
  if (callerRank <= targetRank) {
    throw forbidden('insufficient rank to modify this user', 'insufficient_rank');
  }
}

// Last-owner protection: the org must always have at least one owner
export function assertNotLastOwner(db, orgId, userId) {
  const count = db.prepare(
    `SELECT COUNT(*) as n FROM memberships
     WHERE org_id = ? AND role = 'owner' AND status = 'active'`
  ).get(orgId);
  if (count.n <= 1) {
    // Check if the user being modified IS one of the owners
    const isOwner = db.prepare(
      `SELECT 1 FROM memberships
       WHERE org_id = ? AND user_id = ? AND role = 'owner' AND status = 'active'`
    ).get(orgId, userId);
    if (isOwner) throw lastOwner();
  }
}

// End all active sessions for a user in an org, or on a device, with a reason
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const now = new Date().toISOString();
  let sql = `UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ?
             WHERE state IN ('connecting', 'active')`;
  const params = [now, reason];

  if (orgId) { sql += ' AND org_id = ?'; params.push(orgId); }
  if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
  if (deviceId) { sql += ' AND device_id = ?'; params.push(deviceId); }
  if (exceptSessionId) { sql += ' AND id != ?'; params.push(exceptSessionId); }

  return db.prepare(sql).run(...params);
}

// Snapshot the authority that authorized a session (PERMISSIONS.md §7.1)
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const { role } = resolve(db, { userId, orgId, deviceId });
  // Find grant IDs that contribute to the permission set for this device
  const grants = db.prepare(
    `SELECT g.id FROM grants g
     WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
     AND (g.device_id IS NULL OR g.device_id = ?)`
  ).all(userId, orgId, deviceId);

  return JSON.stringify({
    role,
    grantIds: grants.map(g => g.id),
    snapshotAt: new Date().toISOString(),
  });
}

// The session expiry: started_at + org.max_session_minutes
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}
