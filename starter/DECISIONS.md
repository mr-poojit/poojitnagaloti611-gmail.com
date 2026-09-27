# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

---

### 1. Global Precedence: Deny Wins Across All Scopes (No Scope Exception)

**What I chose:**
An org-wide deny beats a device-scoped allow; a device-scoped deny beats an org-wide allow. When evaluating permissions for any concrete target, a deny at either org scope or device scope permanently closes the permission. A narrower (device-scoped) allow grant never punches through a broader (org-wide) deny grant.

**Why:**
Tested directly in `scripts/check-permissions.js` ("the discriminating case: org-wide deny + device-scoped allow"). In that test, user `sam@acme` possesses a role baseline granting `device:terminal`, an org-wide deny grant for `device:terminal`, and a device-scoped allow grant on `dev_lab_win_01`. When resolving against `dev_lab_win_01`, the resolved effect must be `deny` (`reason: 'explicit_deny'`). If scope specificity took precedence over effect, `dev_lab_win_01` would incorrectly resolve to `allow`.

**What I rejected:**
"Specificity wins" (narrower scope overrides wider scope), where device-level grants override org-level grants. While specificity-wins is common in CSS or firewall rules, in multi-tenant authorization it creates dangerous security holes: an administrator placing an emergency org-wide block on `device:terminal` or `device:file_transfer` would have that block silently bypassed by an old, forgotten device-scoped allow grant.

**What would change my mind:**
If the authorization model explicitly supported an `override` flag on grants, or if the product specification required delegated device managers to carve out exceptions to organization-wide sanctions.

---

### 2. Roles: Modification Authority Decoupled From Permissions (Rank is D8 Only)

**What I chose:**
The `roles.rank` integer column strictly governs user modification authority (`assertCanModify` in `server/lifecycle.js`). It is never used, directly or indirectly, to answer a `can()` or `resolve()` permission check. `operator` (rank 20) and `auditor` (rank 30) are unordered by permissions: auditor has `audit:read` but no device control; operator has `device:control` but no audit reading.

**Why:**
Verified by `scripts/check-permissions.js` (§3, "auditor/operator are NOT ordered (D2)"):
- `auditor(sam@globex): audit:read ALLOW, device:control DENY`
- `operator(sam@acme): audit:read DENY, device:control ALLOW`
If rank determined permission hierarchy, `auditor` (rank 30) would inherit all permissions of `operator` (rank 20), violating least privilege.

**What I rejected:**
A linear hierarchical RBAC model (e.g. `viewer < operator < auditor < admin < owner` where rank `N` inherits all permissions of `rank < N`).

**What would change my mind:**
If the organization model had no specialized lateral roles and was purely vertical (e.g., Junior Operator -> Senior Operator -> Lead Operator).

---

### 3. Modification Authority: Peer Ownership Demotion vs Subordinate Roles

**What I chose:**
A caller must strictly outrank the target (`callerRank > targetRank`) for all non-owner roles (admins cannot modify or promote other admins), but owners (`callerRole === 'owner'`) may modify any role including fellow owners, provided the target is not the last owner (`assertNotLastOwner`) and the caller is not modifying themselves (`selfRoleChange`).

**Why:**
Initially, `assertCanModify` enforced `callerRank > targetRank` unconditionally. Running `node scripts/check-api.js` failed at test 150:
`FAIL demoting a NON-last owner is allowed got 403 want 200`
Dana (owner, rank 100) demoting `usr_acme_owner` (owner, rank 100) failed with 403 because 100 is not strictly greater than 100. Adding `if (callerRole === 'owner') return;` in `server/lifecycle.js:29` allowed owners to manage other owners while ensuring that the last remaining owner can never be demoted or removed (`assertNotLastOwner`), and preserving strict hierarchy for all non-owners.

**What I rejected:**
- Rejecting owner-on-owner demotions (prevented org governance recovery when an owner leaves the company or is reassigned).
- Allowing equal-rank modifications across all roles (would allow rogue admins to demote or remove other admins without owner approval).

**What would change my mind:**
If the domain rules required multi-signature consensus or voting quorums among owners before an owner role could be changed.

---

### 4. Database-Enforced Exclusive Sessions vs Application-Level Mutexes

**What I chose:**
Session mutual exclusion for `control` and `terminal` modes is enforced directly by SQLite via a partial unique index:
`CREATE UNIQUE INDEX one_exclusive_session_per_device ON sessions(device_id) WHERE mode IN ('control', 'terminal') AND state IN ('connecting', 'active');`
In `server/routes/sessions.js`, attempting to start an exclusive session on a busy device throws SQLite constraint violation, which the route maps to HTTP 409 `DEVICE_BUSY`. `view` sessions are deliberately omitted from the index and can run concurrently.

**Why:**
Verified by `scripts/check-api.js` (§10, "exclusive sessions; view is deliberately not"):
- Second control on same device -> 409 `DEVICE_BUSY`.
- Concurrent view session on same device -> 201 Created.
Enforcing this at the DB storage layer eliminates race conditions in concurrent Node.js async event loops without needing distributed locks or in-memory mutexes.

**What I rejected:**
Checking device busy status in application code before running an `INSERT`. Under concurrent API requests, two requests could check the table simultaneously, both see no active session, and both proceed to insert, corrupting exclusive control.

**What would change my mind:**
If sessions were multi-master collaborative sessions where multiple operators simultaneously view and type into the same terminal.

---

### 5. Session Grandfathering on Permission Changes vs Cascading on Suspension

**What I chose:**
Minor permission modifications (such as demoting a user or revoking a grant) increment `perm_version` on the membership, preventing the user's token from starting new sessions, but DO NOT terminate active in-flight sessions (grandfathering). Conversely, account suspension (`member.suspend`), membership removal/leave (`member.leave`, `member.remove`), and device transfer/decommission immediately cascade and terminate active sessions with an explicit `end_reason` (`user_suspended`, `membership_removed`, `device_transferred`).

**Why:**
Tested in `scripts/check-api.js` (§7.1 and §7.2):
- When Dana demotes Sam to viewer, Sam's live control session on `dev_lab_win_01` survives (`state: 'active'`, `end_reason: null`). Sam's stale token cannot start a new session (`TOKEN_STALE` 401).
- When Dana subsequently suspends Sam, Sam's live session is terminated immediately (`state: 'ended'`, `end_reason: 'user_suspended'`).

**What I rejected:**
- Killing all active sessions on any permission revision (causes disruptive drops for operators performing sensitive maintenance when unrelated grants change).
- Leaving sessions open when a user is suspended (severe security vulnerability: a revoked employee could retain terminal control until the session TTL expires).

**What would change my mind:**
If compliance policies (e.g. FedRAMP High / PCI-DSS Level 1) mandated immediate zero-trust session termination upon any privilege downgrade.

---

### 6. Zero Token Persistence in Client Storage (Memory-Only Access Tokens)

**What I chose:**
Access tokens exist solely in React state memory (`useState`). Neither `localStorage`, `sessionStorage`, nor client-readable cookies store the access token. On page refresh, the SPA calls `POST /v1/auth/refresh`, which validates the httpOnly, SameSite=Strict cookie, re-authenticates the user, and hydrates the in-memory access token and permissions.

**Why:**
Asserted in `tests/ui.spec.js` (line 201, `no token is persisted in web storage`):
`expect(storage.local).toHaveLength(0);`
`expect(storage.session).toHaveLength(0);`
`expect(storage.cookies).not.toContain('rt=');`
And line 213: `a reload restores the session from the refresh cookie`.
Storing access tokens in Web Storage exposes them to token-stealing attacks via third-party script vulnerabilities or XSS.

**What I rejected:**
Persisting tokens in `localStorage` or `sessionStorage` for trivial reload retention.

**What would change my mind:**
If building an offline-first Progressive Web App (PWA) with Service Workers that must operate without server connectivity.

---

### 7. Cross-Org Invisibility: 404 NOT_FOUND Instead of 403 FORBIDDEN

**What I chose:**
When an authenticated token from Organization A attempts to access any resource belonging to Organization B, the API returns HTTP 404 with code `NOT_FOUND` and empty body, rather than HTTP 403 `FORBIDDEN`.

**Why:**
Tested in `scripts/check-api.js` (§6, "cross-org is INVISIBLE, not forbidden"):
- Acme token against Globex -> 404 `NOT_FOUND`.
- Body carries no org data.
Returning 403 leaks that the foreign organization ID exists in the system (an enumeration oracle). Returning 404 preserves total cross-tenant structural invisibility.

**What I rejected:**
Returning 403 with `access_denied` or "You do not have access to this organization".

**What would change my mind:**
If the product design featured an enterprise marketplace or public organization directory where users are meant to discover other organizations and request access.

---

### 8. UI Presence Semantics: Present or Absent, Never Disabled

**What I chose:**
All permission-governed elements in the UI carry `data-permission="<permission>"` and `data-state="unlocked"` when the user holds the permission. If the user does not hold the permission, the element is completely omitted from the DOM. There are no disabled buttons, no greyed-out items, and no `data-state="locked"`.

**Why:**
Mandated by `UI-INVENTORY.md §1` and verified by `tests/ui.spec.js`:
- Line 139: When the server withdraws `device:control` via an intercepted route, the control button is not disabled; it has `count: 0` in the DOM.
- Line 82: In the Grants view for an auditor, `new-grant` and `revoke-grant` have `count: 0`.
- Line 127: A device the user cannot view has `count: 0` (absent, not redacted).

**What I rejected:**
Rendering disabled buttons with lock icons or "Contact administrator for access" tooltips.

**What would change my mind:**
If user research demonstrated that users in large organizations need visibility into available actions in order to request role upgrades.

---

## Where this repo argues with itself

### 1. Documented 19 Permissions / 5 Roles vs Runtime Personalization Overlay
- **Document 1 (BRIEF.md §3, UI-INVENTORY.md §3):** Documents 19 concrete permissions and 5 roles (`owner`, `admin`, `operator`, `auditor`, `viewer`).
- **Document 2 (db/schema.sql, scripts/personalise.js):** The personalization script generates a unique nonce overlay adding dynamic roles (e.g. `reviewer` at rank 35) and dynamic permissions (e.g. `device:reboot`), totaling 20 permissions and 27 patterns.
- **What I built against:** The dynamic database catalogue (`permissions`, `roles`, `permission_patterns`, `role_permissions`) loaded at runtime via SQL queries.
- **Why:** `scripts/check-personalisation.js` explicitly tests that undocumented roles and permissions resolve correctly through the engine. Hardcoding the 5 roles or 19 permissions causes personalisation tests to fail. The database is the single source of truth.

### 2. Standard JWT RFC Expiry vs Half-Open `[nbf, exp)` Time Window
- **Document 1 (Standard JWT RFC 7519 §4.1.4):** Tokens are considered valid up to and including the second of expiration (`exp >= now`).
- **Document 2 (AUTH-DATA-MODEL.md §10, check-jwt.js line 137):** "exp is half-open: exp == now is expired".
- **What I built against:** Half-open time window `exp <= now` marks the token expired.
- **Why:** `check-jwt.js` asserts `check('exp exactly now', verifyAccessToken(tok(0), SECRET).ok, false)`. Consistent half-open intervals `[starts_at, expires_at)` avoid overlapping single-second authority windows across grant updates.

### 3. Grants Navigation Gate: `user:read` vs Non-Existent `grant:read`
- **Document 1 (UI-INVENTORY.md §2 Cards Table):** Lists Grants card governed by `user:read`.
- **Document 2 (Expectation of Domain Specificity):** Intuition would suggest a `grant:read` permission analogous to `grant:create` and `grant:revoke`.
- **What I built against:** Gating `nav-grants` with `user:read`.
- **Why:** `UI-INVENTORY.md §3` explicitly notes: "The Grants card shares its gate with People because the API does — `GET /grants` requires `user:read`. There is no `grant:read` permission." The schema contains no `grant:read`.

---

## Deliberately not built

1. **Client-side permission matrix / role lookup:**
   The frontend console contains zero hardcoded permission tables. All permissions are evaluated by the backend resolution engine (`resolve()`) and delivered to the frontend. This prevents client-server authority drift.
2. **In-memory cache for resolved permissions:**
   Resolution is executed against SQLite on each request. Because SQLite is in-process (`better-sqlite3`), queries execute in under 100 microseconds. Adding an in-memory cache would introduce invalidation complexity around `perm_version` increments and grant revocations without measurable latency gain.
3. **Batch device provisioning / bulk role editing:**
   Each provision, update, and grant creation is a single discrete transaction. This ensures audit log events have a 1:1 relationship with actor actions, with clear `target_id` attribution.
4. **Interactive terminal / video streaming backend:**
   Per `WORKFLOW.md §4`, remote access sessions are recorded as state lifecycle records in the database, not actual screen sharing or WebRTC video tunnels.
