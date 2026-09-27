# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

---

## 2026-09-26 13:17 · Phase 0 — orientation

Installed, ran `npm run db:reset`. First issue: Windows path handling — `load-db.js` uses
`new URL(...).pathname` which produces `/C:/Users/...` on Windows, and `readFileSync` treats
that as a relative path yielding `C:\C:\...`. Fixed with `fileURLToPath` from `node:url`.
Same issue in `server/index.js` for the DIST path.

After the fix, db:reset succeeds. Noticed the personalisation overlay:
- Extra role: `reviewer` (rank 35, between operator and admin)
- Extra permission: `device:reboot`
- 20 permissions total (not 19), 27 patterns (not 26)
- The overlay adds an org `Ironside Labs` with two devices, one with an allow grant and one
  with a deny grant for `device:reboot`

This confirms: I **must** read roles/permissions from the database. Hardcoding the 5×19 matrix
would miss `reviewer` and `device:reboot` entirely.

Ran all four test suites against the untouched skeleton:
- `check-jwt.js`: all fail (verifyAccessToken is a stub that throws NOT_IMPLEMENTED)
- `check-permissions.js`: all fail (resolve() is a stub)
- `check-api.js`: cannot run — server crashes on context.js stub
- `playwright`: not installed yet

Starting line: 43 JWT tests to pass, ~30 permission tests, ~50 API tests.

## 2026-09-26 13:22 · Phase 1 — token verification

Implemented `verifyAccessToken` in `server/auth.js`. The order of checks matters:
1. Structural: three dot-separated segments
2. Parse header as base64url JSON object
3. Algorithm pinning: reject anything that isn't `{alg: 'HS256', typ: 'JWT'}` — this is
   the defence against `alg: none` and algorithm substitution attacks
4. Parse payload as base64url JSON object
5. Constant-time signature comparison using `timingSafeEqual`
6. Expiry: half-open, so `exp <= now` is expired (not `exp < now`)
7. Issuer and audience validation
8. JTI present and non-empty

**Prediction that was wrong:** Initially thought I should check the signature BEFORE checking
the header algorithm. But the tests showed that `alg: none` with an empty signature must be
rejected by the algorithm check, not by a signature mismatch. If I checked signature first,
an `alg: none` token with a coincidentally valid HMAC signature would pass — the algorithm
check exists to prevent trusting the header's claim about what algorithm was used.

**Key insight:** The signature comparison must use `timingSafeEqual` and the lengths must match
first. A truncated signature where `timingSafeEqual` would throw (different lengths) needs
to be caught. Used `actualSig.length !== expectedSig.length` as the guard.

## 2026-09-26 13:24 · Phase 2 — caller context and resolution engine

Implemented `server/context.js` and `server/permissions.js`:
- `authenticate(db, secret)(req, params)`: Extracts Bearer token, validates token via `verifyAccessToken`, verifies user exists, verifies active membership in token's org, checks `membership.perm_version === payload.pv` (token freshness / D16).
- `resolve(db, { userId, orgId, deviceId })`:
  1. If no active membership in orgId: return all permissions denied (`reason: 'not_a_member'`).
  2. If suspended: return all permissions denied (`reason: 'suspended'`).
  3. Load role baseline permissions from `role_permissions` joined with `permission_patterns`.
  4. Query active grants (`effect`, `permission`, `device_id`) within valid half-open time window `starts_at <= now < expires_at` and `revoked_at IS NULL`.
  5. Deny-wins evaluation: Org-wide denies, then device-scoped denies.
  6. Allow evaluation: Baseline allowed OR org-wide grant allowed OR device-scoped grant allowed.
  7. Tested against `check-permissions.js` and `check-personalisation.js`. All 35 permission tests and 18 personalisation tests pass.

## 2026-09-26 13:28 · Phases 3 & 4 — API routes, lifecycle, sessions, and audit

Implemented domain support modules and full HTTP API surface:
- `server/lifecycle.js`: `roleRanks`, `assertRoleExists`, `assertCanModify`, `assertNotLastOwner`, `endActiveSessions`, `snapshotAuthority`, `sessionExpiry`.
- `server/audit.js`: `audit()`, `auditDenials()`.
- Routes:
  - `server/routes/auth.js`: `/v1/auth/login`, `/v1/auth/refresh`, `/v1/auth/token`, `/v1/auth/me`.
  - `server/routes/orgs.js`: Orgs CRUD, members list, role change, suspend/reinstate, leave, remove, audit log with strict pagination boundaries.
  - `server/routes/invites.js`: Create invite (raw token returned once, hashed in DB), list, revoke, public peek, accept (upsert user, create active membership, issue tokens).
  - `server/routes/devices.js`: Devices CRUD, device transfer, grant creation (with D9 no-self-grant and no-privilege-laundering checks, D19 pattern validation, D7 half-open time window), grant revoke.
  - `server/routes/sessions.js`: Compound permission check (`session:start` + mode permission), exclusive session enforcement via SQLite unique index, authority snapshot, grandfathering.
- Encountered failure on `demoting a NON-last owner is allowed got 403 want 200`: `assertCanModify` strictly required `callerRank > targetRank`, which prevented an owner (100) from demoting another owner (100). Adjusted `assertCanModify` to permit owner-on-owner modifications (since `assertNotLastOwner` and `selfRoleChange` guards already protect integrity).
- Result: 66/66 tests pass in `scripts/check-api.js`.

## 2026-09-26 13:42 · Phase 5 — Console React SPA and Playwright UI tests

Implemented the complete UI console in `starter/web/`:
- `web/index.css`: Modern glassmorphic dark-mode design system with distinct background colors per `data-org-theme` (Cobalt `#0f172a`, Amber `#26180c`, Emerald `#06281c`, Crimson `#2a0a12`, Slate `#121418`).
- `web/main.jsx`:
  - `data-testid="app-shell"` carrying `data-org-id` and `data-org-theme`.
  - Zero-storage architecture: Access token strictly in React memory (`useState`). Nothing in `localStorage` or `sessionStorage`. Session restored on reload via `/v1/auth/refresh`.
  - Strict presence semantics: Elements are rendered with `data-permission` and `data-state="unlocked"` only when the server resolves `allow`.
  - Dynamic navigation cards: Devices (`device:list`), People (`user:read`), Grants (`user:read`), Sessions (`session:view`), Audit (`audit:read`), Admin (`org:update` or `org:delete`).
  - Device actions per row resolved individually: View, Control, Terminal, Transfer, Rename, Decommission.
  - Invites redeem flow on `/invite/:token` with safe public peek (no data leaks).
  - Failed sign-in live-region error feedback (`role="alert"` and `data-error-code`).
- Installed Playwright Chromium browser (`npx playwright install chromium`).
- Built production bundle (`npm run build`) and executed `npm test`.
- Result: All 25/25 Playwright UI tests pass!

