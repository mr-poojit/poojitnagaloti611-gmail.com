// Route registration. The router is deliberately tiny: createRouter() from
// ../router.js, first match wins, so register specific paths before parameterised
// ones ('/members/me' before '/members/:userId').
//
// YOURS TO WRITE. The file list is empty on purpose — every endpoint in BRIEF.md §5.1
// is yours to add, and the response shapes the console reads are in §5.2.
//
// Suggested split, mirroring the API: auth, orgs (orgs + members + effective + audit),
// invites, devices (devices + grants), sessions. Keep the registration order here.
//
// The server boots with this file empty: every /v1/* request returns 404 until you
// register something. That is the intended starting line.

import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerOrgRoutes(router, deps);
  registerInviteRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  registerSessionRoutes(router, deps);
}

