import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';

// Catalogue of permission keys for the grant creation UI
const PERMISSION_OPTIONS = [
  'device:view',
  'device:control',
  'device:terminal',
  'device:file_transfer',
  'device:update',
  'device:provision',
  'device:*',
  'session:start',
  'session:view',
  'session:terminate',
  'session:*',
  'grant:create',
  'grant:revoke',
  'grant:*',
  'user:read',
  'user:invite',
  'user:role:update',
  'user:remove',
  'user:*',
  'audit:read',
  'org:update',
  'org:delete',
  '*',
];

export function App() {
  // In-memory auth state — NEVER persisted to localStorage or sessionStorage (D13)
  const [auth, setAuth] = useState(null); // { token, userId, name, email, orgId, role, permissions, orgs }
  const [loading, setLoading] = useState(true);

  // Invite route state
  const isInviteRoute = window.location.pathname.startsWith('/invite/');
  const inviteToken = isInviteRoute ? window.location.pathname.replace(/^\/invite\//, '') : null;
  const [inviteData, setInviteData] = useState(null);
  const [inviteError, setInviteError] = useState(null);
  const [inviteAccepted, setInviteAccepted] = useState(false);

  // Login form state
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState(null);

  // Navigation: active card
  const [activeTab, setActiveTab] = useState('devices');

  // Active org data
  const [devices, setDevices] = useState([]);
  const [members, setMembers] = useState([]);
  const [grants, setGrants] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  // Modals & form state
  const [showGrantModal, setShowGrantModal] = useState(false);
  const [grantUser, setGrantUser] = useState('');
  const [grantDevice, setGrantDevice] = useState('');
  const [grantEffect, setGrantEffect] = useState('allow');
  const [selectedGrantPerms, setSelectedGrantPerms] = useState(new Set());

  // Restore session via httpOnly refresh cookie on initial load
  useEffect(() => {
    if (isInviteRoute) {
      // Fetch public invite peek
      fetch(`/v1/invites/${inviteToken}`)
        .then(async (res) => {
          if (!res.ok) {
            setInviteError('Invalid or expired invitation link');
            return;
          }
          const data = await res.json();
          setInviteData(data);
        })
        .catch(() => setInviteError('Network error'))
        .finally(() => setLoading(false));
      return;
    }

    fetch('/v1/auth/refresh', { method: 'POST' })
      .then(async (res) => {
        if (res.ok) {
          const data = await res.json();
          setAuth(data);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [isInviteRoute, inviteToken]);

  // Current org metadata
  const currentOrg = useMemo(() => {
    if (!auth || !auth.orgs) return null;
    return auth.orgs.find((o) => o.id === auth.orgId) || { id: auth.orgId, theme: 'cobalt', name: auth.orgId };
  }, [auth]);

  // Authenticated API caller helper
  const apiCall = useCallback(
    async (method, path, body = null) => {
      if (!auth?.token) throw new Error('Not authenticated');
      const headers = { Authorization: `Bearer ${auth.token}` };
      if (body) headers['Content-Type'] = 'application/json';
      const res = await fetch(path, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        throw Object.assign(new Error(data?.error?.message || 'Request failed'), {
          status: res.status,
          error: data?.error,
        });
      }
      return data;
    },
    [auth?.token]
  );

  // Refresh data for the active view and active org
  const fetchData = useCallback(async () => {
    if (!auth?.token || !auth?.orgId) return;

    // Reset data before fetch to avoid leaking across org switches
    if (activeTab === 'devices' && auth.permissions?.['device:list']?.effect === 'allow') {
      try {
        const res = await apiCall('GET', `/v1/orgs/${auth.orgId}/devices`);
        setDevices(res.devices || []);
      } catch {
        setDevices([]);
      }
    } else if (activeTab === 'people' && auth.permissions?.['user:read']?.effect === 'allow') {
      try {
        const res = await apiCall('GET', `/v1/orgs/${auth.orgId}/members`);
        setMembers(res.members || []);
      } catch {
        setMembers([]);
      }
    } else if (activeTab === 'grants' && auth.permissions?.['user:read']?.effect === 'allow') {
      try {
        const res = await apiCall('GET', `/v1/orgs/${auth.orgId}/grants`);
        setGrants(res.grants || []);
        // Also ensure we have members & devices for the grant form dropdowns
        const memRes = await apiCall('GET', `/v1/orgs/${auth.orgId}/members`).catch(() => ({ members: [] }));
        setMembers(memRes.members || []);
        const devRes = await apiCall('GET', `/v1/orgs/${auth.orgId}/devices`).catch(() => ({ devices: [] }));
        setDevices(devRes.devices || []);
      } catch {
        setGrants([]);
      }
    } else if (activeTab === 'sessions' && auth.permissions?.['session:view']?.effect === 'allow') {
      try {
        const res = await apiCall('GET', `/v1/orgs/${auth.orgId}/sessions`);
        setSessions(res.sessions || []);
      } catch {
        setSessions([]);
      }
    } else if (activeTab === 'audit' && auth.permissions?.['audit:read']?.effect === 'allow') {
      try {
        const res = await apiCall('GET', `/v1/orgs/${auth.orgId}/audit?limit=100`);
        setAuditLogs(res.events || []);
      } catch {
        setAuditLogs([]);
      }
    }
  }, [auth?.token, auth?.orgId, auth?.permissions, activeTab, apiCall]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Login handler
  const handleLogin = async (e) => {
    e.preventDefault();
    if (!loginEmail || !loginPassword) {
      setLoginError({ code: 'VALIDATION', message: 'Email and password are required' });
      return;
    }
    setLoginError(null);
    try {
      const res = await fetch('/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setLoginError({
          code: data?.error?.code || 'AUTH_FAILED',
          message: data?.error?.message || 'Invalid credentials',
        });
        return;
      }
      setAuth(data);
      // Default to devices tab if allowed, else first allowed card
      if (data.permissions?.['device:list']?.effect === 'allow') {
        setActiveTab('devices');
      } else if (data.permissions?.['user:read']?.effect === 'allow') {
        setActiveTab('people');
      } else if (data.permissions?.['session:view']?.effect === 'allow') {
        setActiveTab('sessions');
      } else if (data.permissions?.['audit:read']?.effect === 'allow') {
        setActiveTab('audit');
      }
    } catch {
      setLoginError({ code: 'NETWORK_ERROR', message: 'Unable to connect to server' });
    }
  };

  // Switch Org handler
  const handleSwitchOrg = async (targetOrgId) => {
    if (targetOrgId === auth.orgId) return;
    try {
      // Clear data to prevent leakage across org views
      setDevices([]);
      setMembers([]);
      setGrants([]);
      setSessions([]);
      setAuditLogs([]);

      const data = await apiCall('POST', '/v1/auth/token', { orgId: targetOrgId });
      setAuth((prev) => ({
        ...prev,
        token: data.token,
        orgId: data.orgId,
        role: data.role,
        permissions: data.permissions,
      }));

      // Adjust active tab if the new org doesn't have permission for it
      if (activeTab === 'devices' && data.permissions?.['device:list']?.effect !== 'allow') {
        setActiveTab('sessions');
      }
    } catch (err) {
      alert(err.message);
    }
  };

  // Create Org handler
  const handleCreateOrg = async () => {
    const name = window.prompt('Organization name:');
    if (!name) return;
    try {
      const newOrg = await apiCall('POST', '/v1/orgs', { name });
      // Switch token to the new org
      const switched = await apiCall('POST', '/v1/auth/token', { orgId: newOrg.id });
      setAuth((prev) => ({
        ...prev,
        token: switched.token,
        orgId: newOrg.id,
        role: 'owner',
        permissions: switched.permissions,
        orgs: [...(prev.orgs || []), { id: newOrg.id, name: newOrg.name, theme: newOrg.theme, role: 'owner' }],
      }));
      setDevices([]);
      setActiveTab('devices');
    } catch (err) {
      alert(err.message);
    }
  };

  // Logout handler
  const handleLogout = () => {
    setAuth(null);
    setDevices([]);
    setMembers([]);
    setGrants([]);
    setSessions([]);
    setAuditLogs([]);
  };

  // Invite accept handler
  const handleAcceptInvite = async (e) => {
    e.preventDefault();
    const form = e.target;
    const name = form.elements['name']?.value;
    const password = form.elements['password']?.value;
    try {
      const res = await fetch(`/v1/invites/${inviteToken}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, password }),
      });
      if (!res.ok) {
        setInviteError('Failed to accept invitation');
        return;
      }
      setInviteAccepted(true);
    } catch {
      setInviteError('Network error');
    }
  };

  if (loading) {
    return <div style={{ color: '#fff', padding: 40, textAlign: 'center' }}>Loading RemoteOps...</div>;
  }

  // --- Public Invite Page ---
  if (isInviteRoute && !inviteAccepted) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <h1 className="auth-title">Organization Invitation</h1>
            <p className="auth-subtitle">Join {inviteData?.orgName || 'organization'}</p>
          </div>
          {inviteError ? (
            <div data-testid="invite-error" className="alert-error" role="alert">
              {inviteError}
            </div>
          ) : (
            <form onSubmit={handleAcceptInvite} className="auth-form">
              <div className="form-group">
                <label className="form-label">Role</label>
                <div style={{ display: 'flex' }}>
                  <span data-testid="invite-role" className="role-tag">
                    {inviteData?.role}
                  </span>
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Email</label>
                <input
                  data-testid="invite-email"
                  className="text-input"
                  value={inviteData?.email || ''}
                  readOnly
                />
              </div>
              <div className="form-group">
                <label className="form-label">Your Full Name</label>
                <input
                  name="name"
                  data-testid="invite-name"
                  className="text-input"
                  placeholder="e.g. Alex Morgan"
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Create Password</label>
                <input
                  name="password"
                  type="password"
                  data-testid="invite-password"
                  className="text-input"
                  placeholder="Choose a secure password"
                  required
                />
              </div>
              <button type="submit" data-testid="invite-submit" className="btn-primary" style={{ justifyContent: 'center' }}>
                Accept &amp; Join
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  // --- Login Page ---
  if (!auth) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <div className="brand-logo" style={{ justifyContent: 'center', marginBottom: 8 }}>
              <div className="brand-badge">⚡</div>
              <span>RemoteOps</span>
            </div>
            <h1 className="auth-title">Welcome back</h1>
            <p className="auth-subtitle">Sign in to your organization console</p>
          </div>

          <form data-testid="login-form" onSubmit={handleLogin} className="auth-form">
            {loginError && (
              <div
                data-testid="login-error"
                role="alert"
                aria-live="assertive"
                data-error-code={loginError.code}
                className="alert-error"
              >
                {loginError.message}
              </div>
            )}
            <div className="form-group">
              <label className="form-label">Email</label>
              <input
                data-testid="login-email"
                type="email"
                className="text-input"
                placeholder="name@example.test"
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                data-testid="login-password"
                type="password"
                className="text-input"
                placeholder="••••••••"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
              />
            </div>
            <button
              type="submit"
              data-testid="login-submit"
              className="btn-primary"
              style={{ justifyContent: 'center', marginTop: 8 }}
            >
              Sign In
            </button>
          </form>
        </div>
      </div>
    );
  }

  // --- Authenticated App Shell ---
  const perms = auth.permissions || {};

  return (
    <div
      data-testid="app-shell"
      data-org-id={auth.orgId}
      data-org-theme={currentOrg?.theme || 'cobalt'}
      className="app-shell"
    >
      {/* Top Navbar */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-logo">
            <div className="brand-badge">⚡</div>
            <span>RemoteOps</span>
          </div>

          <div className="org-switcher-wrapper">
            {auth.orgs?.map((o) => (
              <button
                key={o.id}
                data-testid="org-option"
                data-org-id={o.id}
                onClick={() => handleSwitchOrg(o.id)}
                className={`org-button ${o.id === auth.orgId ? 'active' : ''}`}
              >
                {o.name}
              </button>
            ))}
            <button data-testid="create-org" onClick={handleCreateOrg} className="btn-create-org">
              + New Org
            </button>
          </div>
        </div>

        <div className="header-user-section">
          <span data-testid="active-role" className="role-tag">
            {auth.role}
          </span>
          <span style={{ fontSize: '0.88rem', color: 'var(--text-muted)' }}>{auth.email}</span>
          <button onClick={handleLogout} className="btn-signout">
            Sign out
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="app-body">
        {/* Sidebar Nav */}
        <nav className="sidebar-nav">
          {perms['device:list']?.effect === 'allow' && (
            <button
              data-testid="nav-devices"
              onClick={() => setActiveTab('devices')}
              className={`nav-item ${activeTab === 'devices' ? 'active' : ''}`}
            >
              <span>🖥️</span> Devices
            </button>
          )}

          {perms['user:read']?.effect === 'allow' && (
            <button
              data-testid="nav-people"
              onClick={() => setActiveTab('people')}
              className={`nav-item ${activeTab === 'people' ? 'active' : ''}`}
            >
              <span>👥</span> People
            </button>
          )}

          {perms['user:read']?.effect === 'allow' && (
            <button
              data-testid="nav-grants"
              onClick={() => setActiveTab('grants')}
              className={`nav-item ${activeTab === 'grants' ? 'active' : ''}`}
            >
              <span>🛡️</span> Grants
            </button>
          )}

          {perms['session:view']?.effect === 'allow' && (
            <button
              data-testid="nav-sessions"
              onClick={() => setActiveTab('sessions')}
              className={`nav-item ${activeTab === 'sessions' ? 'active' : ''}`}
            >
              <span>⚡</span> Sessions
            </button>
          )}

          {perms['audit:read']?.effect === 'allow' && (
            <button
              data-testid="nav-audit"
              onClick={() => setActiveTab('audit')}
              className={`nav-item ${activeTab === 'audit' ? 'active' : ''}`}
            >
              <span>📋</span> Audit
            </button>
          )}

          {(perms['org:update']?.effect === 'allow' || perms['org:delete']?.effect === 'allow') && (
            <button
              data-testid="nav-admin"
              onClick={() => setActiveTab('admin')}
              className={`nav-item ${activeTab === 'admin' ? 'active' : ''}`}
            >
              <span>⚙️</span> Admin
            </button>
          )}
        </nav>

        {/* Panel View */}
        <main className="main-view-panel">
          {/* DEVICES TAB */}
          {activeTab === 'devices' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Devices</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Connected infrastructure and remote targets
                  </p>
                </div>
                <div className="panel-actions">
                  {perms['device:provision']?.effect === 'allow' && (
                    <button
                      data-testid="add-device"
                      data-permission="device:provision"
                      data-state="unlocked"
                      className="btn-primary"
                      onClick={async () => {
                        const name = window.prompt('Device name:');
                        const kind = window.prompt('Device kind (macos, windows, linux, android, ios):', 'linux');
                        if (name && kind) {
                          await apiCall('POST', `/v1/orgs/${auth.orgId}/devices`, { name, kind });
                          fetchData();
                        }
                      }}
                    >
                      + Add Device
                    </button>
                  )}
                </div>
              </div>

              {devices.length === 0 ? (
                <div data-testid="devices-empty" className="empty-box">
                  No devices provisioned for this organization.
                </div>
              ) : (
                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Device Name</th>
                        <th>Kind</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {devices.map((device) => {
                        const dp = device.permissions || {};
                        return (
                          <tr key={device.id} data-testid="device-row" data-device-id={device.id}>
                            <td style={{ fontWeight: 600 }}>{device.name}</td>
                            <td style={{ textTransform: 'uppercase', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                              {device.kind}
                            </td>
                            <td>
                              <span className={`status-pill ${device.online ? 'online' : 'offline'}`}>
                                {device.online ? '● Online' : '○ Offline'}
                              </span>
                            </td>
                            <td className="actions-cell">
                              {dp['device:view']?.effect === 'allow' && (
                                <button
                                  data-testid="start-view"
                                  data-permission="device:view"
                                  data-state="unlocked"
                                  className="btn-secondary"
                                  onClick={async () => {
                                    await apiCall('POST', `/v1/orgs/${auth.orgId}/sessions`, {
                                      deviceId: device.id,
                                      mode: 'view',
                                    });
                                    alert('View session started');
                                  }}
                                >
                                  View
                                </button>
                              )}
                              {dp['device:control']?.effect === 'allow' && (
                                <button
                                  data-testid="start-control"
                                  data-permission="device:control"
                                  data-state="unlocked"
                                  className="btn-secondary"
                                  onClick={async () => {
                                    await apiCall('POST', `/v1/orgs/${auth.orgId}/sessions`, {
                                      deviceId: device.id,
                                      mode: 'control',
                                    });
                                    alert('Control session started');
                                  }}
                                >
                                  Control
                                </button>
                              )}
                              {dp['device:terminal']?.effect === 'allow' && (
                                <button
                                  data-testid="start-terminal"
                                  data-permission="device:terminal"
                                  data-state="unlocked"
                                  className="btn-secondary"
                                  onClick={async () => {
                                    await apiCall('POST', `/v1/orgs/${auth.orgId}/sessions`, {
                                      deviceId: device.id,
                                      mode: 'terminal',
                                    });
                                    alert('Terminal session started');
                                  }}
                                >
                                  Terminal
                                </button>
                              )}
                              {dp['device:file_transfer']?.effect === 'allow' && (
                                <button
                                  data-testid="transfer-files"
                                  data-permission="device:file_transfer"
                                  data-state="unlocked"
                                  className="btn-secondary"
                                >
                                  Transfer
                                </button>
                              )}
                              {dp['device:update']?.effect === 'allow' && (
                                <button
                                  data-testid="rename-device"
                                  data-permission="device:update"
                                  data-state="unlocked"
                                  className="btn-secondary"
                                  onClick={async () => {
                                    const newName = window.prompt('New name:', device.name);
                                    if (newName) {
                                      await apiCall('PATCH', `/v1/orgs/${auth.orgId}/devices/${device.id}`, {
                                        name: newName,
                                      });
                                      fetchData();
                                    }
                                  }}
                                >
                                  Rename
                                </button>
                              )}
                              {dp['device:provision']?.effect === 'allow' && (
                                <button
                                  data-testid="decommission-device"
                                  data-permission="device:provision"
                                  data-state="unlocked"
                                  className="btn-danger"
                                  onClick={async () => {
                                    if (window.confirm(`Decommission ${device.name}?`)) {
                                      await apiCall('DELETE', `/v1/orgs/${auth.orgId}/devices/${device.id}`);
                                      fetchData();
                                    }
                                  }}
                                >
                                  Decommission
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* PEOPLE TAB */}
          {activeTab === 'people' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">People</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Team members, roles, and status
                  </p>
                </div>
                <div className="panel-actions">
                  {perms['user:invite']?.effect === 'allow' && (
                    <button
                      data-testid="invite-user"
                      data-permission="user:invite"
                      data-state="unlocked"
                      className="btn-primary"
                      onClick={async () => {
                        const email = window.prompt('Email to invite:');
                        const role = window.prompt('Role (admin, operator, auditor, viewer):', 'viewer');
                        if (email && role) {
                          const res = await apiCall('POST', `/v1/orgs/${auth.orgId}/invites`, { email, role });
                          window.prompt('Invite created! Share this token:', res.inviteToken);
                        }
                      }}
                    >
                      + Invite Member
                    </button>
                  )}
                </div>
              </div>

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Name / Email</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((member) => (
                      <tr key={member.user_id} data-testid="user-row" data-user-id={member.user_id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{member.name || member.email}</div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{member.email}</div>
                        </td>
                        <td>
                          {perms['user:role:update']?.effect === 'allow' ? (
                            <select
                              data-testid="role-select"
                              data-permission="user:role:update"
                              data-state="unlocked"
                              className="select-input"
                              value={member.role}
                              onChange={async (e) => {
                                const newRole = e.target.value;
                                await apiCall('PATCH', `/v1/orgs/${auth.orgId}/members/${member.user_id}`, {
                                  role: newRole,
                                });
                                fetchData();
                              }}
                            >
                              <option value="owner">Owner</option>
                              <option value="admin">Admin</option>
                              <option value="operator">Operator</option>
                              <option value="auditor">Auditor</option>
                              <option value="viewer">Viewer</option>
                            </select>
                          ) : (
                            <span className="role-tag">{member.role}</span>
                          )}
                        </td>
                        <td>
                          <span
                            className={`status-pill ${
                              member.status === 'active' ? 'online' : 'offline'
                            }`}
                          >
                            {member.status}
                          </span>
                        </td>
                        <td className="actions-cell">
                          {perms['user:remove']?.effect === 'allow' && (
                            <>
                              <button
                                data-testid="suspend-user"
                                data-permission="user:remove"
                                data-state="unlocked"
                                className="btn-secondary"
                                onClick={async () => {
                                  if (member.status === 'suspended') {
                                    await apiCall('DELETE', `/v1/orgs/${auth.orgId}/members/${member.user_id}/suspend`);
                                  } else {
                                    await apiCall('POST', `/v1/orgs/${auth.orgId}/members/${member.user_id}/suspend`);
                                  }
                                  fetchData();
                                }}
                              >
                                {member.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                              </button>
                              <button
                                data-testid="remove-user"
                                data-permission="user:remove"
                                data-state="unlocked"
                                className="btn-danger"
                                onClick={async () => {
                                  if (window.confirm(`Remove member?`)) {
                                    await apiCall('DELETE', `/v1/orgs/${auth.orgId}/members/${member.user_id}`);
                                    fetchData();
                                  }
                                }}
                              >
                                Remove
                              </button>
                            </>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* GRANTS TAB */}
          {activeTab === 'grants' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Grants</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Explicit allow &amp; deny exceptions (D1/D6)
                  </p>
                </div>
                <div className="panel-actions">
                  {perms['grant:create']?.effect === 'allow' && (
                    <button
                      data-testid="new-grant"
                      data-permission="grant:create"
                      data-state="unlocked"
                      className="btn-primary"
                      onClick={() => setShowGrantModal(true)}
                    >
                      + New Grant
                    </button>
                  )}
                </div>
              </div>

              {/* New Grant Modal / Form */}
              {showGrantModal && (
                <div className="modal-overlay">
                  <div className="modal-content">
                    <h3 className="modal-title">Create Access Grant</h3>

                    <div className="form-group">
                      <label className="form-label">User</label>
                      <select
                        data-testid="grant-user"
                        className="select-input"
                        value={grantUser}
                        onChange={(e) => setGrantUser(e.target.value)}
                      >
                        <option value="">Select a user...</option>
                        {members.map((m) => (
                          <option key={m.user_id} value={m.user_id}>
                            {m.name || m.email} ({m.role})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Target Device (optional)</label>
                      <select
                        data-testid="grant-device"
                        className="select-input"
                        value={grantDevice}
                        onChange={(e) => setGrantDevice(e.target.value)}
                      >
                        <option value="">Org-wide (All Devices)</option>
                        {devices.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} ({d.kind})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Effect</label>
                      <select
                        data-testid="grant-effect"
                        className="select-input"
                        value={grantEffect}
                        onChange={(e) => setGrantEffect(e.target.value)}
                      >
                        <option value="allow">Allow</option>
                        <option value="deny">Deny</option>
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Permissions</label>
                      <div className="checkbox-grid">
                        {PERMISSION_OPTIONS.map((p) => (
                          <label key={p} className="checkbox-label">
                            <input
                              type="checkbox"
                              data-permission-key={p}
                              checked={selectedGrantPerms.has(p)}
                              onChange={(e) => {
                                const next = new Set(selectedGrantPerms);
                                if (e.target.checked) next.add(p);
                                else next.delete(p);
                                setSelectedGrantPerms(next);
                              }}
                            />
                            <span>{p}</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => {
                          setShowGrantModal(false);
                          setSelectedGrantPerms(new Set());
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        data-testid="grant-submit"
                        className="btn-primary"
                        onClick={async () => {
                          if (!grantUser) {
                            alert('Please select a user');
                            return;
                          }
                          if (selectedGrantPerms.size === 0) {
                            alert('Please select at least one permission');
                            return;
                          }
                          try {
                            await apiCall('POST', `/v1/orgs/${auth.orgId}/grants`, {
                              userId: grantUser,
                              deviceId: grantDevice || null,
                              effect: grantEffect,
                              permissions: Array.from(selectedGrantPerms),
                            });
                            setShowGrantModal(false);
                            setSelectedGrantPerms(new Set());
                            fetchData();
                          } catch (err) {
                            alert(err.message);
                          }
                        }}
                      >
                        Create Grant
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Effect</th>
                      <th>Permissions</th>
                      <th>Target Device</th>
                      <th>User ID</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {grants.map((grant) => (
                      <tr key={grant.id} data-testid="grant-row" data-effect={grant.effect}>
                        <td>
                          <span className={`status-pill ${grant.effect}`}>
                            {grant.effect.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {grant.permissions?.map((p) => (
                              <span key={p} className="role-tag" style={{ fontSize: '0.72rem' }}>
                                {p}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                          {grant.deviceId ? grant.deviceId : 'All Devices'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                          {grant.userId}
                        </td>
                        <td className="actions-cell">
                          {perms['grant:revoke']?.effect === 'allow' && (
                            <button
                              data-testid="revoke-grant"
                              data-permission="grant:revoke"
                              data-state="unlocked"
                              className="btn-danger"
                              onClick={async () => {
                                if (window.confirm('Revoke this grant?')) {
                                  await apiCall('DELETE', `/v1/orgs/${auth.orgId}/grants/${grant.id}`);
                                  fetchData();
                                }
                              }}
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SESSIONS TAB */}
          {activeTab === 'sessions' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Sessions</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Active and past remote connections
                  </p>
                </div>
                <div className="panel-actions">
                  {perms['session:start']?.effect === 'allow' && (
                    <button
                      data-testid="new-session"
                      data-permission="session:start"
                      data-state="unlocked"
                      className="btn-primary"
                      onClick={async () => {
                        const deviceId = window.prompt('Device ID:');
                        const mode = window.prompt('Mode (view, control, terminal):', 'view');
                        if (deviceId && mode) {
                          await apiCall('POST', `/v1/orgs/${auth.orgId}/sessions`, { deviceId, mode });
                          fetchData();
                        }
                      }}
                    >
                      + Start Session
                    </button>
                  )}
                </div>
              </div>

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Device ID</th>
                      <th>Mode</th>
                      <th>State</th>
                      <th>User</th>
                      <th>Started</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((session) => {
                      const canStop =
                        session.state !== 'ended' &&
                        (session.user_id === auth.userId || perms['session:terminate']?.effect === 'allow');
                      return (
                        <tr key={session.id} data-testid="session-row">
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                            {session.device_id}
                          </td>
                          <td style={{ textTransform: 'uppercase', fontSize: '0.8rem', fontWeight: 600 }}>
                            {session.mode}
                          </td>
                          <td>
                            <span
                              className={`status-pill ${
                                session.state === 'active' ? 'online' : 'offline'
                              }`}
                            >
                              {session.state}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.85rem' }}>{session.user_id}</td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                            {session.started_at ? new Date(session.started_at).toLocaleTimeString() : '-'}
                          </td>
                          <td className="actions-cell">
                            {canStop && (
                              <button
                                data-testid="stop-session"
                                className="btn-danger"
                                onClick={async () => {
                                  await apiCall('DELETE', `/v1/sessions/${session.id}`);
                                  fetchData();
                                }}
                              >
                                End Session
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* AUDIT TAB */}
          {activeTab === 'audit' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Audit Log</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Immutable record of system actions and denied attempts
                  </p>
                </div>
              </div>

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.id} data-testid="audit-row">
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          {log.created_at ? new Date(log.created_at).toLocaleTimeString() : '-'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                          {log.actor_id}
                        </td>
                        <td style={{ fontWeight: 600 }}>{log.action}</td>
                        <td style={{ fontSize: '0.85rem' }}>
                          {log.target_type}: {log.target_id || '-'}
                        </td>
                        <td>
                          <span className={`status-pill ${log.result}`}>
                            {log.result}
                            {log.reason_code ? ` (${log.reason_code})` : ''}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ADMIN TAB */}
          {activeTab === 'admin' && (
            <div>
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Organization Settings</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                    Governance and organization lifecycle
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 480 }}>
                {perms['org:update']?.effect === 'allow' && (
                  <div
                    style={{
                      background: 'rgba(255,255,255,0.02)',
                      padding: 20,
                      borderRadius: 12,
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <h3 style={{ fontSize: '1.1rem', marginBottom: 8 }}>Rename Organization</h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: 16 }}>
                      Change the public display name of this organization.
                    </p>
                    <button
                      data-testid="rename-org"
                      data-permission="org:update"
                      data-state="unlocked"
                      className="btn-secondary"
                      onClick={async () => {
                        const newName = window.prompt('New organization name:', currentOrg?.name);
                        if (newName) {
                          await apiCall('PATCH', `/v1/orgs/${auth.orgId}`, { name: newName });
                          setAuth((prev) => ({
                            ...prev,
                            orgs: prev.orgs.map((o) => (o.id === auth.orgId ? { ...o, name: newName } : o)),
                          }));
                        }
                      }}
                    >
                      Rename Organization
                    </button>
                  </div>
                )}

                {perms['org:delete']?.effect === 'allow' && (
                  <div
                    style={{
                      background: 'rgba(239, 68, 68, 0.05)',
                      padding: 20,
                      borderRadius: 12,
                      border: '1px solid rgba(239, 68, 68, 0.2)',
                    }}
                  >
                    <h3 style={{ fontSize: '1.1rem', color: '#fca5a5', marginBottom: 8 }}>
                      Delete Organization
                    </h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: 16 }}>
                      Permanently decommission this organization and its resources.
                    </p>
                    <button
                      data-testid="delete-org"
                      data-permission="org:delete"
                      data-state="unlocked"
                      className="btn-danger"
                      onClick={async () => {
                        if (window.confirm('Are you sure you want to delete this organization?')) {
                          await apiCall('DELETE', `/v1/orgs/${auth.orgId}`);
                          handleLogout();
                        }
                      }}
                    >
                      Delete Organization
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
