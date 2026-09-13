/**
 * Thin fetch wrapper.
 *
 * Auth is a same-site HttpOnly cookie, so every call just needs
 * `credentials: 'include'`; there is no token for the SPA to hold.
 */

class ApiError extends Error {
  constructor(status, detail, body) {
    super(detail || `HTTP ${status}`)
    this.status = status
    this.detail = detail
    this.body = body
  }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const options = {
    method,
    credentials: 'include',
    headers: { Accept: 'application/json', ...headers },
  }
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(body)
  }

  const response = await fetch(path, options)
  if (response.status === 204) return null

  const text = await response.text()
  let payload = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }

  if (!response.ok) {
    const detail =
      (payload && (payload.detail || payload.error || payload.message)) ||
      (typeof payload === 'string' ? payload : null)
    throw new ApiError(response.status, detail, payload)
  }
  return raw ? { data: payload, response } : payload
}

const qs = (params) => {
  const search = new URLSearchParams()
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') search.append(key, value)
  })
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

export const api = {
  ApiError,

  // -- auth ---------------------------------------------------------------
  login: (username, password) =>
    request('/api/auth/login', { method: 'POST', body: { username, password } }),
  logout: () => request('/api/auth/logout', { method: 'POST' }),
  me: () => request('/api/auth/me'),
  changePassword: (current_password, new_password) =>
    request('/api/auth/password', { method: 'POST', body: { current_password, new_password } }),
  oidcStatus: () => request('/api/auth/oidc/status'),

  listTokens: () => request('/api/auth/tokens'),
  createToken: (payload) => request('/api/auth/tokens', { method: 'POST', body: payload }),
  revokeToken: (id) => request(`/api/auth/tokens/${id}`, { method: 'DELETE' }),

  // -- search -------------------------------------------------------------
  search: (params) => request(`/api/search${qs(params)}`),
  packageDetail: (ecosystem, name) =>
    request(`/api/packages/${ecosystem}/${encodeURIComponent(name)}`),
  clientConfig: () => request('/api/client-config'),

  // -- CLI ----------------------------------------------------------------
  cliPending: (code) => request(`/api/cli/auth/pending/${encodeURIComponent(code)}`),
  cliApprove: (payload) => request('/api/cli/auth/approve', { method: 'POST', body: payload }),
  cliAudit: (payload) => request('/api/cli/audit', { method: 'POST', body: payload }),

  // -- admin: users -------------------------------------------------------
  listUsers: () => request('/api/admin/users'),
  createUser: (payload) => request('/api/admin/users', { method: 'POST', body: payload }),
  updateUser: (id, payload) => request(`/api/admin/users/${id}`, { method: 'PATCH', body: payload }),
  deleteUser: (id) => request(`/api/admin/users/${id}`, { method: 'DELETE' }),

  // -- admin: upstreams ---------------------------------------------------
  listUpstreams: () => request('/api/admin/upstreams'),
  createUpstream: (payload) => request('/api/admin/upstreams', { method: 'POST', body: payload }),
  updateUpstream: (id, payload) =>
    request(`/api/admin/upstreams/${id}`, { method: 'PATCH', body: payload }),
  deleteUpstream: (id) => request(`/api/admin/upstreams/${id}`, { method: 'DELETE' }),
  testUpstream: (id) => request(`/api/admin/upstreams/${id}/test`, { method: 'POST' }),
  indexUpstream: (id) => request(`/api/admin/upstreams/${id}/index`, { method: 'POST' }),

  // -- admin: rules & settings --------------------------------------------
  listRules: () => request('/api/admin/rules'),
  createRule: (payload) => request('/api/admin/rules', { method: 'POST', body: payload }),
  updateRule: (id, payload) => request(`/api/admin/rules/${id}`, { method: 'PATCH', body: payload }),
  deleteRule: (id) => request(`/api/admin/rules/${id}`, { method: 'DELETE' }),
  testRule: (params) => request(`/api/admin/rules/test${qs(params)}`, { method: 'POST' }),
  previewSpec: (payload) =>
    request('/api/admin/rules/preview-spec', { method: 'POST', body: payload }),

  getSettings: () => request('/api/admin/settings'),
  updateCvePolicy: (payload) =>
    request('/api/admin/settings/cve-policy', { method: 'PUT', body: payload }),
  updateAllowlistMode: (enabled) =>
    request('/api/admin/settings/allowlist-mode', { method: 'PUT', body: { enabled } }),

  // -- admin: stats & logs -------------------------------------------------
  statsOverview: (days) => request(`/api/admin/stats/overview${qs({ days })}`),
  topPackages: (params) => request(`/api/admin/stats/top-packages${qs(params)}`),
  downloadsTimeline: (days) => request(`/api/admin/stats/downloads-timeline${qs({ days })}`),
  recentLogins: (limit) => request(`/api/admin/stats/recent-logins${qs({ limit })}`),
  storageStats: () => request('/api/admin/stats/storage'),

  auditLog: (params) => request(`/api/admin/audit${qs(params)}`),
  auditActions: () => request('/api/admin/audit/actions'),
  downloadLog: (params) => request(`/api/admin/downloads${qs(params)}`),

  // -- admin: security -----------------------------------------------------
  vulnerabilities: (params) => request(`/api/admin/vulnerabilities${qs(params)}`),
  vulnerabilityAffected: (id) => request(`/api/admin/vulnerabilities/${id}/affected`),
  suppressVulnerability: (linkId, payload) =>
    request(`/api/admin/vulnerabilities/links/${linkId}/suppress`, { method: 'POST', body: payload }),
  triggerScan: (params) => request(`/api/admin/scan${qs(params)}`, { method: 'POST' }),
  rescoreVulnerabilities: () => request('/api/admin/rescore', { method: 'POST' }),

  // -- admin: packages & cache ---------------------------------------------
  adminPackages: (params) => request(`/api/admin/packages${qs(params)}`),
  adminPackageDetail: (id) => request(`/api/admin/packages/${id}`),
  deletePackage: (id, purgeOnly) =>
    request(`/api/admin/packages/${id}${qs({ purge_only: purgeOnly })}`, { method: 'DELETE' }),
  purgeCache: (params) => request(`/api/admin/cache/purge${qs(params)}`, { method: 'POST' }),
  garbageCollect: () => request('/api/admin/cache/gc', { method: 'POST' }),

  health: () => request('/api/health/detailed'),

  // -- documentation shipped with this build --------------------------------
  helpPages: () => request('/api/help/pages'),
  helpPage: (slug) => request(`/api/help/pages/${encodeURIComponent(slug)}`),
}

export default api
