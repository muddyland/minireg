export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '—'
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value.toFixed(value >= 100 || exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

export function formatNumber(value) {
  if (value === null || value === undefined) return '—'
  return new Intl.NumberFormat().format(value)
}

export function formatDate(value, withTime = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return withTime ? date.toLocaleString() : date.toLocaleDateString()
}

export function formatDateTime(value) {
  return formatDate(value, true)
}

export function relativeTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  const steps = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [2592000, 'day', 86400],
    [31536000, 'month', 2592000],
    [Infinity, 'year', 31536000],
  ]
  for (const [limit, unit, divisor] of steps) {
    if (Math.abs(seconds) < limit) {
      const amount = Math.round(seconds / divisor)
      return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(-amount, unit)
    }
  }
  return formatDate(value)
}

/** Map a CVSS base score onto the FIRST.org qualitative band. */
export function severityClass(score) {
  if (score === null || score === undefined) return 'sev-low'
  if (score >= 9.0) return 'sev-critical'
  if (score >= 7.0) return 'sev-high'
  if (score >= 4.0) return 'sev-medium'
  return 'sev-low'
}

export function severityLabel(score) {
  if (score === null || score === undefined) return 'unknown'
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

export function percent(value, total) {
  if (!total) return 0
  return Math.min(100, Math.round((value / total) * 100))
}

// The badge classes are named after the ecosystem values themselves, so this
// stays correct as ecosystems are added. It replaced a
// `eco === 'npm' ? 'badge-npm' : 'badge-pypi'` ternary repeated across eight
// views, which silently mislabelled every ecosystem that was not npm the
// moment a third one existed.
const ECOSYSTEMS = ['npm', 'pypi', 'cargo']

export function ecosystemBadge(ecosystem) {
  return ECOSYSTEMS.includes(ecosystem) ? `badge-${ecosystem}` : 'badge'
}

export function ecosystemLabel(ecosystem) {
  return ecosystem === 'pypi' ? 'PyPI' : ecosystem
}
