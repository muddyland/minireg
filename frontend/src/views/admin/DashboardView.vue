<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { ecosystemBadge, formatBytes, formatNumber, relativeTime } from '@/utils/format'

const days = ref(30)
const overview = ref(null)
const top = ref([])
const logins = ref([])
const timeline = ref([])
const health = ref(null)
const loading = ref(true)

const maxDownloads = computed(() => Math.max(1, ...top.value.map((p) => p.downloads)))

const dailyTotals = computed(() => {
  const byDay = new Map()
  for (const point of timeline.value) {
    byDay.set(point.day, (byDay.get(point.day) || 0) + point.downloads)
  }
  return [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b))
})
const maxDaily = computed(() => Math.max(1, ...dailyTotals.value.map(([, v]) => v)))

const cacheHitPercent = computed(() => {
  const rate = overview.value?.downloads?.cache_hit_rate
  return rate === null || rate === undefined ? null : Math.round(rate * 100)
})

async function load() {
  loading.value = true
  const [o, t, l, tl, h] = await Promise.all([
    api.statsOverview(days.value),
    api.topPackages({ days: days.value, limit: 12 }),
    api.recentLogins(10),
    api.downloadsTimeline(days.value),
    api.health().catch(() => null),
  ])
  overview.value = o
  top.value = t.packages
  logins.value = l.logins
  timeline.value = tl.points
  health.value = h
  loading.value = false
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Dashboard</h1>
      <p class="page-sub">Registry activity over the last {{ days }} days.</p>
    </div>
    <select v-model.number="days" style="width: auto" @change="load">
      <option :value="7">Last 7 days</option>
      <option :value="30">Last 30 days</option>
      <option :value="90">Last 90 days</option>
      <option :value="365">Last year</option>
    </select>
  </div>

  <div v-if="loading" class="empty">Loading…</div>

  <template v-else-if="overview">
    <div class="grid grid-4 mb">
      <div class="card stat">
        <div class="stat-label">Packages</div>
        <div class="stat-value">{{ formatNumber(overview.packages.with_content) }}</div>
        <div class="stat-meta">
          {{ formatNumber(overview.packages.npm) }} npm · {{ formatNumber(overview.packages.pypi) }} PyPI
          <template v-if="overview.packages.index_only">
            <br />
            <span
              class="faint"
              title="Names imported by indexing an upstream, not yet resolved to versions"
            >
              + {{ formatNumber(overview.packages.index_only) }} indexed names
            </span>
          </template>
        </div>
      </div>
      <div class="card stat">
        <div class="stat-label">Downloads</div>
        <div class="stat-value">{{ formatNumber(overview.downloads.artifacts) }}</div>
        <div class="stat-meta">
          {{ formatNumber(overview.downloads.metadata) }} metadata requests
        </div>
      </div>
      <div class="card stat">
        <div class="stat-label">Bytes served</div>
        <div class="stat-value">{{ formatBytes(overview.downloads.bytes_served) }}</div>
        <div class="stat-meta">
          <template v-if="cacheHitPercent !== null">{{ cacheHitPercent }}% served from cache</template>
          <template v-else>no traffic yet</template>
        </div>
      </div>
      <div class="card stat">
        <div class="stat-label">Known CVEs</div>
        <div class="stat-value">{{ formatNumber(overview.security.known_cves) }}</div>
        <div class="stat-meta">
          affecting {{ formatNumber(overview.security.affected_versions) }} versions
        </div>
      </div>
    </div>

    <div class="grid grid-2 mb">
      <div class="card">
        <div class="card-head">
          <h3>Daily downloads</h3>
          <span class="faint small">
            {{ dailyTotals.length }} {{ dailyTotals.length === 1 ? 'day' : 'days' }} with activity
          </span>
        </div>
        <div class="card-body">
          <div v-if="!dailyTotals.length" class="empty">No downloads recorded yet.</div>
          <div v-else>
            <div class="spark">
              <div
                v-for="[day, count] in dailyTotals"
                :key="day"
                class="spark-bar"
                :style="{ height: `${Math.max(3, (count / maxDaily) * 100)}%` }"
                :title="`${day}: ${count} requests`"
              />
            </div>
            <div class="row faint small" style="justify-content: space-between; margin-top: 0.4rem">
              <span>{{ dailyTotals[0]?.[0]?.slice(0, 10) }}</span>
              <span>peak {{ formatNumber(maxDaily) }}/day</span>
              <span>{{ dailyTotals[dailyTotals.length - 1]?.[0]?.slice(0, 10) }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>System</h3></div>
        <div class="card-body small">
          <div class="row" style="justify-content: space-between">
            <span class="dim">Upstreams healthy</span>
            <span>
              <span
                class="badge"
                :class="overview.upstreams.healthy === overview.upstreams.enabled ? 'badge-ok' : 'badge-warn'"
              >
                {{ overview.upstreams.healthy }} / {{ overview.upstreams.enabled }}
              </span>
            </span>
          </div>
          <div class="row" style="justify-content: space-between">
            <span class="dim">Versions indexed</span><span>{{ formatNumber(overview.versions) }}</span>
          </div>
          <div class="row" style="justify-content: space-between">
            <span class="dim">Files cached</span>
            <span>{{ formatNumber(overview.files.cached) }} / {{ formatNumber(overview.files.total) }}</span>
          </div>
          <div class="row" style="justify-content: space-between">
            <span class="dim">Users</span>
            <span>{{ overview.users.active_in_window }} active of {{ overview.users.total }}</span>
          </div>
          <template v-if="health">
            <div class="row" style="justify-content: space-between; margin-top: 0.5rem">
              <span class="dim">Database</span>
              <span class="badge" :class="health.checks.database.ok ? 'badge-ok' : 'badge-danger'">
                {{ health.checks.database.ok ? 'ok' : 'down' }}
              </span>
            </div>
            <div class="row" style="justify-content: space-between">
              <span class="dim">Redis cache</span>
              <span class="badge" :class="health.checks.redis.ok ? 'badge-ok' : 'badge-warn'">
                {{ health.checks.redis.ok ? 'ok' : 'unavailable' }}
              </span>
            </div>
          </template>
        </div>
      </div>
    </div>

    <div class="grid grid-2 grid-top">
      <div class="card">
        <div class="card-head">
          <h3>Most downloaded</h3>
          <router-link :to="{ name: 'admin-packages' }" class="small">All packages →</router-link>
        </div>
        <div class="card-body">
          <div v-if="!top.length" class="empty">No downloads recorded yet.</div>
          <div v-else class="bars">
            <div v-for="pkg in top" :key="`${pkg.ecosystem}:${pkg.name}`" class="bar-row">
              <div class="truncate small" :title="pkg.name">
                <span class="badge" :class="ecosystemBadge(pkg.ecosystem)">
                  {{ pkg.ecosystem }}
                </span>
                {{ pkg.name }}
              </div>
              <div class="bar-track">
                <div
                  class="bar-fill"
                  :class="pkg.ecosystem"
                  :style="{ width: `${(pkg.downloads / maxDownloads) * 100}%` }"
                />
              </div>
              <span class="small nowrap faint">{{ formatNumber(pkg.downloads) }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <h3>Recent sign-ins</h3>
          <router-link :to="{ name: 'audit' }" class="small">Audit log →</router-link>
        </div>
        <div class="card-body tight">
          <div v-if="!logins.length" class="empty">No sign-ins recorded.</div>
          <div v-else class="table-wrap">
            <table>
              <thead>
                <tr><th>User</th><th>Method</th><th>When</th><th>IP</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="entry in logins" :key="entry.ts + entry.username">
                  <td>{{ entry.username || '—' }}</td>
                  <td><span class="badge">{{ entry.method }}</span></td>
                  <td class="dim small nowrap">{{ relativeTime(entry.ts) }}</td>
                  <td class="mono faint small">{{ entry.ip || '—' }}</td>
                  <td>
                    <span class="badge" :class="entry.success ? 'badge-ok' : 'badge-danger'">
                      {{ entry.success ? 'ok' : 'failed' }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>
