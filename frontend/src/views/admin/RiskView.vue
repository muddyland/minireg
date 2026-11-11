<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import api from '@/api/client'
import { formatNumber, relativeTime } from '@/utils/format'
import { errorMessage } from '@/utils/errors'
import EcosystemBadge from '@/components/EcosystemBadge.vue'

// "Where's my risk": every known vulnerability, packages and images in one
// list, exposed ones (served or pulled lately) first.
const data = ref(null)
const loading = ref(true)
const error = ref(null)
const filters = ref({ source: 'all', min_severity: 'high', only_in_use: true, search: '', in_use_days: 30 })
const openId = ref(null)
const detail = ref({})
const detailError = ref(null)

let timer = null
async function load() {
  loading.value = true
  error.value = null
  try {
    data.value = await api.risk({
      ...filters.value,
      search: filters.value.search.trim() || undefined,
    })
  } catch (err) {
    error.value = errorMessage(err, 'Could not load the risk overview.')
  } finally {
    loading.value = false
  }
}
watch(
  () => ({ ...filters.value }),
  () => {
    clearTimeout(timer)
    timer = setTimeout(load, 250)
  },
)

async function toggle(item) {
  if (openId.value === item.id) {
    openId.value = null
    return
  }
  openId.value = item.id
  detailError.value = null
  if (!detail.value[item.id]) {
    try {
      detail.value = { ...detail.value, [item.id]: await api.riskDetail(item.id) }
    } catch (err) {
      detailError.value = errorMessage(err, 'Could not load what this affects.')
    }
  }
}

const SEV_CLASS = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }
const summary = computed(() => data.value?.summary)
// A long list renders in pages; the summary above counts all of it.
const PAGE = 50
const shown = ref(PAGE)
const visible = computed(() => (data.value?.items || []).slice(0, shown.value))
watch(data, () => (shown.value = PAGE))

function advisoryUrl(id) {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Risk</h1>
      <p class="page-sub">
        Every known vulnerability in your packages and images, in one place. What was served or
        pulled in the last {{ filters.in_use_days }} days comes first: that is the risk you are
        carrying right now.
      </p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>

  <div v-if="summary" class="risk-stats mb">
    <div class="card stat">
      <div class="stat-label">Known exploited, in use</div>
      <div class="stat-value" :class="{ 'text-danger': summary.kev_in_use }">{{ formatNumber(summary.kev_in_use) }}</div>
      <div class="stat-meta">On CISA's known-exploited list and served lately</div>
    </div>
    <div class="card stat">
      <div class="stat-label">Critical, in use</div>
      <div class="stat-value" :class="{ 'text-danger': summary.critical_in_use }">{{ formatNumber(summary.critical_in_use) }}</div>
      <div class="stat-meta">Critical severity and served lately</div>
    </div>
    <div class="card stat">
      <div class="stat-label">In use</div>
      <div class="stat-value">{{ formatNumber(summary.in_use) }}</div>
      <div class="stat-meta">of {{ formatNumber(summary.total) }} matching the filters</div>
    </div>
    <div class="card stat">
      <div class="stat-label">No fix yet</div>
      <div class="stat-value">{{ formatNumber(summary.no_fix) }}</div>
      <div class="stat-meta">
        Nothing to upgrade to<template v-if="summary.malware"> · {{ formatNumber(summary.malware) }} malware</template>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head risk-filters">
      <div class="seg" role="group" aria-label="Source">
        <button
          v-for="[value, label] in [['all', 'All'], ['packages', 'Packages'], ['images', 'Images']]"
          :key="value"
          class="seg-btn"
          :class="{ active: filters.source === value }"
          @click="filters.source = value"
        >{{ label }}</button>
      </div>
      <select v-model="filters.min_severity" aria-label="Minimum severity" style="width: auto">
        <option value="critical">Critical only</option>
        <option value="high">High and above</option>
        <option value="medium">Medium and above</option>
        <option value="none">All severities</option>
      </select>
      <label class="check" style="margin: 0">
        <input v-model="filters.only_in_use" type="checkbox" /> Only in use
      </label>
      <select v-model.number="filters.in_use_days" aria-label="In use within" style="width: auto">
        <option :value="7">in the last 7 days</option>
        <option :value="30">in the last 30 days</option>
        <option :value="90">in the last 90 days</option>
      </select>
      <input id="risk-search" v-model="filters.search" type="search" placeholder="CVE or advisory id…" aria-label="Search" />
    </div>

    <div v-if="loading && !data" class="empty">Loading…</div>
    <div v-else-if="data && !data.items.length" class="empty">
      Nothing matches.<template v-if="filters.only_in_use"> Nothing vulnerable was served or pulled in the last {{ filters.in_use_days }} days.</template>
    </div>
    <ul v-else-if="data" class="risk-list">
      <li v-for="item in visible" :key="item.id" :class="{ open: openId === item.id }">
        <div
          class="risk-row"
          role="button"
          tabindex="0"
          :aria-expanded="openId === item.id"
          @click="toggle(item)"
          @keydown.enter.prevent="toggle(item)"
          @keydown.space.prevent="toggle(item)"
        >
          <span class="chev" aria-hidden="true">›</span>
          <span class="risk-id">
            <span class="mono strong">{{ item.id }}</span>
            <span class="faint small truncate" :title="item.title">{{ item.title || '—' }}</span>
          </span>
          <span class="risk-sev">
            <span class="sev-pill" :class="SEV_CLASS[item.severity]">{{ [item.severity || 'unscored', item.cvss !== null ? item.cvss.toFixed(1) : ''].join(' ').trim() }}</span>
            <span v-if="item.kev" class="sev-pill sev-critical" title="On CISA's known-exploited vulnerabilities list">KEV</span>
            <span v-if="item.malicious" class="sev-pill sev-critical">malware</span>
          </span>
          <span class="risk-meta">
          <span class="risk-where small">
            <span v-if="item.packages">{{ formatNumber(item.packages.versions) }} package version{{ item.packages.versions === 1 ? '' : 's' }}</span>
            <span v-if="item.images">{{ formatNumber(item.images.repositories) }} image{{ item.images.repositories === 1 ? '' : 's' }}</span>
          </span>
          <span class="risk-use small">
            <span v-if="item.in_use" class="badge badge-warn">in use</span>
            <span class="faint">{{ item.last_used ? relativeTime(item.last_used) : 'never served' }}</span>
          </span>
          <span class="small" :class="item.fix_available ? 'dim' : 'text-danger'">{{ item.fix_available ? 'fix available' : 'no fix' }}</span>
          </span>
        </div>

        <div v-if="openId === item.id" class="risk-detail">
          <div v-if="detailError" class="alert alert-error small">{{ detailError }}</div>
          <div v-else-if="!detail[item.id]" class="empty small">Loading…</div>
          <template v-else>
            <p class="small" style="margin-top: 0">
              <a :href="advisoryUrl(item.id)" target="_blank" rel="noopener">Read the advisory on osv.dev</a>
            </p>
            <template v-if="detail[item.id].packages.length">
              <h4 class="small">Packages</h4>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr><th>Package</th><th>Version</th><th>Fixed in</th><th>Status</th><th>Last served</th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="p in detail[item.id].packages" :key="`${p.ecosystem}:${p.name}:${p.version}`">
                      <td>
                        <EcosystemBadge :ecosystem="p.ecosystem" />
                        <router-link class="mono" :to="{ name: 'package', params: { ecosystem: p.ecosystem, name: p.name } }">{{ p.name }}</router-link>
                      </td>
                      <td class="mono small">{{ p.version }}</td>
                      <td class="mono small">{{ p.fixed_version || '—' }}</td>
                      <td class="small">
                        <span v-if="p.blocked" class="badge badge-ok" :title="p.block_reason">blocked</span>
                        <span v-else class="badge badge-danger">served</span>
                      </td>
                      <td class="faint small nowrap">{{ p.last_served ? relativeTime(p.last_served) : 'never' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </template>
            <template v-if="detail[item.id].images.length">
              <h4 class="small">Images</h4>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr><th>Image</th><th>Platform</th><th>Package in image</th><th>Fixed in</th><th>Last pulled</th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="(img, n) in detail[item.id].images" :key="`${img.repository}:${img.digest}:${n}`">
                      <td>
                        <router-link class="mono" :to="{ name: 'image', params: { name: img.repository } }">{{ img.repository }}</router-link>
                        <span v-if="img.tags.length" class="faint small">:{{ img.tags.join(', :') }}</span>
                        <span v-if="img.quarantined" class="badge badge-danger">quarantined</span>
                      </td>
                      <td class="small">{{ img.platform || '—' }}</td>
                      <td class="mono small">{{ img.package }} {{ img.installed_version }}</td>
                      <td class="mono small">{{ img.fixed_version || '—' }}</td>
                      <td class="faint small nowrap">{{ img.last_pulled ? relativeTime(img.last_pulled) : 'never' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </template>
          </template>
        </div>
      </li>
    </ul>
    <div v-if="data && data.items.length > shown" class="row" style="justify-content: center; padding: 0.8rem">
      <button class="btn btn-sm" @click="shown += PAGE">
        Show {{ Math.min(PAGE, data.items.length - shown) }} more of {{ data.items.length - shown }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.risk-filters {
  flex-wrap: wrap;
  gap: 0.6rem;
  justify-content: flex-start;
}
/* The global input rule sets width: 100%; only an id out-ranks it. */
#risk-search {
  width: 220px;
  margin-left: auto;
}
.seg {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.seg-btn {
  background: none;
  border: none;
  padding: 0.3rem 0.75rem;
  font: inherit;
  font-size: 0.85rem;
  color: var(--text-dim);
  cursor: pointer;
}
.seg-btn + .seg-btn {
  border-left: 1px solid var(--border);
}
.seg-btn.active {
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}
.risk-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.risk-list > li + li {
  border-top: 1px solid var(--border);
}
.risk-row {
  display: grid;
  grid-template-columns: 1rem minmax(12rem, 1fr) 13rem 11rem 10rem 6.5rem;
  gap: 0.9rem;
  align-items: center;
  padding: 0.6rem 1rem;
  cursor: pointer;
}
.risk-row:hover {
  background: var(--surface-2);
}
.risk-row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
li.open > .risk-row {
  background: var(--accent-soft);
}
.chev {
  color: var(--text-faint);
  font-size: 1.1rem;
  transition: transform 0.12s ease;
}
li.open .chev {
  transform: rotate(90deg);
  color: var(--accent);
}
.risk-id {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.strong {
  font-weight: 650;
}
.truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.risk-sev,
.risk-where,
.risk-use {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem 0.5rem;
  align-items: center;
}
.sev-pill {
  font-size: 0.76rem;
  font-weight: 650;
  padding: 0.05rem 0.45rem;
  border-radius: 999px;
  background: color-mix(in srgb, currentColor 12%, transparent);
  text-transform: capitalize;
  white-space: nowrap;
}
.sev-critical {
  color: var(--critical);
}
.sev-high {
  color: var(--danger);
}
.sev-medium {
  color: var(--warn);
}
.sev-low {
  color: var(--text-dim);
}
.text-danger {
  color: var(--danger);
}
.risk-detail {
  padding: 0.4rem 1rem 1rem 2.9rem;
}
/* Fixed column counts (4 -> 2 -> 1), so a narrow window never leaves one
   card alone on a row. */
.risk-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1rem;
}
/* Wide: the meta cells are grid columns of the row. Narrow: one wrapped
   line under the title instead of three stacked ones. */
.risk-meta {
  display: contents;
}
@media (max-width: 1100px) {
  .risk-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .risk-row {
    grid-template-columns: 1rem minmax(10rem, 1fr) auto;
  }
  .risk-meta {
    grid-column: 2 / -1;
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 1.2rem;
    align-items: center;
  }
}
@media (max-width: 640px) {
  .risk-stats {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
