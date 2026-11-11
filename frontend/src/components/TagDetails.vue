<script setup>
/**
 * Everything about one tag, the body of the tag page: a summary (platform,
 * pull command, scan), then tabs for vulnerabilities, packages (from the
 * SBOM), layers with the build step that made each one, and the image config.
 *
 * Vulnerabilities default to one row per package to upgrade (high and
 * critical first), with what no release fixes yet folded away: a large
 * image has ~1k findings, mostly the same CVEs across sibling packages, and
 * a flat table of them buried the few that need action.
 *
 * Each section loads on first view and is cached per digest, so switching
 * tabs or platforms back and forth costs nothing after the first look.
 */
import { computed, reactive, ref, watch } from 'vue'
import api from '@/api/client'
import CodeBlock from '@/components/CodeBlock.vue'
import FindingsTable from '@/components/FindingsTable.vue'
import { errorMessage } from '@/utils/errors'
import { safeHttpUrl } from '@/utils/url'
import {
  SEVERITIES,
  formatBytes,
  formatDateTime,
  relativeTime,
  shortDigest,
  trivySeverityClass,
} from '@/utils/format'

const props = defineProps({
  repo: { type: Object, required: true },
  tag: { type: Object, required: true },
  // The platform to show (from the parent, so it survives a reload).
  digest: { type: String, default: null },
})
const emit = defineEmits(['update:digest'])

// -- platform ---------------------------------------------------------------
const platforms = computed(() =>
  props.tag.manifest.is_index ? props.tag.platforms.filter((p) => !p.attestation) : [],
)
const attestations = computed(() =>
  props.tag.manifest.is_index ? props.tag.platforms.filter((p) => p.attestation).length : 0,
)
/** The asked-for platform, else the one pulled most recently: the one in use. */
function defaultDigest() {
  if (!props.tag.manifest.is_index) return props.tag.manifest.digest
  const fetched = platforms.value.filter((p) => p.fetched)
  if (props.digest && fetched.some((p) => p.digest === props.digest)) return props.digest
  const used = (p) => Date.parse(p.manifest?.last_accessed_at || '') || 0
  const pick =
    [...fetched].sort((a, b) => used(b) - used(a)).find((p) => used(p)) ||
    fetched.find((p) => p.platform === 'linux/amd64') ||
    fetched.find((p) => (p.platform || '').startsWith('linux/arm64')) ||
    fetched[0]
  return pick?.digest || null
}
const digest = ref(defaultDigest())
watch(digest, (d) => emit('update:digest', d), { immediate: true })
const pulledPlatforms = computed(() => platforms.value.filter((p) => p.fetched).length)
function platformLabel(p) {
  if (!p.fetched) return `${p.platform || '?'} (not pulled yet)`
  const worst = p.manifest?.scan_status === 'scanned' ? worstOf(p.manifest.severity_counts) : null
  return worst ? `${p.platform} · worst: ${worst.toLowerCase()}` : p.platform || '?'
}
// The push verdict belongs to this repository, not to the digest (the same
// bytes pulled through an upstream are judged by the pull rules), so it comes
// from the repository listing rather than the digest's detail.
const blockReason = computed(() => {
  if (!props.tag.manifest.is_index) return props.tag.manifest.policy_block_reason
  return platforms.value.find((p) => p.digest === digest.value)?.manifest?.policy_block_reason || null
})

// -- data, per digest ---------------------------------------------------------
const cache = reactive({}) // digest -> { detail, config, packages, findings }
const entry = computed(() => (digest.value ? cache[digest.value] || {} : {}))
const detail = computed(() => entry.value.detail)
const loading = ref(false)
const sectionError = ref(null)

async function ensure(key, loader) {
  const d = digest.value
  if (!d) return
  cache[d] = cache[d] || {}
  if (cache[d][key] !== undefined) return
  try {
    cache[d][key] = await loader(d)
  } catch (err) {
    cache[d][key] = null
    if (err.status !== 404) sectionError.value = err.detail || `Could not load ${key}.`
  }
}

// -- tabs ---------------------------------------------------------------------
const tab = ref('vulns')
const TABS = computed(() => [
  {
    key: 'vulns',
    label: 'Vulnerabilities',
    count: detail.value?.scan_status === 'scanned' ? totalFindings.value : null,
  },
  { key: 'packages', label: 'Packages', count: entry.value.packages?.total ?? null },
  { key: 'layers', label: 'Layers', count: detail.value?.layers?.filter((l) => l.type === 'blob').length ?? null },
  { key: 'config', label: 'Config' },
  { key: 'scans', label: 'Scan history', count: detail.value?.scans?.length ?? null },
])

async function loadTab() {
  sectionError.value = null
  if (!digest.value) return
  loading.value = true
  try {
    await ensure('detail', (d) => api.dockerManifest(d))
    if (tab.value === 'vulns') await loadFindings()
    if (tab.value === 'packages' && detail.value?.has_sbom) await ensure('packages', (d) => api.dockerPackages(d))
    if (tab.value === 'layers' || tab.value === 'config') {
      await ensure('config', (d) => api.dockerImageConfig(d))
      if (detail.value?.has_sbom) await ensure('packages', (d) => api.dockerPackages(d))
    }
  } finally {
    loading.value = false
  }
}

// -- vulnerabilities ------------------------------------------------------------
// High and critical first; the rest is one click away.
const filters = reactive({ severity: 'CRITICAL,HIGH', fixable: '', kev: '', q: '' })
const view = ref('package')
const findings = ref([])
const findingsShown = ref(0)
const grouped = ref(null)
const GROUP_PAGE = 25
const groupLimit = ref(GROUP_PAGE)
const unfixedLimit = ref(GROUP_PAGE)
const openGroups = ref(new Set())
const groupKey = (g) => `${g.packages.join(',')}@${g.installed_version || ''}`
function toggleGroup(key) {
  const next = new Set(openGroups.value)
  next.has(key) ? next.delete(key) : next.add(key)
  openGroups.value = next
}
const SEVERITY_FILTER_LABEL = { CRITICAL: 'critical', 'CRITICAL,HIGH': 'high or critical', MEDIUM: 'medium', LOW: 'low' }
const totalFindings = computed(() =>
  Object.values(detail.value?.severity_counts || {}).reduce((a, b) => a + b, 0),
)
async function loadFindings() {
  if (detail.value?.scan_status !== 'scanned') {
    findings.value = []
    findingsShown.value = 0
    return
  }
  const common = {
    severity: filters.severity || undefined,
    kev: filters.kev === '' ? undefined : filters.kev,
    q: filters.q || undefined,
  }
  let data
  try {
    data =
      view.value === 'package'
        ? await api.dockerFindings(digest.value, { ...common, group: 'package' })
        : await api.dockerFindings(digest.value, {
            ...common,
            fixable: filters.fixable === '' ? undefined : filters.fixable,
            limit: 500,
          })
  } catch (err) {
    sectionError.value = errorMessage(err, 'Could not load the findings.')
    return
  }
  if (view.value === 'package') {
    grouped.value = data
    groupLimit.value = GROUP_PAGE
    unfixedLimit.value = GROUP_PAGE
    openGroups.value = new Set()
  } else {
    findings.value = data.findings
    findingsShown.value = data.total
  }
}
function showLayer(layerDigest) {
  tab.value = 'layers'
  expandedLayer.value = layerDigest
}

// -- packages -----------------------------------------------------------------
const pkgQuery = ref('')
const pkgType = ref('')
const pkgOnlyVulnerable = ref(false)
const PKG_PAGE = 200
const pkgLimit = ref(PKG_PAGE)
function pkgFindings(c) {
  return entry.value.packages?.findings_by_package?.[`${c.name}@${c.version || ''}`] || null
}
function worstOf(counts) {
  return SEVERITIES.find((s) => counts?.[s]) || null
}
const packages = computed(() => {
  const all = entry.value.packages?.components || []
  const q = pkgQuery.value.trim().toLowerCase()
  return all.filter(
    (c) =>
      (!pkgType.value || c.type === pkgType.value) &&
      (!q || c.name.toLowerCase().includes(q) || (c.purl || '').toLowerCase().includes(q)) &&
      (!pkgOnlyVulnerable.value || pkgFindings(c)),
  )
})
watch([pkgQuery, pkgType, pkgOnlyVulnerable], () => (pkgLimit.value = PKG_PAGE))

// -- layers ---------------------------------------------------------------------
const layers = computed(() => {
  const fromConfig = entry.value.config?.layers
  if (fromConfig?.length) return fromConfig
  return (detail.value?.layers || [])
    .filter((l) => l.type === 'blob')
    .map((l, index) => ({ ...l, index, created_by: null }))
})
const largestLayer = computed(() => Math.max(1, ...layers.value.map((l) => l.size || 0)))
const packagesPerLayer = computed(() => {
  const out = {}
  for (const c of entry.value.packages?.components || []) {
    if (c.layer_digest) out[c.layer_digest] = (out[c.layer_digest] || 0) + 1
  }
  return out
})
const expandedLayer = ref(null)
function prettyStep(step) {
  if (!step) return ''
  return step
    .replace(/^\/bin\/sh -c #\(nop\)\s+/, '')
    .replace(/^\/bin\/sh -c /, 'RUN ')
    .replace(/\s*# buildkit$/, '')
    .replace(/\t+/g, ' ')
}
function layerPackages(layerDigest) {
  return (entry.value.packages?.components || []).filter((c) => c.layer_digest === layerDigest)
}

// -- config -----------------------------------------------------------------------
const config = computed(() => entry.value.config?.config || null)
const showEmptySteps = ref(false)
// Long RUN steps (a whole build script) are clamped to three lines until clicked.
const openSteps = ref(new Set())
function toggleStep(i) {
  const next = new Set(openSteps.value)
  next.has(i) ? next.delete(i) : next.add(i)
  openSteps.value = next
}
watch(showEmptySteps, () => (openSteps.value = new Set()))
const history = computed(() =>
  (config.value?.history || []).filter((h) => showEmptySteps.value || !h.empty_layer),
)

// -- actions ------------------------------------------------------------------------
// By tag follows the tag as it moves; by digest is the exact image, for
// deployments that must not change underneath you.
const pullMode = ref('tag')
const pullCommand = computed(() =>
  pullMode.value === 'tag'
    ? `docker pull ${props.repo.pull_reference}:${props.tag.tag}`
    : `docker pull ${props.repo.pull_reference}@${props.tag.manifest.digest}`,
)

const countsFor = (m) =>
  SEVERITIES.filter((s) => (m?.severity_counts || {})[s]).map((s) => [s, m.severity_counts[s]])
const fixableFor = (m, s) => (m?.fixable_counts || {})[s] || 0

watch([digest, tab], loadTab, { immediate: true })
watch([filters, view], loadFindings)
</script>

<template>
  <div class="tag-details">
    <!-- summary: platform, pull command, scan -->
    <div class="td-summary">
      <div class="td-row">
        <div v-if="platforms.length" class="td-platform">
          <label for="td-platform" class="td-label">Platform</label>
          <select id="td-platform" v-model="digest">
            <option v-for="p in platforms" :key="p.digest" :value="p.digest" :disabled="!p.fetched">
              {{ platformLabel(p) }}
            </option>
          </select>
          <span class="faint small nowrap" :title="attestations ? `+ ${attestations} BuildKit attestation(s): recorded, not scanned` : ''">
            {{ pulledPlatforms }} of {{ platforms.length }} pulled
          </span>
        </div>
        <div class="td-pull">
          <div class="seg seg-sm" role="group" aria-label="Pull by">
            <button :class="{ active: pullMode === 'tag' }" @click="pullMode = 'tag'">by tag</button>
            <button :class="{ active: pullMode === 'digest' }" title="Pinned: the tag can move, the digest cannot" @click="pullMode = 'digest'">by digest</button>
          </div>
          <CodeBlock :code="pullCommand" />
        </div>
      </div>

      <div v-if="detail" class="td-stats">
        <div class="td-stat td-sev">
          <div class="td-label">Vulnerabilities</div>
          <div v-if="detail.scan_status === 'scanned'" class="sev-bars">
            <span v-if="detail.kev_count" class="sev-pill kev" title="CISA Known Exploited Vulnerabilities">
              KEV <strong>{{ detail.kev_count }}</strong>
            </span>
            <span v-for="[sev, n] in countsFor(detail)" :key="sev" class="sev-pill" :class="trivySeverityClass(sev)" :title="`${fixableFor(detail, sev)} of ${n} have a fixed version`">
              {{ sev.toLowerCase() }} <strong>{{ n }}</strong>
            </span>
            <span v-if="!countsFor(detail).length" class="badge badge-ok">none found</span>
          </div>
          <span
            v-else
            class="badge"
            :class="{
              'badge-warn': ['queued', 'scanning'].includes(detail.scan_status),
              'badge-danger': detail.scan_status === 'failed',
            }"
          >{{ detail.scan_status.replace('_', ' ') }}</span>
        </div>
        <div v-if="detail.scan_status === 'scanned' && totalFindings" class="td-stat">
          <div class="td-label">Fixable</div>
          <div><strong>{{ detail.fixable_count }}</strong> <span class="faint small">of {{ totalFindings }}</span></div>
        </div>
        <div class="td-stat">
          <div class="td-label">Size</div>
          <div>{{ formatBytes(detail.total_size) }} <span class="faint small">· {{ detail.layer_count }} layers</span></div>
        </div>
        <div v-if="detail.scanned_at" class="td-stat">
          <div class="td-label">Scanned</div>
          <div :title="detail.scans?.[0] ? `Trivy ${detail.scans[0].trivy_version} · ${detail.scans[0].os || 'unknown OS'}${detail.scans[0].db_updated_at ? ` · DB ${formatDateTime(detail.scans[0].db_updated_at)}` : ''}` : ''">
            {{ relativeTime(detail.scanned_at) }}
            <span v-if="detail.scans?.[0]?.os" class="faint small">· {{ detail.scans[0].os }}</span>
          </div>
        </div>
        <a v-if="detail.has_sbom" class="small td-sbom" :href="api.dockerSbomUrl(detail.digest)" title="CycloneDX JSON">Download SBOM</a>
      </div>
    </div>

    <div v-if="!digest" class="alert alert-info small">
      No platform of this tag has been pulled through the registry yet, so there is nothing to show.
      Pull it once (or use <strong>Refresh from upstream</strong> in the ⋯ menu) and it is cached and scanned.
    </div>

    <template v-else-if="detail">
      <div v-if="blockReason" class="alert alert-error small">
        Pulls of this image are refused: {{ blockReason }}
      </div>
      <div v-if="detail.last_job?.status === 'failed'" class="alert alert-error small">
        Last scan failed after {{ detail.last_job.attempts }} attempts: {{ detail.last_job.error }}
      </div>

      <!-- tabs -->
      <div class="tabs td-tabs" role="tablist">
        <button
          v-for="t in TABS"
          :key="t.key"
          class="tab"
          :class="{ active: tab === t.key }"
          role="tab"
          :aria-selected="tab === t.key"
          @click="tab = t.key"
        >
          {{ t.label }}<span v-if="t.count !== null && t.count !== undefined" class="tab-count">{{ t.count }}</span>
        </button>
      </div>

      <div v-if="sectionError" class="alert alert-error small" role="alert">{{ sectionError }}</div>

      <!-- vulnerabilities -->
      <section v-if="tab === 'vulns'">
        <div v-if="detail.scan_status !== 'scanned'" class="empty small">
          <template v-if="['queued', 'scanning'].includes(detail.scan_status)">A scan is {{ detail.scan_status }}; results appear here when it finishes.</template>
          <template v-else-if="detail.kind !== 'image'">This is not a runnable image, so it is not scanned.</template>
          <template v-else>Not scanned yet.</template>
        </div>
        <template v-else>
          <div class="row mb td-filters">
            <div class="seg" role="group" aria-label="View">
              <button :class="{ active: view === 'package' }" title="One row per package to upgrade" @click="view = 'package'">By package</button>
              <button :class="{ active: view === 'all' }" title="Every finding, one row each" @click="view = 'all'">All findings</button>
            </div>
            <select v-model="filters.severity" aria-label="Severity">
              <option value="CRITICAL,HIGH">High and above</option>
              <option value="CRITICAL">Critical</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="">Any severity</option>
            </select>
            <select v-if="view === 'all'" v-model="filters.fixable" aria-label="Fix available">
              <option value="">Fixed or not</option>
              <option :value="true">Has a fix</option>
              <option :value="false">No fix yet</option>
            </select>
            <label class="check small nowrap" style="margin: 0">
              <input v-model="filters.kev" type="checkbox" :true-value="true" false-value="" /> Known exploited only
            </label>
            <input v-model.lazy="filters.q" type="search" placeholder="CVE or package…" aria-label="Filter findings by CVE or package" class="grow" />
          </div>

          <!-- by package -->
          <template v-if="view === 'package'">
            <div v-if="!grouped" class="empty small">Loading…</div>
            <template v-else>
              <div v-if="!grouped.total" class="empty small">
                No {{ SEVERITY_FILTER_LABEL[filters.severity] || '' }} findings match.
                <a v-if="filters.severity" href="#" @click.prevent="filters.severity = ''">Show every severity</a>
              </div>
              <template v-else>
                <p class="small dim td-lead">
                  <strong>{{ grouped.vulnerabilities }}</strong>
                  {{ SEVERITY_FILTER_LABEL[filters.severity] || '' }} vulnerabilit{{ grouped.vulnerabilities === 1 ? 'y' : 'ies' }}.
                  <template v-if="grouped.fixable.length">
                    Upgrading <strong>{{ grouped.fixable.length }}</strong> package{{ grouped.fixable.length === 1 ? '' : 's' }}
                    (usually by rebuilding on a newer base image) fixes {{ grouped.fixable_findings }} of them.
                  </template>
                  <template v-else>None has a fix yet.</template>
                </p>
                <ul v-if="grouped.fixable.length" class="pkg-groups">
                  <li v-for="g in grouped.fixable.slice(0, groupLimit)" :key="groupKey(g)" :class="{ open: openGroups.has(groupKey(g)) }">
                    <button class="pg-row" :aria-expanded="openGroups.has(groupKey(g))" @click="toggleGroup(groupKey(g))">
                      <span class="chev" aria-hidden="true">›</span>
                      <span class="pg-name mono" :title="g.packages.join(', ')">
                        {{ g.packages[0] }}<span v-if="g.packages.length > 1" class="faint"> +{{ g.packages.length - 1 }}</span>
                      </span>
                      <span class="pg-ver mono small">
                        {{ g.installed_version || '—' }}<span class="faint arrow" aria-label="upgrade to">→</span><span class="fix-available">{{ g.fixed_version }}</span>
                      </span>
                      <span class="pkg-vulns">
                        <span v-if="g.fixable.kev" class="sev-mini kev" title="Known exploited (CISA KEV)">KEV {{ g.fixable.kev }}</span>
                        <span
                          v-for="sev in SEVERITIES.filter((x) => g.fixable.counts[x])"
                          :key="sev"
                          class="sev-mini"
                          :class="trivySeverityClass(sev)"
                          :title="sev.toLowerCase()"
                        ><span aria-hidden="true">{{ sev[0] }}</span><span class="sr-only">{{ sev.toLowerCase() }}</span> {{ g.fixable.counts[sev] }}</span>
                      </span>
                      <span class="faint small nowrap pg-count">{{ g.fixable.count }} fixed</span>
                    </button>
                    <div v-if="openGroups.has(groupKey(g))" class="pg-body">
                      <p v-if="g.packages.length > 1" class="small dim" style="margin: 0 0 0.5rem">
                        Built from one source, upgraded together: <span class="mono">{{ g.packages.join(', ') }}</span>
                      </p>
                      <FindingsTable :findings="g.fixable.findings" :layers="layers" :show-package="false" @show-layer="showLayer" />
                    </div>
                  </li>
                </ul>
                <div v-if="grouped.fixable.length > groupLimit" class="row mt" style="justify-content: center">
                  <button class="btn btn-sm" @click="groupLimit += GROUP_PAGE">
                    Show {{ Math.min(GROUP_PAGE, grouped.fixable.length - groupLimit) }} more of {{ grouped.fixable.length - groupLimit }}
                  </button>
                </div>

                <details v-if="grouped.unfixed.length" class="pg-unfixed" :open="!grouped.fixable.length">
                  <summary>
                    No fix available yet: {{ grouped.unfixed_findings }} finding{{ grouped.unfixed_findings === 1 ? '' : 's' }}
                    in {{ grouped.unfixed.length }} package{{ grouped.unfixed.length === 1 ? '' : 's' }}
                  </summary>
                  <p class="small faint" style="margin: 0.5rem 0">
                    No release fixes these yet, so there is nothing to upgrade to. Images in use are rescanned
                    on a schedule, so a fix shows up here once one is published.
                  </p>
                  <ul class="pkg-groups">
                    <li v-for="g in grouped.unfixed.slice(0, unfixedLimit)" :key="groupKey(g)" :class="{ open: openGroups.has(`u:${groupKey(g)}`) }">
                      <button class="pg-row" :aria-expanded="openGroups.has(`u:${groupKey(g)}`)" @click="toggleGroup(`u:${groupKey(g)}`)">
                        <span class="chev" aria-hidden="true">›</span>
                        <span class="pg-name mono" :title="g.packages.join(', ')">
                          {{ g.packages[0] }}<span v-if="g.packages.length > 1" class="faint"> +{{ g.packages.length - 1 }}</span>
                        </span>
                        <span class="pg-ver mono small">{{ g.installed_version || '—' }}</span>
                        <span class="pkg-vulns">
                          <span v-if="g.unfixed.kev" class="sev-mini kev" title="Known exploited (CISA KEV)">KEV {{ g.unfixed.kev }}</span>
                          <span
                            v-for="sev in SEVERITIES.filter((x) => g.unfixed.counts[x])"
                            :key="sev"
                            class="sev-mini"
                            :class="trivySeverityClass(sev)"
                            :title="sev.toLowerCase()"
                          ><span aria-hidden="true">{{ sev[0] }}</span><span class="sr-only">{{ sev.toLowerCase() }}</span> {{ g.unfixed.counts[sev] }}</span>
                        </span>
                        <span class="faint small nowrap pg-count">{{ g.unfixed.count }} open</span>
                      </button>
                      <div v-if="openGroups.has(`u:${groupKey(g)}`)" class="pg-body">
                        <FindingsTable :findings="g.unfixed.findings" :layers="layers" :show-package="false" :show-fix="false" @show-layer="showLayer" />
                      </div>
                    </li>
                  </ul>
                  <div v-if="grouped.unfixed.length > unfixedLimit" class="row mt" style="justify-content: center">
                    <button class="btn btn-sm" @click="unfixedLimit += GROUP_PAGE">
                      Show {{ Math.min(GROUP_PAGE, grouped.unfixed.length - unfixedLimit) }} more of {{ grouped.unfixed.length - unfixedLimit }}
                    </button>
                  </div>
                </details>
                <p v-if="grouped.truncated" class="field-hint">Only the first {{ grouped.total }} findings are grouped here; narrow the filters to see the rest.</p>
              </template>
            </template>
          </template>

          <!-- every finding -->
          <template v-else>
            <p class="small faint td-lead">{{ findingsShown }} finding{{ findingsShown === 1 ? '' : 's' }}<template v-if="findingsShown > findings.length"> (showing the first {{ findings.length }})</template></p>
            <div v-if="!findings.length" class="empty small">No findings match.</div>
            <FindingsTable v-else :findings="findings" :layers="layers" @show-layer="showLayer" />
          </template>
        </template>
      </section>

      <!-- packages -->
      <section v-else-if="tab === 'packages'">
        <div v-if="!detail.has_sbom" class="empty small">
          No SBOM yet. The scanner records one with each scan.
        </div>
        <div v-else-if="loading && !entry.packages" class="empty small">Loading packages…</div>
        <template v-else-if="entry.packages">
          <div class="pkg-meta small dim mb">
            {{ entry.packages.total }} packages
            <template v-if="entry.packages.os"> · OS {{ entry.packages.os }}</template>
            · {{ entry.packages.format }}<template v-if="entry.packages.tool"> from {{ entry.packages.tool }}</template>
            <template v-if="entry.packages.generated_at"> · {{ relativeTime(entry.packages.generated_at) }}</template>
          </div>
          <div class="row mb td-filters">
            <input v-model="pkgQuery" type="search" placeholder="Package name or purl…" aria-label="Filter packages by name or purl" class="grow" />
            <div class="eco-filter" style="margin-top: 0">
              <button class="eco-chip" :class="{ active: !pkgType }" @click="pkgType = ''">All</button>
              <button
                v-for="(n, type) in entry.packages.by_type"
                :key="type"
                class="eco-chip"
                :class="{ active: pkgType === type }"
                @click="pkgType = type"
              >{{ type }} <span class="faint">{{ n }}</span></button>
            </div>
            <label class="check small nowrap"><input v-model="pkgOnlyVulnerable" type="checkbox" /> with vulnerabilities</label>
          </div>
          <div v-if="!packages.length" class="empty small">No packages match.</div>
          <div v-else class="table-wrap">
            <table class="td-table">
              <thead><tr><th>Package</th><th>Version</th><th>Type</th><th>Licence</th><th>Vulnerabilities</th><th>Layer</th></tr></thead>
              <tbody>
                <tr v-for="c in packages.slice(0, pkgLimit)" :key="(c.purl || c.name) + c.version + (c.path || '')">
                  <td class="mono small">
                    {{ c.name }}
                    <div v-if="c.path" class="faint small truncate" :title="c.path">{{ c.path }}</div>
                  </td>
                  <td class="mono small">{{ c.version || '—' }}</td>
                  <td class="small">{{ c.type }}</td>
                  <td class="small">{{ c.licenses.join(', ') || '—' }}</td>
                  <td class="nowrap">
                    <template v-if="pkgFindings(c)">
                      <span class="pkg-vulns">
                        <span
                          v-for="sev in SEVERITIES.filter((s) => pkgFindings(c)[s])"
                          :key="sev"
                          class="sev-mini"
                          :class="trivySeverityClass(sev)"
                          :title="sev.toLowerCase()"
                        ><span aria-hidden="true">{{ sev[0] }}</span><span class="sr-only">{{ sev.toLowerCase() }}</span> {{ pkgFindings(c)[sev] }}</span>
                        <a href="#" class="small" @click.prevent="filters.q = c.name; filters.severity = ''; tab = 'vulns'">view</a>
                      </span>
                    </template>
                    <span v-else class="faint small">—</span>
                  </td>
                  <td class="mono small nowrap">
                    <template v-if="c.layer_digest">
                      {{ (layers.findIndex((l) => l.digest === c.layer_digest) + 1) || '?' }}
                    </template>
                    <template v-else>—</template>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="packages.length > pkgLimit" class="row mt" style="justify-content: center">
            <button class="btn btn-sm" @click="pkgLimit += PKG_PAGE">Show {{ Math.min(PKG_PAGE, packages.length - pkgLimit) }} more of {{ packages.length - pkgLimit }}</button>
          </div>
          <p v-if="entry.packages.truncated" class="field-hint">
            Showing the first {{ entry.packages.components.length }} of {{ entry.packages.total }}. Download the SBOM for the full list.
          </p>
        </template>
      </section>

      <!-- layers -->
      <section v-else-if="tab === 'layers'">
        <div v-if="!layers.length" class="empty small">No layers recorded.</div>
        <template v-else>
          <p v-if="entry.config && !entry.config.available" class="field-hint" style="margin-top: 0">
            The image config is not available, so layers are shown without the build step that made them.
          </p>
          <ol class="layer-list">
            <li v-for="layer in layers" :key="layer.digest" :class="{ open: expandedLayer === layer.digest }">
              <button class="layer-row" @click="expandedLayer = expandedLayer === layer.digest ? null : layer.digest">
                <span class="layer-n">{{ layer.index + 1 }}</span>
                <span class="layer-step mono" :title="layer.created_by || ''">
                  {{ prettyStep(layer.created_by) || shortDigest(layer.digest) }}
                </span>
                <span class="faint small nowrap layer-pkgs">{{ packagesPerLayer[layer.digest] ? `${packagesPerLayer[layer.digest]} pkgs` : '' }}</span>
                <span class="layer-size">
                  <span class="layer-bar"><span :style="{ width: `${Math.max(2, (100 * (layer.size || 0)) / largestLayer)}%` }" /></span>
                  <span class="small nowrap">{{ formatBytes(layer.size) }}</span>
                </span>
                <span class="badge" :class="layer.cached ? 'badge-ok' : ''" :title="layer.cached ? 'Stored in this registry' : 'Fetched from upstream on first pull'">
                  {{ layer.cached ? 'cached' : 'not cached' }}
                </span>
              </button>
              <div v-if="expandedLayer === layer.digest" class="layer-detail">
                <div class="detail-grid small">
                  <span class="dim">Digest</span><span class="mono">{{ layer.digest }}</span>
                  <span v-if="layer.diff_id" class="dim">Diff ID</span><span v-if="layer.diff_id" class="mono">{{ layer.diff_id }}</span>
                  <span class="dim">Media type</span><span class="mono">{{ layer.media_type || '—' }}</span>
                  <span v-if="layer.created" class="dim">Created</span><span v-if="layer.created">{{ formatDateTime(layer.created) }}</span>
                </div>
                <CodeBlock v-if="layer.created_by" class="mt" :code="prettyStep(layer.created_by)" caption="build step" />
                <div v-if="layerPackages(layer.digest).length" class="mt small">
                  <span class="dim">Packages added here:</span>
                  <span class="mono">
                    {{ layerPackages(layer.digest).slice(0, 40).map((c) => `${c.name} ${c.version || ''}`).join(', ') }}
                    <template v-if="layerPackages(layer.digest).length > 40"> … and {{ layerPackages(layer.digest).length - 40 }} more</template>
                  </span>
                </div>
              </div>
            </li>
          </ol>
        </template>
      </section>

      <!-- config -->
      <section v-else-if="tab === 'config'">
        <div v-if="loading && !entry.config" class="empty small">Loading config…</div>
        <div v-else-if="!config" class="empty small">
          The image config is not available (the upstream could not be reached, or this is not an image).
        </div>
        <template v-else>
          <div class="config-grid">
            <div class="detail-grid small">
              <span class="dim">Platform</span>
              <span class="mono">{{ [config.os, config.architecture, config.variant].filter(Boolean).join('/') }}</span>
              <span class="dim">Created</span><span>{{ config.created ? formatDateTime(config.created) : '—' }}</span>
              <span class="dim">Entrypoint</span><span class="mono">{{ config.entrypoint.length ? JSON.stringify(config.entrypoint) : '—' }}</span>
              <span class="dim">Command</span><span class="mono">{{ config.cmd.length ? JSON.stringify(config.cmd) : '—' }}</span>
              <span class="dim">User</span>
              <span class="mono">
                {{ config.user || 'root' }}
                <span v-if="!config.user || config.user === 'root' || config.user === '0'" class="badge badge-warn" title="The container runs as root unless overridden">root</span>
              </span>
              <span class="dim">Working dir</span><span class="mono">{{ config.working_dir || '/' }}</span>
              <span class="dim">Ports</span><span class="mono">{{ config.exposed_ports.join(', ') || '—' }}</span>
              <span v-if="config.volumes.length" class="dim">Volumes</span><span v-if="config.volumes.length" class="mono">{{ config.volumes.join(', ') }}</span>
              <span v-if="config.healthcheck.length" class="dim">Healthcheck</span><span v-if="config.healthcheck.length" class="mono">{{ config.healthcheck.join(' ') }}</span>
              <span v-if="config.stop_signal" class="dim">Stop signal</span><span v-if="config.stop_signal" class="mono">{{ config.stop_signal }}</span>
            </div>
            <div>
              <h4 class="td-h4">Environment</h4>
              <div v-if="!config.env.length" class="faint small">None.</div>
              <ul v-else class="kv-list mono small">
                <li v-for="e in config.env" :key="e">
                  <span class="kv-k">{{ e.split('=')[0] }}</span>=<span class="kv-v">{{ e.slice(e.indexOf('=') + 1) }}</span>
                </li>
              </ul>
            </div>
          </div>
          <div v-if="Object.keys(config.labels).length" class="mt">
            <h4 class="td-h4">Labels</h4>
            <ul class="kv-list mono small">
              <li v-for="(v, k) in config.labels" :key="k">
                <span class="kv-k">{{ k }}</span>=<span class="kv-v">
                  <a v-if="safeHttpUrl(v)" :href="safeHttpUrl(v)" target="_blank" rel="noopener noreferrer">{{ v }}</a>
                  <template v-else>{{ v }}</template>
                </span>
              </li>
            </ul>
          </div>
          <div class="mt">
            <div class="row" style="justify-content: space-between">
              <h4 class="td-h4">Build history</h4>
              <label class="check small"><input v-model="showEmptySteps" type="checkbox" /> include metadata-only steps</label>
            </div>
            <ol class="history-list mono small">
              <li
                v-for="(h, i) in history"
                :key="i"
                :class="{ meta: h.empty_layer, long: (h.created_by || '').length > 240, open: openSteps.has(i) }"
                @click="(h.created_by || '').length > 240 && toggleStep(i)"
              >
                <span class="hist-step">{{ prettyStep(h.created_by) || h.comment || '—' }}</span>
                <span v-if="h.created" class="faint nowrap">{{ relativeTime(h.created) }}</span>
              </li>
            </ol>
          </div>
        </template>
      </section>

      <!-- scan history -->
      <section v-else-if="tab === 'scans'">
        <div v-if="!detail.scans?.length" class="empty small">No scans recorded yet.</div>
        <div v-else class="table-wrap">
          <table class="td-table">
            <thead><tr><th>When</th><th>Mode</th><th>Findings</th><th>Trivy</th><th>DB</th><th class="num">Took</th></tr></thead>
            <tbody>
              <tr v-for="s in detail.scans" :key="s.id">
                <td class="small nowrap">{{ formatDateTime(s.created_at) }}</td>
                <td class="small">{{ s.mode === 'sbom' ? 'SBOM match' : 'full image' }}</td>
                <td class="nowrap">
                  <span class="pkg-vulns">
                    <span v-for="sev in SEVERITIES.filter((x) => s.severity_counts?.[x])" :key="sev" class="sev-mini" :class="trivySeverityClass(sev)">
                      <span aria-hidden="true">{{ sev[0] }}</span><span class="sr-only">{{ sev.toLowerCase() }}</span> {{ s.severity_counts[sev] }}
                    </span>
                  </span>
                  <span v-if="!s.finding_count" class="faint small">none</span>
                </td>
                <td class="small">{{ s.trivy_version || '—' }}</td>
                <td class="small nowrap">{{ s.db_updated_at ? formatDateTime(s.db_updated_at) : '—' }}</td>
                <td class="num small">{{ s.duration_ms != null ? `${(s.duration_ms / 1000).toFixed(1)}s` : '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="field-hint">
          A rescan normally matches the stored SBOM against today's vulnerability database, without pulling the image
          again. A full rescan pulls and unpacks it.
        </p>
      </section>
    </template>
    <div v-else-if="loading" class="empty small">Loading…</div>
  </div>
</template>

<style scoped>
.tag-details {
  padding: 0;
}
/* Summary: what you pull (platform, command), then what is in it. */
.td-summary {
  padding: 0.9rem 1rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 1rem;
}
.td-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem 1.4rem;
  align-items: center;
}
.td-platform {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.td-platform .td-label {
  margin: 0;
}
/* The global select rule sets width: 100%; only an id out-ranks it. */
#td-platform {
  width: auto;
  min-width: 13rem;
  height: 32px;
}
.td-pull {
  flex: 1;
  min-width: min(100%, 26rem);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.td-pull > :last-child {
  flex: 1;
  min-width: 0;
}
.seg {
  display: inline-flex;
  flex: none;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.seg button {
  font: inherit;
  font-size: 0.8rem;
  padding: 0.3rem 0.7rem;
  border: none;
  background: var(--surface);
  color: var(--text-dim);
  cursor: pointer;
  white-space: nowrap;
}
.seg-sm button {
  font-size: 0.78rem;
  padding: 0.25rem 0.6rem;
}
.seg button + button {
  border-left: 1px solid var(--border);
}
.seg button.active {
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}
.td-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 0.8rem 2.2rem;
  align-items: flex-start;
  margin-top: 0.85rem;
  padding-top: 0.85rem;
  border-top: 1px solid var(--border);
}
.td-sbom {
  margin-left: auto;
  align-self: center;
}
.td-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-faint);
  margin-bottom: 0.25rem;
}
.sev-bars {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
}
.sev-pill {
  font-size: 0.8rem;
  padding: 0.1rem 0.5rem;
  border-radius: 999px;
  background: color-mix(in srgb, currentColor 12%, transparent);
  white-space: nowrap;
}
.sev-pill.kev {
  color: var(--critical);
  outline: 1px solid color-mix(in srgb, currentColor 45%, transparent);
}
.td-tabs {
  margin: 0.6rem 0 0.8rem;
}
.tab-count {
  font-size: 0.72rem;
  padding: 0 0.4rem;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text-dim);
  font-weight: 600;
}
.td-filters {
  flex-wrap: wrap;
}
.td-filters select {
  width: auto;
}
.td-filters .grow {
  flex: 1;
  min-width: 180px;
}
.td-table {
  background: var(--surface);
}
.td-table {
  width: 100%;
}
.fix-available {
  color: var(--ok);
}
.detail-grid {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 0.35rem 1rem;
  align-items: baseline;
}
.detail-grid > span {
  overflow-wrap: anywhere;
}
.pkg-meta {
  margin-top: -0.2rem;
}
.td-lead {
  margin: 0 0 0.6rem;
}
/* vulnerabilities by package */
.pkg-groups {
  list-style: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--surface);
  overflow: hidden;
}
.pkg-groups > li + li {
  border-top: 1px solid var(--border);
}
.pg-row {
  display: grid;
  grid-template-columns: 1rem minmax(9rem, 1.1fr) minmax(10rem, 1.3fr) minmax(9rem, 1fr) 5rem;
  gap: 0.8rem;
  align-items: center;
  width: 100%;
  padding: 0.55rem 0.8rem;
  border: none;
  background: none;
  font: inherit;
  color: inherit;
  text-align: left;
  cursor: pointer;
}
.pg-row:hover,
li.open > .pg-row {
  background: var(--surface-2);
}
.pg-row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
.chev {
  display: inline-block;
  color: var(--text-faint);
  font-size: 1.1rem;
  line-height: 1;
  transition: transform 0.12s ease;
}
li.open > .pg-row .chev {
  transform: rotate(90deg);
  color: var(--accent);
}
.pg-name {
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pg-ver {
  overflow-wrap: anywhere;
}
.pg-ver .arrow {
  margin: 0 0.4em;
}
.pg-count {
  justify-self: end;
}
.pg-body {
  padding: 0.5rem 0.8rem 0.9rem 2.6rem;
  background: var(--surface-2);
}
.pg-unfixed {
  margin-top: 1rem;
}
.pg-unfixed > summary {
  cursor: pointer;
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--text-dim);
  padding: 0.3rem 0;
}
.sev-mini.kev {
  color: var(--critical);
  outline: 1px solid color-mix(in srgb, currentColor 45%, transparent);
}

/* layers */
.layer-list {
  list-style: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--surface);
  overflow: hidden;
}
.layer-list li + li {
  border-top: 1px solid var(--border);
}
.layer-row {
  display: grid;
  grid-template-columns: 2rem minmax(0, 1fr) 4.5rem 12rem 6rem;
  gap: 0.8rem;
  align-items: center;
  width: 100%;
  padding: 0.5rem 0.8rem;
  border: none;
  background: none;
  text-align: left;
  font: inherit;
  color: inherit;
  cursor: pointer;
}
.layer-row:hover,
li.open .layer-row {
  background: var(--surface-2);
}
.layer-row > .badge {
  justify-self: end;
}
.layer-n {
  font-variant-numeric: tabular-nums;
  color: var(--text-faint);
  text-align: right;
}
.layer-step {
  font-size: 0.8rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.layer-size {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.5rem;
  align-items: center;
}
.layer-bar {
  height: 6px;
  border-radius: 999px;
  background: var(--surface-2);
  overflow: hidden;
}
.layer-bar > span {
  display: block;
  height: 100%;
  background: var(--docker, var(--accent));
  border-radius: 999px;
}
.layer-detail {
  padding: 0.6rem 0.9rem 0.9rem 3.6rem;
  background: var(--surface-2);
}

/* config */
.config-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 1.2rem 2rem;
}
.td-h4 {
  margin: 0 0 0.4rem;
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-faint);
}
.kv-list {
  list-style: none;
  margin: 0;
  padding: 0.5rem 0.7rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  max-height: 18rem;
  overflow: auto;
}
.kv-list li {
  overflow-wrap: anywhere;
  padding: 0.12rem 0;
}
.kv-k {
  color: var(--accent);
}
.history-list {
  margin: 0;
  padding: 0.4rem 0.7rem 0.4rem 2.2rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
}
.history-list li {
  padding: 0.25rem 0;
}
.history-list li + li {
  border-top: 1px dashed var(--border);
}
.history-list li.meta {
  color: var(--text-faint);
}
.hist-step {
  overflow-wrap: anywhere;
  margin-right: 0.6rem;
}
.history-list li.long {
  cursor: pointer;
}
.history-list li.long:not(.open) .hist-step {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.history-list li.long:not(.open)::after {
  content: 'click to show the whole step';
  display: block;
  font-family: var(--font-sans, inherit);
  font-size: 0.72rem;
  color: var(--accent);
}
.pkg-vulns {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  align-items: center;
}
.sev-mini {
  font-size: 0.74rem;
  font-weight: 650;
  padding: 0.02rem 0.4rem;
  border-radius: 999px;
  background: color-mix(in srgb, currentColor 12%, transparent);
  white-space: nowrap;
}

@media (max-width: 1100px) {
  .config-grid {
    grid-template-columns: 1fr;
  }
  .pg-row {
    grid-template-columns: 1rem minmax(0, 1fr) auto;
  }
  /* Version on its own line under the name; badges stay beside it. */
  .pg-ver {
    grid-column: 2 / -1;
    grid-row: 2;
  }
  .pg-count {
    display: none;
  }
  .layer-row {
    grid-template-columns: 2rem minmax(0, 1fr) 8rem;
  }
  .layer-row > .layer-pkgs,
  .layer-row > .badge {
    display: none;
  }
}
</style>
