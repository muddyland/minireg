<script setup>
/**
 * Everything about one tag, shown when its row is expanded on the image page:
 * platform picker, scan summary, vulnerabilities, packages (from the SBOM),
 * layers with the build step that made each one, and the image config.
 *
 * Each section loads on first view and is cached per digest, so switching
 * tabs or platforms back and forth costs nothing after the first look.
 */
import { computed, reactive, ref, watch } from 'vue'
import api from '@/api/client'
import CodeBlock from '@/components/CodeBlock.vue'
import { useAuthStore } from '@/stores/auth'
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
})
const emit = defineEmits(['message', 'error'])
const auth = useAuthStore()

// -- platform ---------------------------------------------------------------
const platforms = computed(() =>
  props.tag.manifest.is_index ? props.tag.platforms.filter((p) => !p.attestation) : [],
)
const attestations = computed(() =>
  props.tag.manifest.is_index ? props.tag.platforms.filter((p) => p.attestation).length : 0,
)
function defaultDigest() {
  if (!props.tag.manifest.is_index) return props.tag.manifest.digest
  const fetched = platforms.value.filter((p) => p.fetched)
  const pick =
    fetched.find((p) => p.platform === 'linux/amd64') ||
    fetched.find((p) => (p.platform || '').startsWith('linux/arm64')) ||
    fetched[0]
  return pick?.digest || null
}
const digest = ref(defaultDigest())

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
const filters = reactive({ severity: '', fixable: '', kev: '', q: '' })
const findings = ref([])
const findingsShown = ref(0)
const totalFindings = computed(() =>
  Object.values(detail.value?.severity_counts || {}).reduce((a, b) => a + b, 0),
)
async function loadFindings() {
  if (detail.value?.scan_status !== 'scanned') {
    findings.value = []
    findingsShown.value = 0
    return
  }
  const data = await api.dockerFindings(digest.value, {
    severity: filters.severity || undefined,
    fixable: filters.fixable === '' ? undefined : filters.fixable,
    kev: filters.kev === '' ? undefined : filters.kev,
    q: filters.q || undefined,
    limit: 500,
  })
  findings.value = data.findings
  findingsShown.value = data.total
}
const expandedFinding = ref(null)

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

async function rescan(full) {
  try {
    const result = await api.dockerRescan(digest.value, full)
    emit(
      'message',
      result.queued
        ? `Rescan queued (${result.mode === 'sbom' ? 'against the stored SBOM, no image pull' : 'full image scan'}).`
        : 'A scan is already queued for this image.',
    )
    delete cache[digest.value]
    await loadTab()
  } catch (err) {
    emit('error', err.detail || 'Could not queue a rescan.')
  }
}

const countsFor = (m) =>
  SEVERITIES.filter((s) => (m?.severity_counts || {})[s]).map((s) => [s, m.severity_counts[s]])
const fixableFor = (m, s) => (m?.fixable_counts || {})[s] || 0

watch([digest, tab], loadTab, { immediate: true })
watch(filters, loadFindings)
</script>

<template>
  <div class="tag-details">
    <!-- platform picker + pull commands -->
    <div class="td-top">
      <div v-if="platforms.length" class="td-platforms">
        <span class="faint small">Platform</span>
        <button
          v-for="p in platforms"
          :key="p.digest"
          class="eco-chip"
          :class="{ active: digest === p.digest }"
          :disabled="!p.fetched"
          :title="p.fetched ? p.digest : 'Not pulled through this registry yet'"
          @click="digest = p.digest"
        >
          {{ p.platform || '?' }}
          <span
            v-if="p.manifest?.scan_status === 'scanned' && worstOf(p.manifest.severity_counts)"
            class="dot"
            :class="trivySeverityClass(worstOf(p.manifest.severity_counts))"
            :title="`worst finding: ${worstOf(p.manifest.severity_counts).toLowerCase()}`"
          />
        </button>
        <span v-if="attestations" class="faint small" title="BuildKit provenance / SBOM attestations: recorded, not scanned">
          + {{ attestations }} attestation{{ attestations > 1 ? 's' : '' }}
        </span>
      </div>
      <div class="td-pull">
        <div class="seg seg-sm">
          <button :class="{ active: pullMode === 'tag' }" @click="pullMode = 'tag'">by tag</button>
          <button :class="{ active: pullMode === 'digest' }" title="Pinned: the tag can move, the digest cannot" @click="pullMode = 'digest'">by digest</button>
        </div>
        <CodeBlock :code="pullCommand" />
      </div>
    </div>

    <div v-if="!digest" class="alert alert-info small">
      No platform of this tag has been pulled through the registry yet, so there is nothing to show.
      Pull it once (or use <strong>Refresh</strong>) and it is cached and scanned.
    </div>

    <template v-else-if="detail">
      <!-- summary strip -->
      <div v-if="detail.policy_block_reason" class="alert alert-error small">
        Pulls of this image are refused: {{ detail.policy_block_reason }}
      </div>
      <div v-if="detail.last_job?.status === 'failed'" class="alert alert-error small">
        Last scan failed after {{ detail.last_job.attempts }} attempts: {{ detail.last_job.error }}
      </div>

      <div class="td-summary">
        <div class="td-stat">
          <div class="td-label">Scan</div>
          <span
            class="badge"
            :class="{
              'badge-ok': detail.scan_status === 'scanned',
              'badge-warn': ['queued', 'scanning'].includes(detail.scan_status),
              'badge-danger': detail.scan_status === 'failed',
            }"
          >{{ detail.scan_status.replace('_', ' ') }}</span>
          <div v-if="detail.scanned_at" class="faint small">{{ relativeTime(detail.scanned_at) }}</div>
        </div>
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
          <span v-else class="faint small">—</span>
          <div v-if="detail.scan_status === 'scanned' && totalFindings" class="faint small">
            {{ detail.fixable_count }} of {{ totalFindings }} have a fixed version
          </div>
        </div>
        <div class="td-stat">
          <div class="td-label">Size</div>
          <div>{{ formatBytes(detail.total_size) }}</div>
          <div class="faint small">{{ detail.layer_count }} layers</div>
        </div>
        <div v-if="detail.scans?.[0]" class="td-stat">
          <div class="td-label">Scanned by</div>
          <div class="small">Trivy {{ detail.scans[0].trivy_version }}</div>
          <div class="faint small">
            {{ detail.scans[0].os || 'unknown OS' }}<template v-if="detail.scans[0].db_updated_at">
              · DB {{ formatDateTime(detail.scans[0].db_updated_at) }}</template>
          </div>
        </div>
        <div class="td-actions">
          <a v-if="detail.has_sbom" class="btn btn-sm" :href="api.dockerSbomUrl(detail.digest)" title="CycloneDX JSON">
            Download SBOM
          </a>
          <template v-if="auth.isAdmin && detail.kind === 'image'">
            <button
              class="btn btn-sm"
              :disabled="['queued', 'scanning'].includes(detail.scan_status)"
              title="Match the stored SBOM against today's vulnerability database"
              @click="rescan(false)"
            >Rescan</button>
            <button class="btn btn-sm" title="Pull the image and scan it again from scratch" @click="rescan(true)">
              Full rescan
            </button>
          </template>
        </div>
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

      <div v-if="sectionError" class="alert alert-error small">{{ sectionError }}</div>

      <!-- vulnerabilities -->
      <section v-if="tab === 'vulns'">
        <div v-if="detail.scan_status !== 'scanned'" class="empty small">
          <template v-if="['queued', 'scanning'].includes(detail.scan_status)">A scan is {{ detail.scan_status }}; results appear here when it finishes.</template>
          <template v-else-if="detail.kind !== 'image'">This is not a runnable image, so it is not scanned.</template>
          <template v-else>Not scanned yet.</template>
        </div>
        <template v-else>
          <div class="row mb td-filters">
            <select v-model="filters.severity">
              <option value="">Any severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="CRITICAL,HIGH">High and above</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select v-model="filters.fixable">
              <option value="">Fixed or not</option>
              <option :value="true">Has a fix</option>
              <option :value="false">No fix yet</option>
            </select>
            <select v-model="filters.kev">
              <option value="">Exploited or not</option>
              <option :value="true">Known exploited (KEV) only</option>
            </select>
            <input v-model.lazy="filters.q" type="search" placeholder="CVE or package…" class="grow" />
            <span class="faint small nowrap">{{ findingsShown }} shown</span>
          </div>
          <div v-if="!findings.length" class="empty small">No findings match.</div>
          <div v-else class="table-wrap">
            <table class="td-table">
              <thead>
                <tr><th>Vulnerability</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Title</th></tr>
              </thead>
              <tbody>
                <template v-for="f in findings" :key="f.vuln_id + f.pkg_name + f.installed_version">
                  <tr class="clickable" @click="expandedFinding = expandedFinding === f ? null : f">
                    <td class="mono nowrap">
                      {{ f.vuln_id }}
                      <div class="row-tight">
                        <span v-if="f.kev" class="badge badge-danger" title="CISA Known Exploited Vulnerability">KEV</span>
                        <span v-if="f.denied" class="badge badge-danger">denied</span>
                        <span v-if="f.accepted" class="badge badge-warn">risk accepted</span>
                      </div>
                    </td>
                    <td class="nowrap">
                      <span class="sev" :class="trivySeverityClass(f.severity)">{{ f.severity.toLowerCase() }}</span>
                      <div v-if="f.cvss !== null" class="faint small">CVSS {{ f.cvss.toFixed(1) }}</div>
                    </td>
                    <td class="mono small">{{ f.pkg_name }}<div class="faint small">{{ f.pkg_type }}</div></td>
                    <td class="mono small">{{ f.installed_version || '—' }}</td>
                    <td class="mono small" :class="{ 'fix-available': f.fixed_version }">{{ f.fixed_version || '—' }}</td>
                    <td class="small td-title"><div class="truncate" :title="f.title">{{ f.title || '—' }}</div></td>
                  </tr>
                  <tr v-if="expandedFinding === f" class="td-subrow">
                    <td colspan="6">
                      <div class="detail-grid small">
                        <span class="dim">Title</span><span>{{ f.title || '—' }}</span>
                        <span class="dim">Package</span><span class="mono">{{ f.pkg_name }} {{ f.installed_version }} ({{ f.pkg_type }})</span>
                        <span class="dim">Fix</span>
                        <span>
                          <template v-if="f.fixed_version">Upgrade to <span class="mono">{{ f.fixed_version }}</span>, usually by rebuilding on a newer base image.</template>
                          <template v-else>No fixed version published yet.</template>
                        </span>
                        <span class="dim">Introduced in</span>
                        <span class="mono">
                          <template v-if="f.layer_digest">
                            layer {{ (layers.findIndex((l) => l.digest === f.layer_digest) + 1) || '?' }} ·
                            {{ shortDigest(f.layer_digest) }}
                            <a href="#" class="small" @click.prevent="tab = 'layers'; expandedLayer = f.layer_digest">show layer</a>
                          </template>
                          <template v-else>—</template>
                        </span>
                        <span class="dim">Advisory</span>
                        <span><a v-if="f.url" :href="f.url" target="_blank" rel="noopener noreferrer">{{ f.url }}</a><template v-else>—</template></span>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
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
            <input v-model="pkgQuery" type="search" placeholder="Package name or purl…" class="grow" />
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
                        >{{ sev[0] }} {{ pkgFindings(c)[sev] }}</span>
                        <a href="#" class="small" @click.prevent="filters.q = c.name; tab = 'vulns'">view</a>
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
                  <a v-if="/^https?:\/\//.test(v || '')" :href="v" target="_blank" rel="noopener noreferrer">{{ v }}</a>
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
                      {{ sev[0] }} {{ s.severity_counts[sev] }}
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
  padding: 0.9rem 1rem 1.1rem;
  background: var(--surface-2);
  border-top: 1px solid var(--border);
}
.td-top {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.1fr);
  gap: 0.6rem 1.2rem;
  align-items: center;
  margin-bottom: 0.9rem;
}
.td-platforms {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  align-items: center;
}
.td-platforms .faint {
  margin-right: 0.2rem;
}
.td-pull {
  grid-column: 2;
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
  font-size: 0.78rem;
  padding: 0.25rem 0.6rem;
  border: none;
  background: var(--surface);
  color: var(--text-dim);
  cursor: pointer;
  white-space: nowrap;
}
.seg button + button {
  border-left: 1px solid var(--border);
}
.seg button.active {
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}
.td-platforms:only-child,
.td-pull:only-child {
  grid-column: 1 / -1;
}
.dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-left: 0.25rem;
  background: currentColor;
}
.td-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem 2rem;
  align-items: flex-start;
  padding: 0.85rem 1rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  margin-bottom: 0.4rem;
}
.td-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-faint);
  margin-bottom: 0.25rem;
}
.td-actions {
  margin-left: auto;
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
  align-self: center;
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
/* The title is the only column that may give: it truncates (full text is
   one click away in the expanded row) so the table never runs off the card. */
.td-title {
  width: 100%;
  max-width: 0;
}
.td-table {
  width: 100%;
}
.fix-available {
  color: var(--ok);
}
tr.clickable {
  cursor: pointer;
}
tr.clickable:hover td {
  background: var(--surface-2);
}
.td-subrow td {
  background: var(--surface-2);
  padding: 0.7rem 1rem 0.9rem;
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
  .td-top,
  .config-grid {
    grid-template-columns: 1fr;
  }
  .td-pull {
    grid-column: 1;
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
