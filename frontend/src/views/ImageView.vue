<script setup>
/**
 * One image repository: tags, platforms, scan status, and the findings of
 * whichever platform image is selected. Admin controls (pin, quarantine,
 * watch, refresh, rescan) sit alongside.
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import {
  SEVERITIES,
  formatBytes,
  formatDateTime,
  relativeTime,
  shortDigest,
  trivySeverityClass,
} from '@/utils/format'

const route = useRoute()
const auth = useAuthStore()
const name = computed(() => route.params.name)

const repo = ref(null)
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const copied = ref(null)

const selected = ref(null)   // digest of the platform image shown below
const detail = ref(null)
const findings = ref([])
const findingsTotal = ref(0)
const filters = ref({ severity: '', fixable: '', kev: '', q: '' })
const watchInput = ref('')

async function load() {
  loading.value = true
  error.value = null
  try {
    repo.value = await api.dockerRepository(name.value)
    watchInput.value = (repo.value.watched_tags || []).join(', ')
    if (!selected.value) selected.value = defaultDigest()
    if (selected.value) await loadDetail()
  } catch (err) {
    error.value = err.status === 404 ? 'This repository has not been pulled or pushed yet.' : err.detail
  } finally {
    loading.value = false
  }
}

function defaultDigest() {
  const tag = repo.value?.tags?.[0]
  if (!tag) return repo.value?.digests?.[0]?.digest || null
  if (!tag.manifest.is_index) return tag.manifest.digest
  const amd = tag.platforms.find((p) => p.platform === 'linux/amd64' && p.fetched)
  const any = tag.platforms.find((p) => p.fetched && !p.attestation)
  return (amd || any)?.digest || null
}

async function loadDetail() {
  detail.value = await api.dockerManifest(selected.value)
  await loadFindings()
}

async function loadFindings() {
  if (!detail.value || detail.value.scan_status !== 'scanned') {
    findings.value = []
    findingsTotal.value = 0
    return
  }
  const f = filters.value
  const data = await api.dockerFindings(selected.value, {
    severity: f.severity || undefined,
    fixable: f.fixable === '' ? undefined : f.fixable,
    kev: f.kev === '' ? undefined : f.kev,
    q: f.q || undefined,
    limit: 500,
  })
  findings.value = data.findings
  findingsTotal.value = data.total
}

async function select(digest) {
  selected.value = digest
  await loadDetail()
}

async function copy(text, key) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
    setTimeout(() => (copied.value = null), 1500)
  } catch {
    copied.value = null
  }
}

async function update(payload, note) {
  message.value = null
  try {
    await api.dockerUpdateRepository(name.value, payload)
    message.value = note
    await load()
  } catch (err) {
    error.value = err.detail || 'Update failed.'
  }
}

function toggleQuarantine() {
  if (repo.value.quarantined) return update({ quarantined: false }, 'Quarantine lifted.')
  const reason = prompt('Why is this repository being quarantined? The reason is shown to anyone whose pull is refused.')
  if (reason === null) return
  return update({ quarantined: true, quarantine_reason: reason }, 'Repository quarantined; pulls are refused.')
}

function saveWatch() {
  const tags = watchInput.value.split(',').map((t) => t.trim()).filter(Boolean)
  return update({ watched_tags: tags }, tags.length ? `Watching ${tags.join(', ')}.` : 'No longer watching any tags.')
}

async function refresh(tag) {
  message.value = null
  try {
    const result = await api.dockerRefreshTag(name.value, tag)
    message.value = `${tag}: ${result.source}, ${result.layers_fetched} layers fetched, scans queued for ${result.platforms.join(', ') || 'the image'}.`
    await load()
  } catch (err) {
    error.value = err.detail || 'Refresh failed.'
  }
}

async function rescan(full) {
  message.value = null
  try {
    const result = await api.dockerRescan(selected.value, full)
    message.value = result.queued
      ? `Rescan queued (${result.mode === 'sbom' ? 'against the stored SBOM, no image pull' : 'full image scan'}).`
      : 'A scan is already queued for this image.'
    await loadDetail()
  } catch (err) {
    error.value = err.detail || 'Could not queue a rescan.'
  }
}

const countsFor = (m) => SEVERITIES.filter((s) => (m?.severity_counts || {})[s]).map((s) => [s, m.severity_counts[s]])

watch(filters, loadFindings, { deep: true })
watch(name, () => {
  selected.value = null
  load()
})
onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <div class="small dim"><router-link :to="{ name: 'images' }">Images</router-link> /</div>
      <h1 class="mono" style="word-break: break-all">{{ name }}</h1>
      <p v-if="repo" class="page-sub">
        <span v-if="repo.local" class="badge badge-accent">pushed here</span>
        <span v-else class="badge">cached from {{ repo.upstream }}</span>
        <span v-if="repo.quarantined" class="badge badge-danger">quarantined</span>
        <span v-if="repo.pinned" class="badge">pinned</span>
        <span class="faint small">· {{ repo.pull_count }} pulls · last {{ relativeTime(repo.last_pulled_at || repo.last_pushed_at) }}</span>
      </p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-ok">{{ message }}</div>
  <div v-if="loading && !repo" class="empty">Loading…</div>

  <template v-if="repo">
    <div v-if="repo.quarantined" class="alert alert-error">
      Pulls from this repository are refused<span v-if="repo.quarantine_reason">: {{ repo.quarantine_reason }}</span>.
    </div>

    <div class="card mb">
      <div class="card-body">
        <div class="copy-block">
          <pre>docker pull {{ repo.pull_reference }}:{{ repo.tags[0]?.tag || 'latest' }}</pre>
          <button class="btn btn-sm" @click="copy(`docker pull ${repo.pull_reference}:${repo.tags[0]?.tag || 'latest'}`, 'pull')">
            {{ copied === 'pull' ? 'Copied' : 'Copy' }}
          </button>
        </div>
      </div>
    </div>

    <div class="grid grid-2 mb image-grid">
      <div class="card">
        <div class="card-head">
          <h3>Tags</h3>
          <span class="faint small">{{ repo.tags.length }}</span>
        </div>
        <div class="card-body tight">
          <div v-if="!repo.tags.length" class="empty">No tags cached yet.</div>
          <div v-else class="table-wrap">
            <table>
              <thead>
                <tr><th>Tag</th><th>Digest</th><th>Platforms</th><th>Checked</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="tag in repo.tags" :key="tag.tag">
                  <td class="mono">{{ tag.tag }}</td>
                  <td class="mono small" :title="tag.manifest.digest">{{ shortDigest(tag.manifest.digest) }}</td>
                  <td>
                    <template v-if="tag.manifest.is_index">
                      <button
                        v-for="p in tag.platforms.filter((x) => !x.attestation)"
                        :key="p.digest"
                        class="eco-chip"
                        :class="{ active: selected === p.digest }"
                        :disabled="!p.fetched"
                        :title="p.fetched ? p.digest : 'not pulled yet'"
                        @click="select(p.digest)"
                      >
                        {{ p.platform || '?' }}
                      </button>
                      <span v-if="tag.platforms.some((x) => x.attestation)" class="faint small" title="BuildKit provenance / SBOM attestations; recorded, not scanned">
                        + attestations
                      </span>
                    </template>
                    <button
                      v-else
                      class="eco-chip"
                      :class="{ active: selected === tag.manifest.digest }"
                      @click="select(tag.manifest.digest)"
                    >
                      {{ tag.manifest.platform || 'single platform' }}
                    </button>
                  </td>
                  <td class="faint small nowrap">{{ relativeTime(tag.checked_at) }}</td>
                  <td class="num">
                    <button v-if="auth.isAdmin && !repo.local" class="btn btn-sm" title="Revalidate upstream now, pre-fetch layers, queue scans" @click="refresh(tag.tag)">
                      Refresh
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div v-if="auth.isAdmin" class="card">
        <div class="card-head"><h3>Administration</h3></div>
        <div class="card-body">
          <div class="row mb">
            <button class="btn" @click="update({ pinned: !repo.pinned }, repo.pinned ? 'Unpinned.' : 'Pinned: exempt from eviction.')">
              {{ repo.pinned ? 'Unpin' : 'Pin' }}
            </button>
            <button class="btn" :class="repo.quarantined ? '' : 'btn-danger'" @click="toggleQuarantine">
              {{ repo.quarantined ? 'Lift quarantine' : 'Quarantine' }}
            </button>
          </div>
          <div v-if="!repo.local" class="field">
            <label for="watch-tags">Watched tags</label>
            <div class="row">
              <input id="watch-tags" v-model="watchInput" placeholder="3.12-slim, latest" style="flex: 1" />
              <button class="btn" @click="saveWatch">Save</button>
            </div>
            <p class="field-hint">
              Revalidated, pre-fetched and rescanned every hour, so CI finds them warm and current.
              Watched tags are never evicted.
            </p>
          </div>
          <p class="field-hint" style="margin: 0">
            Pinning exempts the repository from storage eviction. Quarantine refuses every pull
            with the reason you give, and is recorded in the audit log.
          </p>
        </div>
      </div>
    </div>

    <div v-if="detail" class="card mb">
      <div class="card-head">
        <h3>
          <span class="mono">{{ shortDigest(detail.digest) }}</span>
          <span v-if="detail.platform" class="faint small"> · {{ detail.platform }}</span>
        </h3>
        <div class="row-tight">
          <a v-if="detail.has_sbom" class="btn btn-sm" :href="api.dockerSbomUrl(detail.digest)">SBOM (CycloneDX)</a>
          <template v-if="auth.isAdmin && detail.kind === 'image'">
            <button class="btn btn-sm" :disabled="detail.scan_status === 'queued' || detail.scan_status === 'scanning'" @click="rescan(false)">
              Rescan
            </button>
            <button class="btn btn-sm" title="Pull the image and scan it again from scratch" @click="rescan(true)">Full rescan</button>
          </template>
        </div>
      </div>
      <div class="card-body">
        <div v-if="detail.policy_block_reason" class="alert alert-error">
          Pulls of this image are refused: {{ detail.policy_block_reason }}
        </div>
        <div class="stat-row mb">
          <div>
            <div class="faint small">Scan</div>
            <span class="badge" :class="{ 'badge-ok': detail.scan_status === 'scanned', 'badge-warn': ['queued', 'scanning'].includes(detail.scan_status), 'badge-danger': detail.scan_status === 'failed' }">
              {{ detail.scan_status.replace('_', ' ') }}
            </span>
            <div v-if="detail.scanned_at" class="faint small">{{ relativeTime(detail.scanned_at) }}</div>
          </div>
          <div>
            <div class="faint small">Findings</div>
            <div class="row-tight">
              <span v-if="detail.kev_count" class="sev sev-critical" title="Known exploited (CISA KEV)">KEV {{ detail.kev_count }}</span>
              <span v-for="[sev, n] in countsFor(detail)" :key="sev" class="sev" :class="trivySeverityClass(sev)">
                {{ sev.toLowerCase() }} {{ n }}
              </span>
              <span v-if="detail.scan_status === 'scanned' && !countsFor(detail).length" class="badge badge-ok">none</span>
            </div>
            <div v-if="detail.scan_status === 'scanned'" class="faint small">{{ detail.fixable_count }} with a fixed version</div>
          </div>
          <div>
            <div class="faint small">Size</div>
            <div>{{ formatBytes(detail.total_size) }} <span class="faint small">· {{ detail.layer_count }} layers</span></div>
          </div>
          <div v-if="detail.scans[0]">
            <div class="faint small">Scanner</div>
            <div class="small">Trivy {{ detail.scans[0].trivy_version }} · {{ detail.scans[0].os || 'unknown OS' }}</div>
            <div class="faint small">DB {{ formatDateTime(detail.scans[0].db_updated_at) }}</div>
          </div>
        </div>
        <div v-if="detail.last_job?.status === 'failed'" class="alert alert-error small">
          Last scan failed after {{ detail.last_job.attempts }} attempts: {{ detail.last_job.error }}
        </div>
        <div v-if="detail.kind !== 'image'" class="alert alert-info small">
          This is {{ detail.kind === 'index' ? 'a multi-platform index' : `an ${detail.kind}` }}, not a runnable image, so it is not scanned itself.
        </div>

        <template v-if="detail.scan_status === 'scanned'">
          <div class="row mb">
            <select v-model="filters.severity" style="width: auto">
              <option value="">Any severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="CRITICAL,HIGH">High and above</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select v-model="filters.fixable" style="width: auto">
              <option value="">Fixed or not</option>
              <option :value="true">Has a fix</option>
              <option :value="false">No fix yet</option>
            </select>
            <select v-model="filters.kev" style="width: auto">
              <option value="">Any</option>
              <option :value="true">Known exploited only</option>
            </select>
            <input v-model.lazy="filters.q" type="search" placeholder="CVE or package…" style="flex: 1; min-width: 160px" />
            <span class="faint small">{{ findingsTotal }} shown</span>
          </div>
          <div v-if="!findings.length" class="empty">No findings match.</div>
          <div v-else class="table-wrap">
            <table>
              <thead>
                <tr><th>Vulnerability</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Title</th></tr>
              </thead>
              <tbody>
                <tr v-for="f in findings" :key="f.vuln_id + f.pkg_name + f.installed_version">
                  <td class="mono nowrap">
                    <a v-if="f.url" :href="f.url" target="_blank" rel="noopener noreferrer">{{ f.vuln_id }}</a>
                    <span v-else>{{ f.vuln_id }}</span>
                    <div class="row-tight">
                      <span v-if="f.kev" class="badge badge-danger" title="CISA Known Exploited Vulnerability">KEV</span>
                      <span v-if="f.denied" class="badge badge-danger">denied</span>
                      <span v-if="f.accepted" class="badge badge-warn">risk accepted</span>
                    </div>
                  </td>
                  <td>
                    <span class="sev" :class="trivySeverityClass(f.severity)">{{ f.severity.toLowerCase() }}</span>
                    <div v-if="f.cvss !== null" class="faint small">CVSS {{ f.cvss.toFixed(1) }}</div>
                  </td>
                  <td class="mono small">{{ f.pkg_name }}<div class="faint small">{{ f.pkg_type }}</div></td>
                  <td class="mono small">{{ f.installed_version || '—' }}</td>
                  <td class="mono small">{{ f.fixed_version || '—' }}</td>
                  <td class="small truncate" style="max-width: 320px" :title="f.title">{{ f.title || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>

        <details v-if="detail.layers.length" class="mt">
          <summary class="small dim">Layers ({{ detail.layers.length }})</summary>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Type</th><th>Digest</th><th class="num">Size</th><th>Cached</th></tr></thead>
              <tbody>
                <tr v-for="layer in detail.layers" :key="layer.digest">
                  <td class="small">{{ layer.type }}</td>
                  <td class="mono small" :title="layer.digest">{{ shortDigest(layer.digest) }}</td>
                  <td class="num small">{{ formatBytes(layer.size) }}</td>
                  <td class="small">{{ layer.cached ? 'yes' : 'no' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </details>
      </div>
    </div>
  </template>
</template>

<style scoped>
.stat-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1.6rem;
}
.stat-row .row-tight {
  flex-wrap: wrap;
}
.eco-chip + .eco-chip {
  margin-left: 0.3rem;
}
@media (max-width: 1000px) {
  .image-grid {
    grid-template-columns: 1fr;
  }
}
</style>
