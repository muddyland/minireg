<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'
import { ecosystemBadge, formatDate, severityClass } from '@/utils/format'

const vulns = ref([])
const total = ref(0)
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const scanning = ref(false)

const filters = ref({ ecosystem: '', severity: '', min_score: 0, max_score: 10, search: '' })
const detail = ref(null)

async function load() {
  loading.value = true
  try {
    const data = await api.vulnerabilities({
      ecosystem: filters.value.ecosystem || undefined,
      severity: filters.value.severity || undefined,
      min_score: filters.value.min_score,
      max_score: filters.value.max_score,
      search: filters.value.search || undefined,
      limit: 100,
    })
    vulns.value = data.vulnerabilities
    total.value = data.total
  } catch (err) {
    error.value = err.detail || 'Could not load vulnerabilities.'
  } finally {
    loading.value = false
  }
}

async function openDetail(vuln) {
  detail.value = await api.vulnerabilityAffected(vuln.id)
}

async function scan(rescanAll = false) {
  scanning.value = true
  message.value = null
  try {
    const result = await api.triggerScan({ rescan_all: rescanAll, limit: 1000 })
    message.value = `Scanned ${result.scanned} versions; ${result.with_cves} have known CVEs.`
    await load()
  } catch (err) {
    error.value = err.detail || 'Scan failed.'
  } finally {
    scanning.value = false
  }
}

async function rescore() {
  scanning.value = true
  message.value = null
  try {
    const result = await api.rescoreVulnerabilities()
    message.value =
      `Re-scored ${result.vulnerabilities_rescored} of ` +
      `${result.vulnerabilities_examined} CVEs; updated ${result.versions_updated} versions.`
    await load()
  } catch (err) {
    error.value = err.detail || 'Rescore failed.'
  } finally {
    scanning.value = false
  }
}

async function toggleSuppress(entry) {
  const suppressing = !entry.suppressed
  const reason = suppressing ? prompt('Reason for accepting this risk?') : null
  if (suppressing && reason === null) return
  await api.suppressVulnerability(entry.link_id, { suppressed: suppressing, reason })
  detail.value = await api.vulnerabilityAffected(detail.value.vulnerability.id)
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Vulnerabilities</h1>
      <p class="page-sub">
        CVEs affecting indexed packages, sourced from OSV.dev. Only records carrying a CVE
        identifier are tracked.
      </p>
    </div>
    <div class="row">
      <button class="btn" :disabled="scanning" @click="scan(false)">
        {{ scanning ? 'Scanning…' : 'Scan new versions' }}
      </button>
      <button class="btn" :disabled="scanning" @click="scan(true)">Rescan all</button>
      <button
        class="btn"
        :disabled="scanning"
        title="Recompute stored CVSS scores from the OSV records already held — no network access"
        @click="rescore"
      >
        Recompute scores
      </button>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-ok">{{ message }}</div>

  <div class="card mb">
    <div class="card-body">
      <div class="row">
        <select v-model="filters.ecosystem" style="width: auto" @change="load">
          <option value="">All ecosystems</option>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="cargo">cargo</option>
        </select>
        <select v-model="filters.severity" style="width: auto" @change="load">
          <option value="">Any severity</option>
          <option value="critical">Critical (9.0–10)</option>
          <option value="high">High (7.0–8.9)</option>
          <option value="medium">Medium (4.0–6.9)</option>
          <option value="low">Low (0.1–3.9)</option>
        </select>
        <div class="row-tight">
          <span class="small dim">CVSS</span>
          <input v-model.number="filters.min_score" type="number" min="0" max="10" step="0.1" style="width: 72px" @change="load" />
          <span class="small dim">–</span>
          <input v-model.number="filters.max_score" type="number" min="0" max="10" step="0.1" style="width: 72px" @change="load" />
        </div>
        <input v-model="filters.search" type="search" placeholder="CVE id or summary…" style="flex: 1; min-width: 180px" @keyup.enter="load" />
        <button class="btn" @click="load">Filter</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h3>Known CVEs</h3>
      <span class="faint small">{{ total }} total</span>
    </div>
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!vulns.length" class="empty">
        No CVEs recorded. Run a scan to check indexed packages against OSV.dev.
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>CVSS</th>
              <th>Ecosystem</th>
              <th>Summary</th>
              <th class="num">Affected</th>
              <th>Published</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vuln in vulns" :key="vuln.id">
              <td class="mono nowrap">
                {{ vuln.cve_id }}
                <div v-if="vuln.id !== vuln.cve_id" class="faint small">{{ vuln.id }}</div>
              </td>
              <td>
                <span v-if="vuln.cvss_score !== null" class="sev" :class="severityClass(vuln.cvss_score)">
                  {{ vuln.cvss_score.toFixed(1) }}
                </span>
                <span v-else class="faint">—</span>
                <div class="faint small">{{ vuln.severity || '' }}</div>
              </td>
              <td>
                <span class="badge" :class="ecosystemBadge(vuln.ecosystem)">
                  {{ vuln.ecosystem }}
                </span>
              </td>
              <td class="small truncate" style="max-width: 380px" :title="vuln.summary">
                {{ vuln.summary || '—' }}
              </td>
              <td class="num">{{ vuln.affected_versions }}</td>
              <td class="faint small nowrap">{{ formatDate(vuln.published) }}</td>
              <td class="num">
                <button class="btn btn-sm" @click="openDetail(vuln)">Details</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div v-if="detail" class="modal-backdrop" @click.self="detail = null">
    <div class="modal" style="max-width: 760px">
      <div class="modal-head">
        <div>
          <h3 style="margin: 0">{{ detail.vulnerability.cve_id }}</h3>
          <span v-if="detail.vulnerability.cvss_score !== null" class="sev" :class="severityClass(detail.vulnerability.cvss_score)">
            CVSS {{ detail.vulnerability.cvss_score.toFixed(1) }} ({{ detail.vulnerability.severity }})
          </span>
        </div>
        <button class="btn btn-sm btn-ghost" @click="detail = null">✕</button>
      </div>
      <div class="modal-body">
        <p v-if="detail.vulnerability.summary"><strong>{{ detail.vulnerability.summary }}</strong></p>
        <p v-if="detail.vulnerability.details" class="dim small" style="white-space: pre-wrap">
          {{ detail.vulnerability.details.slice(0, 1200) }}
        </p>

        <h4 class="small mt">Affected versions in this registry</h4>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Package</th><th>Version</th><th>Fixed in</th><th>Status</th><th></th></tr>
            </thead>
            <tbody>
              <tr v-for="entry in detail.affected" :key="entry.link_id">
                <td>
                  <span class="badge" :class="ecosystemBadge(entry.ecosystem)">
                    {{ entry.ecosystem }}
                  </span>
                  {{ entry.package }}
                </td>
                <td class="mono">{{ entry.version }}</td>
                <td class="mono">{{ entry.fixed_version || '—' }}</td>
                <td>
                  <span v-if="entry.suppressed" class="badge badge-warn" :title="entry.suppressed_reason">
                    risk accepted
                  </span>
                  <span v-else class="badge badge-danger">reported</span>
                </td>
                <td class="num">
                  <button class="btn btn-sm" @click="toggleSuppress(entry)">
                    {{ entry.suppressed ? 'Un-accept' : 'Accept risk' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="field-hint">
          Accepting a risk only hides the finding from <code>npm audit</code> output. It does
          <strong>not</strong> lift a block — the block list and CVE range policy are always enforced.
        </p>

        <template v-if="detail.vulnerability.references?.length">
          <h4 class="small mt">References</h4>
          <ul class="small">
            <li v-for="ref in detail.vulnerability.references.slice(0, 8)" :key="ref.url">
              <a :href="ref.url" target="_blank" rel="noopener noreferrer">{{ ref.url }}</a>
            </li>
          </ul>
        </template>
      </div>
    </div>
  </div>
</template>
