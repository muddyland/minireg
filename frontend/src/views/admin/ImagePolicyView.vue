<script setup>
/**
 * Everything an operator decides about images in one place: which upstreams
 * exist and how much of their rate limit is left, what a pull or a push must
 * meet, how scanning runs, how much disk images may use, and "which of our
 * images contain CVE-X?".
 */
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { formatBytes, formatNumber, percent, relativeTime, shortDigest, trivySeverityClass } from '@/utils/format'

const SEVERITY_OPTIONS = [
  { value: null, label: 'Off' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High and above' },
  { value: 'MEDIUM', label: 'Medium and above' },
]

const policy = ref(null)
const stats = ref(null)
const error = ref(null)
const message = ref(null)
const saving = ref(false)
const denyText = ref('')
const allowText = ref('')
const platformsText = ref('')
const budgetGb = ref(0)

const cve = ref('')
const cveResult = ref(null)
const summary = ref(null)

async function load() {
  error.value = null
  try {
    const [p, s, sum] = await Promise.all([
      api.dockerPolicy(),
      api.dockerStats(),
      api.dockerVulnerabilities({}),
    ])
    policy.value = p
    stats.value = s
    summary.value = sum
    denyText.value = p.deny_cves.join('\n')
    allowText.value = p.allow_cves.join('\n')
    platformsText.value = p.platforms.join(', ')
    budgetGb.value = Math.round(p.effective_budget_bytes / 1024 ** 3)
  } catch (err) {
    error.value = err.detail || 'Could not load image settings.'
  }
}

const lines = (text) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

async function save() {
  saving.value = true
  message.value = null
  error.value = null
  try {
    const payload = {
      ...policy.value,
      deny_cves: lines(denyText.value),
      allow_cves: lines(allowText.value),
      platforms: lines(platformsText.value),
      storage_budget_bytes: Math.max(0, Math.round(Number(budgetGb.value) || 0)) * 1024 ** 3,
    }
    policy.value = await api.dockerUpdatePolicy(payload)
    message.value = 'Image policy saved. Pushed images were re-checked against the push rules.'
    stats.value = await api.dockerStats()
  } catch (err) {
    error.value = err.detail || 'Could not save.'
  } finally {
    saving.value = false
  }
}

async function searchCve() {
  if (!cve.value.trim()) {
    cveResult.value = null
    return
  }
  cveResult.value = await api.dockerVulnerabilities({ cve: cve.value.trim() })
}

const storagePct = computed(() =>
  stats.value ? percent(stats.value.storage.total_bytes, stats.value.storage.budget_bytes) : 0,
)
const hitRate = computed(() => {
  const p = stats.value?.pulls_24h
  return p && p.total ? Math.round((p.cache_hits / p.total) * 100) : null
})
const ratelimits = computed(() => Object.entries(stats.value?.upstream_ratelimits || {}))
const scannerSeen = computed(() => Object.entries(stats.value?.scanner_last_seen || {}))

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Image policy</h1>
      <p class="page-sub">
        Container images are scanned with Trivy by the scanner worker. Pulls of upstream images
        are allowed by default and blocked only by the rules below; images pushed here are held
        to a stricter bar before anyone can run them.
      </p>
    </div>
    <router-link class="btn" :to="{ name: 'help-page', params: { slug: 'containers' } }">Documentation</router-link>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-ok">{{ message }}</div>

  <template v-if="policy && stats">
    <div class="grid grid-4 mb">
      <div class="card stat">
        <div class="stat-label">Storage</div>
        <div class="stat-value">{{ formatBytes(stats.storage.total_bytes) }}</div>
        <div class="bar"><div class="bar-fill" :style="{ width: storagePct + '%' }" /></div>
        <div class="faint small">of {{ stats.storage.budget_bytes ? formatBytes(stats.storage.budget_bytes) : 'no budget' }}</div>
      </div>
      <div class="card stat">
        <div class="stat-label">Pulls, 24h</div>
        <div class="stat-value">{{ formatNumber(stats.pulls_24h.total) }}</div>
        <div class="faint small">{{ hitRate === null ? 'no pulls yet' : `${hitRate}% served from cache` }}</div>
      </div>
      <div class="card stat">
        <div class="stat-label">Scan queue</div>
        <div class="stat-value">{{ formatNumber((stats.queue.queued || 0) + (stats.queue.running || 0)) }}</div>
        <div class="faint small">
          <template v-if="scannerSeen.length">
            {{ scannerSeen.length }} worker{{ scannerSeen.length > 1 ? 's' : '' }}, last seen {{ relativeTime(scannerSeen[0][1]) }}
          </template>
          <template v-else>
            <span class="sev sev-high">no scanner has checked in</span> ·
            <router-link :to="{ name: 'tokens', query: { preset: 'scanner' } }">set one up</router-link>
          </template>
        </div>
      </div>
      <div class="card stat">
        <div class="stat-label">Needs attention</div>
        <div class="stat-value">{{ stats.kev_images }}</div>
        <div class="faint small">
          images with known-exploited CVEs · {{ stats.push_blocked_images }} pushed images blocked ·
          {{ stats.quarantined_repositories }} quarantined
        </div>
      </div>
    </div>

    <div class="card mb">
      <div class="card-head">
        <h3>Upstream rate limits</h3>
        <router-link class="small" :to="{ name: 'docker-upstreams' }">Manage container upstreams →</router-link>
      </div>
      <div class="card-body">
        <p v-if="!ratelimits.length" class="field-hint" style="margin: 0">
          No rate-limit headers seen yet. Docker Hub reports them on each manifest request.
        </p>
        <div v-if="ratelimits.length" class="table-wrap mt">
          <table>
            <thead><tr><th>Upstream</th><th>Rate limit remaining</th><th>Window</th><th>Seen</th></tr></thead>
            <tbody>
              <tr v-for="[name, rl] in ratelimits" :key="name">
                <td class="mono">{{ name }}</td>
                <td>
                  <span class="sev" :class="rl.remaining !== null && rl.limit && rl.remaining / rl.limit < 0.2 ? 'sev-high' : 'sev-low'">
                    {{ rl.remaining ?? '?' }} / {{ rl.limit ?? '?' }}
                  </span>
                </td>
                <td class="small">{{ rl.window_seconds ? `${Math.round(rl.window_seconds / 3600)}h` : '—' }}</td>
                <td class="faint small">{{ relativeTime(rl.observed_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="grid grid-2 mb policy-grid">
      <div class="card">
        <div class="card-head"><h3>Pull rules</h3><span class="faint small">upstream images</span></div>
        <div class="card-body">
          <label class="check"><input v-model="policy.pull.block_kev" type="checkbox" /> Block images with a CISA known-exploited vulnerability</label>
          <div class="field">
            <label>Block at severity</label>
            <select v-model="policy.pull.block_severity">
              <option v-for="o in SEVERITY_OPTIONS" :key="String(o.value)" :value="o.value">{{ o.label }}</option>
            </select>
            <p class="field-hint">
              Off by default: ordinary base images carry hundreds of findings
              (<code>postgres:16</code> has over 300), so a severity threshold on pulls blocks almost
              everything.
            </p>
          </div>
          <label class="check"><input v-model="policy.pull.only_fixable" type="checkbox" /> Count only findings that have a fixed version</label>
          <hr />
          <label class="check"><input v-model="policy.strict_mode" type="checkbox" /> Strict mode: never serve an unscanned image</label>
          <p class="field-hint">Unscanned pulls get 503 with Retry-After. Docker retries a few times, then fails the pull.</p>
          <label class="check"><input v-model="policy.hold_enabled" type="checkbox" /> Hold a first pull while the image is scanned</label>
          <div class="row" style="gap: 0.8rem">
            <div class="field" style="flex: 1">
              <label>Hold for up to (s)</label>
              <input v-model.number="policy.hold_seconds" type="number" min="0" max="120" />
            </div>
            <div class="field" style="flex: 1">
              <label>Only images up to (MB)</label>
              <input :value="Math.round(policy.hold_max_bytes / 1024 ** 2)" type="number" min="0" @change="policy.hold_max_bytes = $event.target.value * 1024 ** 2" />
            </div>
          </div>
          <p class="field-hint" style="margin: 0">Larger images are served straight away and scanned in the background.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>Push rules</h3><span class="faint small">images built here</span></div>
        <div class="card-body">
          <label class="check"><input v-model="policy.push.block_kev" type="checkbox" /> Block images with a known-exploited vulnerability</label>
          <div class="field">
            <label>Block at severity</label>
            <select v-model="policy.push.block_severity">
              <option v-for="o in SEVERITY_OPTIONS" :key="String(o.value)" :value="o.value">{{ o.label }}</option>
            </select>
          </div>
          <label class="check"><input v-model="policy.push.only_fixable" type="checkbox" /> Count only findings that have a fixed version</label>
          <label class="check"><input v-model="policy.push_require_scan" type="checkbox" /> Refuse pulls of a pushed image until its scan is in</label>
          <p class="field-hint">
            A push is always accepted; the verdict is attached to the digest once the scan finishes, and
            pulls of a failing image are refused with the reason. Rebuild on a patched base and push again.
          </p>
          <hr />
          <div class="field">
            <label>Denied CVEs <span class="faint">(always blocked, pull or push)</span></label>
            <textarea v-model="denyText" rows="3" placeholder="CVE-2021-44228" />
          </div>
          <div class="field">
            <label>Accepted risks <span class="faint">(never count towards a block)</span></label>
            <textarea v-model="allowText" rows="3" placeholder="CVE-2011-3374" />
          </div>
        </div>
      </div>
    </div>

    <div class="grid grid-2 mb policy-grid">
      <div class="card">
        <div class="card-head">
          <h3>Scanning</h3>
          <router-link class="btn btn-sm" :to="{ name: 'tokens', query: { preset: 'scanner' } }">
            New scanner token
          </router-link>
        </div>
        <div class="card-body">
          <p class="field-hint" style="margin-top: 0">
            Scans run in a separate worker (<code>docker compose --profile scanner up -d</code>) that signs in
            with its own scanner token. Revoke that token on API tokens to cut a worker off.
          </p>
          <label class="check"><input v-model="policy.scanning_enabled" type="checkbox" /> Scanning enabled</label>
          <label class="check"><input v-model="policy.scan_on_pull" type="checkbox" /> Scan upstream images when first pulled</label>
          <label class="check"><input v-model="policy.ignore_unfixed" type="checkbox" /> Ignore findings with no fixed version</label>
          <div class="row" style="gap: 0.8rem">
            <div class="field" style="flex: 1">
              <label>Rescan every (hours)</label>
              <input v-model.number="policy.rescan_hours" type="number" min="1" />
            </div>
            <div class="field" style="flex: 1">
              <label>…if pulled in the last (days)</label>
              <input v-model.number="policy.rescan_recent_days" type="number" min="1" />
            </div>
          </div>
          <p class="field-hint">Rescans match the stored SBOM against the current vulnerability database; the image is not pulled again.</p>
          <div class="row" style="gap: 0.8rem">
            <div class="field" style="flex: 1">
              <label>Scan timeout (s)</label>
              <input v-model.number="policy.scan_timeout_seconds" type="number" min="30" />
            </div>
            <div class="field" style="flex: 1">
              <label>Largest image scanned (GB)</label>
              <input :value="Math.round(policy.max_scan_bytes / 1024 ** 3)" type="number" min="0" @change="policy.max_scan_bytes = $event.target.value * 1024 ** 3" />
            </div>
          </div>
          <div class="field">
            <label>Platforms scanned</label>
            <input v-model="platformsText" placeholder="linux/amd64, linux/arm64" />
            <p class="field-hint" style="margin: 0">Other platforms of a multi-platform image are served but not scanned. Empty scans all.</p>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>Storage</h3></div>
        <div class="card-body">
          <div class="field">
            <label>Disk budget for cached images (GB)</label>
            <input v-model.number="budgetGb" type="number" min="0" />
            <p class="field-hint">
              Over budget, the least recently pulled cached images are evicted until usage is back
              under 90%. Pinned repositories, watched tags and pushed images are never evicted. 0 disables
              eviction.
            </p>
          </div>
          <table class="small">
            <tbody>
              <tr><td class="dim">Layers</td><td class="num">{{ formatNumber(stats.storage.blob_count) }}</td><td class="num">{{ formatBytes(stats.storage.blob_bytes) }}</td></tr>
              <tr><td class="dim">…pushed here</td><td></td><td class="num">{{ formatBytes(stats.storage.local_blob_bytes) }}</td></tr>
              <tr><td class="dim">Manifests</td><td class="num">{{ formatNumber(stats.storage.manifest_count) }}</td><td class="num">{{ formatBytes(stats.storage.manifest_bytes) }}</td></tr>
              <tr><td class="dim">Repositories</td><td class="num">{{ formatNumber(stats.storage.repository_count) }}</td><td></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="row mb" style="justify-content: flex-end">
      <button class="btn btn-primary" :disabled="saving" @click="save">{{ saving ? 'Saving…' : 'Save policy' }}</button>
    </div>

    <div class="card">
      <div class="card-head"><h3>Which images contain…</h3></div>
      <div class="card-body">
        <div class="row mb">
          <input v-model="cve" type="search" placeholder="CVE-2024-3094" style="flex: 1" @keyup.enter="searchCve" />
          <button class="btn" @click="searchCve">Search</button>
        </div>
        <template v-if="cveResult">
          <div v-if="cveResult.kev_entry" class="alert alert-error small">
            {{ cveResult.kev_entry.cve_id }} is on CISA's Known Exploited Vulnerabilities list
            ({{ cveResult.kev_entry.vendor }} {{ cveResult.kev_entry.product }}, added {{ cveResult.kev_entry.date_added }}<span v-if="cveResult.kev_entry.ransomware">, used in ransomware campaigns</span>).
          </div>
          <div v-if="!cveResult.images.length" class="empty">No scanned image contains it.</div>
          <div v-else class="table-wrap">
            <table>
              <thead><tr><th>Image</th><th>Platform</th><th>Where</th><th>Fixed in</th></tr></thead>
              <tbody>
                <tr v-for="img in cveResult.images" :key="img.digest">
                  <td class="mono small" :title="img.digest">{{ shortDigest(img.digest) }}</td>
                  <td class="small">{{ img.platform || '—' }}</td>
                  <td class="small">
                    <div v-for="w in img.where" :key="w">
                      <router-link class="mono" :to="{ name: 'image', params: { name: w.split(':')[0] } }">{{ w }}</router-link>
                    </div>
                  </td>
                  <td class="mono small">{{ img.a_fixed_version || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <template v-else-if="summary?.top?.length">
          <h4 class="small">Most widespread critical and known-exploited findings</h4>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Vulnerability</th><th>Severity</th><th class="num">Images</th><th>Title</th></tr></thead>
              <tbody>
                <tr v-for="row in summary.top.slice(0, 15)" :key="row.vuln_id">
                  <td class="mono nowrap">
                    <a href="#" @click.prevent="cve = row.vuln_id; searchCve()">{{ row.vuln_id }}</a>
                    <span v-if="row.kev" class="badge badge-danger">KEV</span>
                  </td>
                  <td><span class="sev" :class="trivySeverityClass(row.severity)">{{ row.severity.toLowerCase() }}</span></td>
                  <td class="num">{{ row.image_count }}</td>
                  <td class="small truncate" style="max-width: 420px" :title="row.title">{{ row.title }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="field-hint">KEV catalogue: {{ formatNumber(summary.kev_catalogue_size) }} entries, refreshed daily.</p>
        </template>
      </div>
    </div>
  </template>
</template>

<style scoped>
.stat .stat-label {
  font-size: 0.78rem;
  color: var(--text-dim);
}
.stat .stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0.1rem 0 0.35rem;
}
.stat {
  padding: 0.9rem 1rem;
}
textarea {
  width: 100%;
  font-family: var(--mono, monospace);
}
@media (max-width: 1000px) {
  .policy-grid {
    grid-template-columns: 1fr;
  }
}
</style>
