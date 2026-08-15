<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'
import { formatBytes, formatDate, formatNumber, severityClass } from '@/utils/format'

const packages = ref([])
const total = ref(0)
const loading = ref(true)
const error = ref(null)
const detail = ref(null)

const filters = ref({ ecosystem: '', search: '', local_only: false })
const page = ref(0)
const pageSize = 50

async function load() {
  loading.value = true
  try {
    const data = await api.adminPackages({
      ecosystem: filters.value.ecosystem || undefined,
      search: filters.value.search || undefined,
      local_only: filters.value.local_only || undefined,
      limit: pageSize,
      offset: page.value * pageSize,
    })
    packages.value = data.packages
    total.value = data.total
  } catch (err) {
    error.value = err.detail || 'Could not load packages.'
  } finally {
    loading.value = false
  }
}

async function openDetail(pkg) {
  detail.value = await api.adminPackageDetail(pkg.id)
}

async function purge(pkg) {
  if (!confirm(`Drop cached files for "${pkg.name}"? Metadata is kept and files re-download on demand.`)) return
  await api.deletePackage(pkg.id, true)
  await load()
}

async function remove(pkg) {
  const warning = pkg.is_local
    ? `"${pkg.name}" was published here. Deleting it is PERMANENT — the artifacts cannot be recovered from an upstream. Continue?`
    : `Delete "${pkg.name}" entirely? It will be re-fetched from upstream on the next request.`
  if (!confirm(warning)) return
  await api.deletePackage(pkg.id, false)
  detail.value = null
  await load()
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Packages</h1>
      <p class="page-sub">Everything this registry has indexed or cached.</p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div class="card mb">
    <div class="card-body">
      <div class="row">
        <select v-model="filters.ecosystem" style="width: auto" @change="((page = 0), load())">
          <option value="">All ecosystems</option>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
        </select>
        <input v-model="filters.search" type="search" placeholder="Name contains…" style="flex: 1" @keyup.enter="((page = 0), load())" />
        <label class="check">
          <input v-model="filters.local_only" type="checkbox" @change="((page = 0), load())" />
          Published here only
        </label>
        <button class="btn" @click="((page = 0), load())">Filter</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h3>Indexed packages</h3>
      <span class="faint small">{{ formatNumber(total) }} total</span>
    </div>
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!packages.length" class="empty">No packages match these filters.</div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Latest</th><th class="num">Versions</th>
              <th class="num">Downloads</th><th>Max CVSS</th><th>Origin</th><th>First seen</th><th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="pkg in packages" :key="pkg.id">
              <td>
                <span class="badge" :class="pkg.ecosystem === 'npm' ? 'badge-npm' : 'badge-pypi'">
                  {{ pkg.ecosystem }}
                </span>
                <strong>{{ pkg.name }}</strong>
                <div v-if="pkg.description" class="faint small truncate" style="max-width: 320px">
                  {{ pkg.description }}
                </div>
              </td>
              <td class="mono small">{{ pkg.latest_version || '—' }}</td>
              <td class="num">{{ pkg.version_count }}</td>
              <td class="num">{{ formatNumber(pkg.download_count) }}</td>
              <td>
                <span v-if="pkg.max_cvss !== null" class="sev" :class="severityClass(pkg.max_cvss)">
                  {{ pkg.max_cvss.toFixed(1) }}
                </span>
                <span v-else class="faint">—</span>
              </td>
              <td>
                <span class="badge" :class="pkg.is_local ? 'badge-accent' : ''">
                  {{ pkg.is_local ? 'local' : 'upstream' }}
                </span>
              </td>
              <td class="faint small nowrap">{{ formatDate(pkg.first_seen_at) }}</td>
              <td class="num nowrap">
                <button class="btn btn-sm" @click="openDetail(pkg)">Details</button>
                <button v-if="!pkg.is_local" class="btn btn-sm" @click="purge(pkg)">Purge cache</button>
                <button class="btn btn-sm btn-danger" @click="remove(pkg)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div v-if="total > pageSize" class="card-head" style="border-top: 1px solid var(--border); border-bottom: none">
      <button class="btn btn-sm" :disabled="page === 0" @click="((page -= 1), load())">Previous</button>
      <span class="faint small">Page {{ page + 1 }} of {{ Math.ceil(total / pageSize) }}</span>
      <button class="btn btn-sm" :disabled="(page + 1) * pageSize >= total" @click="((page += 1), load())">
        Next
      </button>
    </div>
  </div>

  <div v-if="detail" class="modal-backdrop" @click.self="detail = null">
    <div class="modal" style="max-width: 860px">
      <div class="modal-head">
        <div>
          <h3 style="margin: 0">{{ detail.package.name }}</h3>
          <div class="row-tight" style="margin-top: 0.25rem">
            <span class="badge" :class="detail.package.ecosystem === 'npm' ? 'badge-npm' : 'badge-pypi'">
              {{ detail.package.ecosystem }}
            </span>
            <span v-if="detail.package.is_local" class="badge badge-accent">published here</span>
            <span class="faint small">{{ formatNumber(detail.package.download_count) }} downloads</span>
          </div>
        </div>
        <button class="btn btn-sm btn-ghost" @click="detail = null">✕</button>
      </div>
      <div class="modal-body">
        <p v-if="detail.package.description" class="dim">{{ detail.package.description }}</p>

        <div v-if="detail.upstreams?.length" class="mb">
          <h4 class="small" style="margin-bottom: 0.35rem">Available from</h4>
          <div class="row-tight">
            <template v-for="source in detail.upstreams" :key="source.id ?? 'local'">
              <a
                v-if="source.web_url"
                :href="source.web_url"
                target="_blank"
                rel="noopener noreferrer"
                class="badge badge-accent"
                :title="source.index_url || ''"
              >
                {{ source.name }} ↗
              </a>
              <span
                v-else
                class="badge"
                :class="source.kind === 'local' ? 'badge-accent' : ''"
                :title="source.index_url || ''"
              >
                {{ source.name }}
              </span>
            </template>
          </div>
        </div>

        <div v-if="Object.keys(detail.package.dist_tags || {}).length" class="row-tight mb">
          <span v-for="(version, tag) in detail.package.dist_tags" :key="tag" class="badge">
            {{ tag }} → {{ version }}
          </span>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Version</th><th>Files</th><th>CVEs</th><th>Scanned</th><th>Status</th></tr>
            </thead>
            <tbody>
              <tr v-for="version in detail.versions" :key="version.id">
                <td class="mono">{{ version.version }}</td>
                <td class="small">
                  <div v-for="file in version.files" :key="file.id" class="row-tight">
                    <span class="truncate mono" style="max-width: 240px">{{ file.filename }}</span>
                    <span class="faint">{{ formatBytes(file.size) }}</span>
                    <span class="badge" :class="file.cached ? 'badge-ok' : ''">
                      {{ file.cached ? 'cached' : 'not cached' }}
                    </span>
                  </div>
                  <span v-if="!version.files.length" class="faint">—</span>
                </td>
                <td style="max-width: 320px">
                  <span
                    v-for="cve in version.cves.slice(0, 3)"
                    :key="cve.cve_id"
                    class="badge badge-danger"
                    :title="cve.summary"
                    style="margin: 1px"
                  >
                    {{ cve.cve_id }}
                    <span v-if="cve.cvss_score" class="sev" :class="severityClass(cve.cvss_score)">
                      {{ cve.cvss_score.toFixed(1) }}
                    </span>
                  </span>
                  <span
                    v-if="version.cves.length > 3"
                    class="badge"
                    style="margin: 1px"
                    :title="version.cves.slice(3).map((c) => c.cve_id).join(', ')"
                  >
                    +{{ version.cves.length - 3 }}
                  </span>
                  <span v-if="!version.cves.length" class="faint small">none</span>
                </td>
                <td class="faint small nowrap">
                  {{ version.scanned_at ? formatDate(version.scanned_at) : 'never' }}
                </td>
                <td>
                  <span v-if="version.yanked" class="badge badge-warn">yanked</span>
                  <span v-else-if="version.deprecated" class="badge badge-warn">deprecated</span>
                  <span v-else class="badge badge-ok">ok</span>
                  <span v-if="version.is_local" class="badge badge-accent">local</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-danger" @click="remove(detail.package)">Delete package</button>
        <button class="btn" @click="detail = null">Close</button>
      </div>
    </div>
  </div>
</template>
