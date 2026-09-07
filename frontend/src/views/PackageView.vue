<script setup>
import { onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import api from '@/api/client'
import { ecosystemBadge, formatBytes, formatDate, severityClass } from '@/utils/format'

const route = useRoute()
const pkg = ref(null)
const loading = ref(true)
const error = ref(null)

async function load() {
  loading.value = true
  error.value = null
  try {
    pkg.value = await api.packageDetail(route.params.ecosystem, route.params.name)
  } catch (err) {
    error.value = err.detail || 'Could not load this package.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
watch(() => [route.params.ecosystem, route.params.name], load)
</script>

<template>
  <div v-if="loading" class="empty">Loading…</div>
  <div v-else-if="error" class="alert alert-error">{{ error }}</div>

  <template v-else-if="pkg">
    <div class="page-head">
      <div style="min-width: 0">
        <div class="row-tight mb">
          <router-link :to="{ name: 'search' }" class="small">← Search</router-link>
        </div>
        <h1 style="margin-bottom: 0.3rem">{{ pkg.name }}</h1>
        <div class="row-tight">
          <span class="badge" :class="ecosystemBadge(pkg.ecosystem)">
            {{ pkg.ecosystem }}
          </span>
          <span v-if="pkg.latest_version" class="badge">{{ pkg.latest_version }}</span>
          <span v-if="pkg.is_local" class="badge badge-accent">published here</span>
          <span v-if="pkg.license" class="badge">{{ pkg.license }}</span>
        </div>
        <p v-if="pkg.description" class="page-sub" style="margin-top: 0.6rem">{{ pkg.description }}</p>
      </div>
    </div>

    <div v-if="pkg.blocked" class="alert alert-error">
      <strong>This package is blocked.</strong> {{ pkg.block_reason }}
    </div>

    <div class="grid grid-3 mb">
      <div class="card">
        <div class="card-head"><h3>Install</h3></div>
        <div class="card-body">
          <pre>{{ pkg.install_command }}</pre>
          <p class="field-hint">
            Requires your client to be pointed at this registry — see
            <router-link :to="{ name: 'setup' }">Client setup</router-link>.
          </p>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <h3>Available from</h3>
          <span class="faint small">
            {{ pkg.upstreams.length }}
            {{ pkg.upstreams.length === 1 ? 'source' : 'sources' }}
          </span>
        </div>
        <div class="card-body">
          <p v-if="!pkg.upstreams.length" class="faint small" style="margin: 0">
            No source recorded — this package predates provenance tracking.
          </p>
          <div v-for="source in pkg.upstreams" :key="source.id ?? 'local'" class="source-row">
            <div style="min-width: 0">
              <div class="row-tight">
                <a
                  v-if="source.web_url"
                  :href="source.web_url"
                  target="_blank"
                  rel="noopener noreferrer"
                  style="font-weight: 600"
                >
                  {{ source.name }} ↗
                </a>
                <span v-else style="font-weight: 600">{{ source.name }}</span>

                <span v-if="source.kind === 'local'" class="badge badge-accent">local</span>
                <span v-else-if="source.tier !== null" class="badge">tier {{ source.tier }}</span>
                <span v-if="source.is_origin" class="badge badge-ok" title="First seen here">
                  origin
                </span>
                <span v-if="source.id && !source.enabled" class="badge badge-warn">disabled</span>
              </div>

              <div class="faint small">
                {{ source.versions }} {{ source.versions === 1 ? 'version' : 'versions' }}
                <template v-if="source.files"> · {{ source.files }} files</template>
              </div>

              <!-- The address we actually fetch from. Shown when it differs
                   from the human page, so the link is never a guess. -->
              <a
                v-if="source.index_url"
                :href="source.index_url"
                target="_blank"
                rel="noopener noreferrer"
                class="mono faint"
                style="font-size: 0.74rem; word-break: break-all"
              >
                {{ source.index_url }}
              </a>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>Details</h3></div>
        <div class="card-body small">
          <div class="row" style="justify-content: space-between">
            <span class="dim">Downloads</span><span>{{ pkg.download_count }}</span>
          </div>
          <div class="row" style="justify-content: space-between">
            <span class="dim">Versions</span><span>{{ pkg.versions.length }}</span>
          </div>
          <div v-if="pkg.author" class="row" style="justify-content: space-between">
            <span class="dim">Author</span><span class="truncate">{{ pkg.author }}</span>
          </div>
          <div v-if="pkg.homepage" class="row" style="justify-content: space-between">
            <span class="dim">Homepage</span>
            <a :href="pkg.homepage" target="_blank" rel="noopener noreferrer" class="truncate">
              {{ pkg.homepage }}
            </a>
          </div>
          <div v-if="Object.keys(pkg.dist_tags || {}).length" style="margin-top: 0.5rem">
            <span class="dim">Tags</span>
            <div class="row-tight" style="margin-top: 0.25rem">
              <span v-for="(version, tag) in pkg.dist_tags" :key="tag" class="badge">
                {{ tag }} → {{ version }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Versions</h3></div>
      <div class="card-body tight">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Published</th>
                <th>Files</th>
                <th>CVEs</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="version in pkg.versions" :key="version.version">
                <td class="mono">{{ version.version }}</td>
                <td class="dim small nowrap">{{ formatDate(version.published_at) }}</td>
                <td class="small">
                  <div v-for="file in version.files" :key="file.filename" class="row-tight">
                    <span class="truncate mono" style="max-width: 280px">{{ file.filename }}</span>
                    <span class="faint">{{ formatBytes(file.size) }}</span>
                    <span v-if="file.cached" class="badge badge-ok">cached</span>
                  </div>
                  <span v-if="!version.files.length" class="faint">—</span>
                </td>
                <td style="max-width: 420px">
                  <div v-if="version.cves.length" class="cve-list">
                    <!-- A version can carry a dozen CVEs; showing them all
                         blows the table off the right edge of the page. -->
                    <span
                      v-for="cve in version.cves.slice(0, 4)"
                      :key="cve.cve_id"
                      class="badge badge-danger"
                      :title="cve.summary"
                    >
                      {{ cve.cve_id }}
                      <span v-if="cve.cvss_score" class="sev" :class="severityClass(cve.cvss_score)">
                        {{ cve.cvss_score.toFixed(1) }}
                      </span>
                    </span>
                    <span
                      v-if="version.cves.length > 4"
                      class="badge"
                      :title="version.cves.slice(4).map((c) => c.cve_id).join(', ')"
                    >
                      +{{ version.cves.length - 4 }} more
                    </span>
                  </div>
                  <span v-else class="faint small">none known</span>
                </td>
                <td>
                  <span v-if="version.yanked" class="badge badge-warn">yanked</span>
                  <span v-else-if="version.deprecated" class="badge badge-warn" :title="version.deprecated">
                    deprecated
                  </span>
                  <span v-else class="badge badge-ok">ok</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>
</template>

<style scoped>
.source-row {
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--border);
}
.source-row:first-child { padding-top: 0; }

/* CVE badges wrap instead of forcing the table wider than the viewport. */
.cve-list {
  display: flex;
  flex-wrap: wrap;
  gap: 3px;
}
.source-row:last-child { padding-bottom: 0; border-bottom: none; }
</style>
