<script setup>
/**
 * Container images: every repository this registry holds, cached from an
 * upstream or pushed here, with its tag count and worst scan result.
 */
import { onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api/client'
import { formatBytes, formatNumber, relativeTime } from '@/utils/format'
import EcosystemBadge from '@/components/EcosystemBadge.vue'

const route = useRoute()
const router = useRouter()
const images = ref([])
const total = ref(0)
const loading = ref(true)
const error = ref(null)
const config = ref(null)
const q = ref(route.query.q || '')
const scope = ref(route.query.scope || '')

const SCOPES = [
  { value: '', label: 'All' },
  { value: 'cached', label: 'Cached' },
  { value: 'local', label: 'Pushed here' },
  { value: 'watched', label: 'Watched' },
  { value: 'quarantined', label: 'Quarantined' },
]

async function load() {
  loading.value = true
  error.value = null
  try {
    const data = await api.dockerImages({ q: q.value || undefined, scope: scope.value || undefined, limit: 100 })
    images.value = data.images
    total.value = data.total
  } catch (err) {
    error.value = err.detail || 'Could not load images.'
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  router.replace({ query: { q: q.value || undefined, scope: scope.value || undefined } })
}

watch(() => route.query, () => {
  q.value = route.query.q || ''
  scope.value = route.query.scope || ''
  load()
})

onMounted(async () => {
  load()
  try {
    config.value = await api.dockerClientConfig()
  } catch {
    config.value = null
  }
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Images</h1>
      <p class="page-sub">
        Container images pulled through this registry or pushed to it. Pulls are cached,
        scanned with Trivy, and served from here the next time.
      </p>
    </div>
    <router-link class="btn" :to="{ name: 'setup', query: { tab: 'docker' } }">Client setup</router-link>
  </div>

  <div v-if="config" class="card mb">
    <div class="card-body">
      <div class="row small" style="gap: 1.2rem; flex-wrap: wrap">
        <span class="dim">Pull:</span>
        <code class="mono">{{ config.examples.hub }}</code>
        <code v-for="example in config.examples.other.slice(0, 2)" :key="example" class="mono">{{ example }}</code>
      </div>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div class="card mb">
    <div class="card-body">
      <div class="row">
        <input
          v-model="q"
          type="search"
          placeholder="Filter by name, e.g. python or dockerhub/library"
          style="flex: 1; min-width: 200px"
          @keyup.enter="applyFilters"
        />
        <div class="eco-filter" style="margin-top: 0">
          <button
            v-for="option in SCOPES"
            :key="option.value"
            class="eco-chip"
            :class="{ active: scope === option.value }"
            @click="scope = option.value; applyFilters()"
          >
            {{ option.label }}
          </button>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h3><EcosystemBadge ecosystem="docker" label="images" /></h3>
      <span class="faint small">{{ formatNumber(total) }} repositories</span>
    </div>
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!images.length" class="empty">
        No images yet. Pull one through the registry and it appears here.
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Source</th>
              <th class="num">Tags</th>
              <th>Scan</th>
              <th class="num">Size</th>
              <th class="num">Pulls</th>
              <th>Last pulled</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="image in images" :key="image.name">
              <td>
                <router-link class="mono" :to="{ name: 'image', params: { name: image.name } }">
                  {{ image.name }}
                </router-link>
                <div class="row-tight" style="margin-top: 0.2rem">
                  <span v-if="image.quarantined" class="badge badge-danger">quarantined</span>
                  <span v-if="image.pinned" class="badge">pinned</span>
                  <span v-if="image.watched_tags.length" class="badge" :title="image.watched_tags.join(', ')">
                    watching {{ image.watched_tags.length }}
                  </span>
                </div>
              </td>
              <td>
                <span v-if="image.local" class="badge badge-accent">pushed here</span>
                <span v-else class="badge">{{ image.upstream || 'upstream' }}</span>
              </td>
              <td class="num">{{ image.tag_count }}</td>
              <td class="nowrap">
                <template v-if="image.scanned_count">
                  <span v-if="image.kev_count" class="sev sev-critical" title="Known exploited (CISA KEV)">
                    KEV {{ image.kev_count }}
                  </span>
                  <span v-if="image.worst_counts.CRITICAL" class="sev sev-critical">C {{ image.worst_counts.CRITICAL }}</span>
                  <span v-if="image.worst_counts.HIGH" class="sev sev-high">H {{ image.worst_counts.HIGH }}</span>
                  <span
                    v-if="!image.kev_count && !image.worst_counts.CRITICAL && !image.worst_counts.HIGH"
                    class="badge badge-ok"
                  >no high+</span>
                </template>
                <span v-else-if="image.image_count" class="faint small">not scanned yet</span>
                <span v-else class="faint small">—</span>
              </td>
              <td class="num nowrap">{{ image.largest_image_bytes ? formatBytes(image.largest_image_bytes) : '—' }}</td>
              <td class="num">{{ formatNumber(image.pull_count) }}</td>
              <td class="faint small nowrap">{{ relativeTime(image.last_pulled_at || image.last_pushed_at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
