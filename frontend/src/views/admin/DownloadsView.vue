<script setup>
/**
 * Package requests, with an optional live tail.
 *
 * The tail is a server-sent event stream rather than a poll: an operator
 * watching a CI fleet wants to see requests arrive, and re-fetching the whole
 * first page every second to spot a few new rows is a lot of database work
 * for a worse result.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import api from '@/api/client'
import { ecosystemBadge, formatBytes, formatDateTime, relativeTime } from '@/utils/format'

const entries = ref([])
const total = ref(0)
const loading = ref(true)
const error = ref(null)

const filters = ref({ ecosystem: '', package_name: '', username: '', days: 7 })
const page = ref(0)
const pageSize = 100

const live = ref(false)
const liveState = ref('idle') // idle | connecting | streaming | error
const liveCount = ref(0)
let source = null

/** Rows kept while tailing. Beyond this the oldest are dropped: a busy fleet
 *  can push thousands a minute and an unbounded list would grow until the tab
 *  stops responding. */
const LIVE_BUFFER = 500

const liveLabel = computed(
  () =>
    ({
      idle: 'Live off',
      connecting: 'Connecting…',
      streaming: liveCount.value ? `Live · ${liveCount.value} new` : 'Live · waiting',
      error: 'Live disconnected',
    })[liveState.value],
)

function queryParams() {
  return {
    ecosystem: filters.value.ecosystem || undefined,
    package_name: filters.value.package_name || undefined,
    username: filters.value.username || undefined,
  }
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const data = await api.downloadLog({
      ...queryParams(),
      days: filters.value.days,
      limit: pageSize,
      offset: page.value * pageSize,
    })
    entries.value = data.entries
    total.value = data.total
  } catch (err) {
    error.value = err.detail || 'Could not load the request log.'
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  page.value = 0
  load()
  // The stream filters server-side, so it has to be reopened to match.
  if (live.value) startStream()
}

function stopStream() {
  if (source) {
    source.close()
    source = null
  }
  if (liveState.value !== 'error') liveState.value = 'idle'
}

function startStream({ resume = false } = {}) {
  stopStream()
  liveState.value = 'connecting'
  if (!resume) liveCount.value = 0
  // Resuming names the last row already shown, so nothing recorded during a
  // reconnect gap is silently missed.
  const since = resume && entries.value.length ? entries.value[0].id : undefined
  source = new EventSource(api.downloadStreamUrl({ ...queryParams(), since_id: since }))

  source.addEventListener('open', () => {
    liveState.value = 'streaming'
  })
  source.addEventListener('downloads', (event) => {
    let incoming = []
    try {
      incoming = JSON.parse(event.data)
    } catch {
      return
    }
    if (!incoming.length) return
    liveState.value = 'streaming'
    liveCount.value += incoming.length
    // Newest first, matching the paged view below.
    entries.value = [...incoming.reverse(), ...entries.value].slice(0, LIVE_BUFFER)
    total.value += incoming.length
  })
  source.addEventListener('expired', () => {
    // The server caps how long a tail may stay open. Reconnect from the last
    // row seen, rather than leaving a page that silently stopped updating or
    // one that resumes with a hole in it.
    startStream({ resume: true })
  })
  source.addEventListener('error', () => {
    // EventSource retries on its own; surface the gap rather than pretending
    // the feed is still live.
    liveState.value = 'error'
  })
}

watch(live, (on) => (on ? startStream() : stopStream()))
onMounted(load)
onBeforeUnmount(stopStream)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Package requests</h1>
      <p class="page-sub">
        Every metadata lookup and artifact download, with who asked and whether it was
        served from cache.
      </p>
    </div>
    <label class="check live-toggle" :class="liveState">
      <input v-model="live" type="checkbox" />
      <span class="live-dot" aria-hidden="true"></span>
      {{ liveLabel }}
    </label>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div class="card mb">
    <div class="card-body">
      <div class="row">
        <select v-model="filters.ecosystem" style="width: auto" @change="applyFilters">
          <option value="">All ecosystems</option>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="cargo">cargo</option>
        </select>
        <select
          v-model.number="filters.days"
          style="width: auto"
          :disabled="live"
          :title="live ? 'The window applies to the history below, not the live tail' : ''"
          @change="applyFilters"
        >
          <option :value="1">Last 24 hours</option>
          <option :value="7">Last 7 days</option>
          <option :value="30">Last 30 days</option>
          <option :value="365">Last year</option>
        </select>
        <input
          v-model="filters.package_name"
          placeholder="Package name…"
          style="flex: 1; min-width: 160px"
          @keyup.enter="applyFilters"
        />
        <input
          v-model="filters.username"
          placeholder="Username…"
          style="width: 150px"
          @keyup.enter="applyFilters"
        />
        <button class="btn" @click="applyFilters">Apply</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h3>Requests</h3>
      <span class="faint small">
        <template v-if="live">{{ entries.length }} shown · tailing</template>
        <template v-else>{{ total }} matching</template>
      </span>
    </div>
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!entries.length" class="empty">
        No requests recorded for this window.
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Package</th>
              <th>Version</th>
              <th>Type</th>
              <th>User</th>
              <th>IP</th>
              <th class="num">Size</th>
              <th class="num">Time</th>
              <th>Cache</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in entries" :key="entry.id">
              <td class="dim small nowrap" :title="formatDateTime(entry.ts)">
                {{ relativeTime(entry.ts) }}
              </td>
              <td>
                <span class="badge" :class="ecosystemBadge(entry.ecosystem)">
                  {{ entry.ecosystem }}
                </span>
                {{ entry.package_name }}
              </td>
              <td class="mono small">{{ entry.version || '—' }}</td>
              <td><span class="badge">{{ entry.kind }}</span></td>
              <td class="small">{{ entry.username || 'anonymous' }}</td>
              <td class="mono faint small">{{ entry.ip || '—' }}</td>
              <td class="num small">{{ entry.bytes_sent ? formatBytes(entry.bytes_sent) : '—' }}</td>
              <td class="num small dim">{{ entry.duration_ms != null ? entry.duration_ms + ' ms' : '—' }}</td>
              <td class="nowrap">
                <span class="badge" :class="entry.cache_hit ? 'badge-ok' : ''">
                  {{ entry.cache_hit ? 'hit' : 'miss' }}
                </span>
                <span v-if="entry.status >= 400" class="badge badge-danger">{{ entry.status }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div
      v-if="!live && total > pageSize"
      class="card-head"
      style="border-top: 1px solid var(--border); border-bottom: none"
    >
      <button class="btn btn-sm" :disabled="page === 0" @click="((page -= 1), load())">
        Previous
      </button>
      <span class="faint small">Page {{ page + 1 }} of {{ Math.ceil(total / pageSize) }}</span>
      <button
        class="btn btn-sm"
        :disabled="(page + 1) * pageSize >= total"
        @click="((page += 1), load())"
      >
        Next
      </button>
    </div>
  </div>
</template>
