<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const query = ref('')
const ecosystem = ref('')
const includeUpstream = ref(false)
const results = ref([])
const total = ref(0)
const loading = ref(false)
const error = ref(null)
const searched = ref(false)

async function run() {
  loading.value = true
  error.value = null
  try {
    const data = await api.search({
      q: query.value,
      ecosystem: ecosystem.value || undefined,
      include_upstream: includeUpstream.value || undefined,
      limit: 50,
    })
    results.value = data.results
    total.value = data.total
    searched.value = true
  } catch (err) {
    error.value = err.detail || 'Search failed.'
  } finally {
    loading.value = false
  }
}

onMounted(run)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Search packages</h1>
      <p class="page-sub">Everything this registry has indexed, across npm and PyPI.</p>
    </div>
  </div>

  <div class="card mb">
    <div class="card-body">
      <form class="row" @submit.prevent="run">
        <input
          v-model="query"
          type="search"
          placeholder="Package name or description…"
          style="flex: 1; min-width: 220px"
        />
        <select v-model="ecosystem" style="width: auto">
          <option value="">All ecosystems</option>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
        </select>
        <button class="btn btn-primary" type="submit" :disabled="loading">Search</button>
      </form>
      <label class="check small dim" style="margin-top: 0.65rem">
        <input v-model="includeUpstream" type="checkbox" @change="run" />
        Also search configured upstreams (slower; requires an ecosystem filter)
      </label>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div v-if="loading" class="empty">Searching…</div>
  <div v-else-if="!results.length && searched" class="empty">
    No packages matched. Packages appear here once they have been requested or published.
  </div>

  <div v-else class="grid grid-2">
    <div v-for="pkg in results" :key="`${pkg.ecosystem}:${pkg.normalized_name}`" class="card">
      <div class="card-body">
        <div class="row" style="justify-content: space-between; align-items: flex-start">
          <div style="min-width: 0">
            <router-link
              :to="{ name: 'package', params: { ecosystem: pkg.ecosystem, name: pkg.name } }"
              style="font-weight: 600; font-size: 0.98rem"
            >
              {{ pkg.name }}
            </router-link>
            <div class="row-tight" style="margin-top: 0.3rem">
              <span class="badge" :class="pkg.ecosystem === 'npm' ? 'badge-npm' : 'badge-pypi'">
                {{ pkg.ecosystem }}
              </span>
              <span v-if="pkg.latest_version" class="badge">{{ pkg.latest_version }}</span>
              <span v-if="pkg.is_local" class="badge badge-accent">local</span>
              <span v-if="pkg.source === 'upstream'" class="badge">upstream</span>
              <span v-if="pkg.blocked" class="badge badge-danger" :title="pkg.block_reason">blocked</span>
            </div>
          </div>
          <span class="faint small nowrap">{{ pkg.download_count }} ⇩</span>
        </div>

        <p v-if="pkg.description" class="dim small" style="margin: 0.55rem 0 0">
          {{ pkg.description.slice(0, 180) }}{{ pkg.description.length > 180 ? '…' : '' }}
        </p>

        <div v-if="pkg.blocked && auth.isAdmin" class="alert alert-warn small" style="margin: 0.6rem 0 0">
          Blocked: {{ pkg.block_reason }}
        </div>
      </div>
    </div>
  </div>

  <p v-if="results.length" class="faint small mt">
    Showing {{ results.length }} of {{ total }} indexed packages.
  </p>
</template>
