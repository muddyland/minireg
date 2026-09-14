<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'
import { formatDateTime } from '@/utils/format'

const entries = ref([])
const total = ref(0)
const actions = ref([])
const loading = ref(true)
const error = ref(null)
const expanded = ref(null)

const filters = ref({ action: '', username: '', success: '', days: 90 })
const page = ref(0)
const pageSize = 100

async function loadAudit() {
  loading.value = true
  try {
    const data = await api.auditLog({
      action: filters.value.action || undefined,
      username: filters.value.username || undefined,
      success: filters.value.success === '' ? undefined : filters.value.success === 'true',
      days: filters.value.days,
      limit: pageSize,
      offset: page.value * pageSize,
    })
    entries.value = data.entries
    total.value = data.total
  } catch (err) {
    error.value = err.detail || 'Could not load the audit log.'
  } finally {
    loading.value = false
  }
}

function actionClass(action) {
  if (action.startsWith('auth.login.failed') || action.includes('denied')) return 'badge-danger'
  if (action.startsWith('admin.')) return 'badge-accent'
  if (action.startsWith('registry.publish')) return 'badge-ok'
  return ''
}

onMounted(async () => {
  await loadAudit()
  actions.value = (await api.auditActions()).actions
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Audit log</h1>
      <p class="page-sub">
        Every sign-in and administrative action. Package requests have their own
        <router-link :to="{ name: 'downloads' }">log</router-link>.
      </p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div class="card mb">
    <div class="card-body">
      <div class="row">
        <select v-model="filters.action" style="width: auto" @change="((page = 0), loadAudit())">
          <option value="">All actions</option>
          <option v-for="item in actions" :key="item.action" :value="item.action">
            {{ item.action }} ({{ item.count }})
          </option>
        </select>
        <select v-model="filters.success" style="width: auto" @change="loadAudit">
          <option value="">Any outcome</option>
          <option value="true">Successful</option>
          <option value="false">Failed</option>
        </select>
        <select v-model.number="filters.days" style="width: auto" @change="loadAudit">
          <option :value="1">Last 24 hours</option>
          <option :value="7">Last 7 days</option>
          <option :value="30">Last 30 days</option>
          <option :value="90">Last 90 days</option>
          <option :value="730">Last 2 years</option>
        </select>
        <input
          v-model="filters.username"
          placeholder="Filter by username…"
          style="flex: 1; min-width: 160px"
          @keyup.enter="loadAudit"
        />
        <button class="btn" @click="loadAudit">Apply</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h3>Entries</h3>
      <span class="faint small">{{ total }} matching</span>
    </div>
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!entries.length" class="empty">No audit entries match these filters.</div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th><th>Action</th><th>Actor</th><th>Target</th><th>IP</th><th></th>
            </tr>
          </thead>
          <tbody>
            <template v-for="entry in entries" :key="entry.id">
              <tr>
                <td class="dim small nowrap">{{ formatDateTime(entry.ts) }}</td>
                <td>
                  <span class="badge" :class="actionClass(entry.action)">{{ entry.action }}</span>
                  <span v-if="!entry.success" class="badge badge-danger">failed</span>
                </td>
                <td>
                  {{ entry.actor_username || '—' }}
                  <div class="faint small">{{ entry.actor_type }}</div>
                </td>
                <td class="small mono truncate" style="max-width: 240px">
                  {{ entry.target_id || '—' }}
                </td>
                <td class="mono faint small">{{ entry.ip || '—' }}</td>
                <td class="num">
                  <button
                    v-if="entry.detail && Object.keys(entry.detail).length"
                    class="btn btn-sm btn-ghost"
                    @click="expanded = expanded === entry.id ? null : entry.id"
                  >
                    {{ expanded === entry.id ? '▴' : '▾' }}
                  </button>
                </td>
              </tr>
              <tr v-if="expanded === entry.id">
                <td colspan="6" style="background: var(--surface-2)">
                  <pre>{{ JSON.stringify(entry.detail, null, 2) }}</pre>
                  <p v-if="entry.user_agent" class="faint small" style="margin: 0.4rem 0 0">
                    User agent: {{ entry.user_agent }}
                  </p>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
    <div v-if="total > pageSize" class="card-head" style="border-top: 1px solid var(--border); border-bottom: none">
      <button class="btn btn-sm" :disabled="page === 0" @click="((page -= 1), loadAudit())">Previous</button>
      <span class="faint small">Page {{ page + 1 }} of {{ Math.ceil(total / pageSize) }}</span>
      <button
        class="btn btn-sm"
        :disabled="(page + 1) * pageSize >= total"
        @click="((page += 1), loadAudit())"
      >
        Next
      </button>
    </div>
  </div>
</template>
