<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatDate, relativeTime } from '@/utils/format'

const auth = useAuthStore()
const tokens = ref([])
const loading = ref(true)
const error = ref(null)

const showCreate = ref(false)
const form = ref({ name: '', scopes: ['read'], expires_in_days: null })
const issued = ref(null)
const copied = ref(false)

const availableScopes = computed(() => {
  const scopes = [{ value: 'read', label: 'read', hint: 'Install and download packages' }]
  if (auth.canPublish) {
    scopes.push({ value: 'publish', label: 'publish', hint: 'Publish new package versions' })
  }
  if (auth.isAdmin) {
    scopes.push({ value: 'admin', label: 'admin', hint: 'Full administrative API access' })
  }
  return scopes
})

async function load() {
  loading.value = true
  try {
    tokens.value = (await api.listTokens()).tokens
  } catch (err) {
    error.value = err.detail || 'Could not load tokens.'
  } finally {
    loading.value = false
  }
}

function toggleScope(scope) {
  const set = new Set(form.value.scopes)
  set.has(scope) ? set.delete(scope) : set.add(scope)
  form.value.scopes = [...set]
}

async function create() {
  error.value = null
  try {
    issued.value = await api.createToken({
      name: form.value.name,
      scopes: form.value.scopes,
      expires_in_days: form.value.expires_in_days || null,
    })
    showCreate.value = false
    form.value = { name: '', scopes: ['read'], expires_in_days: null }
    await load()
  } catch (err) {
    error.value = err.detail || 'Could not create the token.'
  }
}

async function revoke(token) {
  if (!confirm(`Revoke "${token.name}"? Any client using it will stop working immediately.`)) return
  await api.revokeToken(token.id)
  await load()
}

async function copyToken() {
  await navigator.clipboard.writeText(issued.value.token)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>API tokens</h1>
      <p class="page-sub">Tokens authenticate npm, pip, and twine. They are shown once, at creation.</p>
    </div>
    <button class="btn btn-primary" @click="showCreate = true">New token</button>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div v-if="issued" class="card mb" style="border-color: var(--ok)">
    <div class="card-head">
      <h3>Token created — copy it now</h3>
      <button class="btn btn-sm btn-ghost" @click="issued = null">Dismiss</button>
    </div>
    <div class="card-body">
      <p class="small dim mb">
        This is the only time the full token is shown. Only a hash is stored on the server.
      </p>
      <div class="copy-block">
        <pre style="word-break: break-all; white-space: pre-wrap">{{ issued.token }}</pre>
        <button class="btn btn-sm" @click="copyToken">{{ copied ? 'Copied' : 'Copy' }}</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!tokens.length" class="empty">
        You have no tokens yet. Create one to configure npm or pip.
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Scopes</th>
              <th>Created</th>
              <th>Last used</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="token in tokens" :key="token.id" :style="token.revoked ? 'opacity:.5' : ''">
              <td>
                {{ token.name }}
                <span v-if="token.revoked" class="badge badge-danger">revoked</span>
              </td>
              <td class="mono faint">{{ token.prefix }}…</td>
              <td>
                <span v-for="scope in token.scopes" :key="scope" class="badge" style="margin-right: 3px">
                  {{ scope }}
                </span>
              </td>
              <td class="dim small nowrap">{{ formatDate(token.created_at) }}</td>
              <td class="dim small nowrap">
                {{ token.last_used_at ? relativeTime(token.last_used_at) : 'never' }}
              </td>
              <td class="dim small nowrap">
                {{ token.expires_at ? formatDate(token.expires_at) : 'never' }}
              </td>
              <td class="num">
                <button v-if="!token.revoked" class="btn btn-sm btn-danger" @click="revoke(token)">
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
    <div class="modal">
      <div class="modal-head">
        <h3>New API token</h3>
        <button class="btn btn-sm btn-ghost" @click="showCreate = false">✕</button>
      </div>
      <div class="modal-body">
        <div class="field">
          <label for="tname">Name</label>
          <input id="tname" v-model="form.name" placeholder="e.g. ci-pipeline" />
          <p class="field-hint">A label so you can recognise this token later.</p>
        </div>

        <div class="field">
          <label>Scopes</label>
          <label v-for="scope in availableScopes" :key="scope.value" class="check" style="margin-bottom: 0.3rem">
            <input
              type="checkbox"
              :checked="form.scopes.includes(scope.value)"
              @change="toggleScope(scope.value)"
            />
            <span><strong>{{ scope.label }}</strong> <span class="faint small">— {{ scope.hint }}</span></span>
          </label>
        </div>

        <div class="field">
          <label for="texp">Expires after (days)</label>
          <input id="texp" v-model.number="form.expires_in_days" type="number" min="1" placeholder="never" />
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn" @click="showCreate = false">Cancel</button>
        <button class="btn btn-primary" :disabled="!form.name || !form.scopes.length" @click="create">
          Create token
        </button>
      </div>
    </div>
  </div>
</template>
