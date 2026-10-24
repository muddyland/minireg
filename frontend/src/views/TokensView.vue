<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api/client'
import CodeBlock from '@/components/CodeBlock.vue'
import { useAuthStore } from '@/stores/auth'
import { errorMessage } from '@/utils/errors'
import { formatDate, relativeTime } from '@/utils/format'

const auth = useAuthStore()
const route = useRoute()
const tokens = ref([])
const loading = ref(true)
const error = ref(null)

const showCreate = ref(false)
const formError = ref(null)
const creating = ref(false)
const blankForm = () => ({ name: '', scopes: ['read'], expires_in_days: null, prefixes: '' })
const form = ref(blankForm())
const issued = ref(null)
const copied = ref(false)

// Scopes that must stand alone: a scanner token reads every image, held ones
// included, so it should carry nothing else and live only in the worker.
const EXCLUSIVE = new Set(['scanner'])

const availableScopes = computed(() => {
  const scopes = [{ value: 'read', label: 'read', hint: 'Install packages and pull images' }]
  if (auth.canPublish) {
    scopes.push({ value: 'publish', label: 'publish', hint: 'Publish new package versions' })
    scopes.push({ value: 'docker:push', label: 'docker:push', hint: 'Push container images under local/' })
  }
  if (auth.isAdmin) {
    scopes.push({ value: 'admin', label: 'admin', hint: 'Full administrative API access' })
    scopes.push({
      value: 'scanner',
      label: 'scanner',
      hint: 'For the Trivy scanner worker only. Reads every image, including held ones, and reports results',
    })
  }
  return scopes
})

const wantsPush = computed(() => form.value.scopes.includes('docker:push'))
const isScanner = computed(() => form.value.scopes.includes('scanner'))

// Preset for the scanner worker, reached from the Image policy page.
function scannerPreset() {
  form.value = { ...blankForm(), name: 'scanner', scopes: ['scanner'] }
  openCreate()
}

function openCreate() {
  formError.value = null
  showCreate.value = true
}

async function load() {
  loading.value = true
  try {
    tokens.value = (await api.listTokens()).tokens
  } catch (err) {
    error.value = errorMessage(err, 'Could not load tokens.')
  } finally {
    loading.value = false
  }
}

function toggleScope(scope) {
  if (EXCLUSIVE.has(scope)) {
    form.value.scopes = form.value.scopes.includes(scope) ? ['read'] : [scope]
    return
  }
  const set = new Set(form.value.scopes.filter((s) => !EXCLUSIVE.has(s)))
  set.has(scope) ? set.delete(scope) : set.add(scope)
  form.value.scopes = [...set]
}

async function create() {
  formError.value = null
  creating.value = true
  try {
    const prefixes = wantsPush.value
      ? form.value.prefixes.split(/[\s,]+/).map((p) => p.trim()).filter(Boolean)
      : []
    const created = await api.createToken({
      name: form.value.name,
      scopes: form.value.scopes,
      expires_in_days: form.value.expires_in_days || null,
      docker_repo_prefixes: prefixes,
    })
    issued.value = { ...created, scanner: isScanner.value }
    showCreate.value = false
    form.value = blankForm()
  } catch (err) {
    formError.value = errorMessage(err, 'Could not create the token.')
    return
  } finally {
    creating.value = false
  }
  await load()
}

async function revoke(token) {
  if (!confirm(`Revoke "${token.name}"? Any client using it will stop working immediately.`)) return
  error.value = null
  try {
    await api.revokeToken(token.id)
  } catch (err) {
    error.value = errorMessage(err, `Could not revoke "${token.name}".`)
    return
  }
  await load()
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(issued.value.token)
  } catch {
    error.value = 'Could not copy to the clipboard. Select the token and copy it by hand.'
    return
  }
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}

onMounted(() => {
  load()
  if (route.query.preset === 'scanner' && auth.isAdmin) scannerPreset()
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>API tokens</h1>
      <p class="page-sub">
        Tokens authenticate npm, pip, twine and <code>docker login</code>. They are shown once, at creation.
      </p>
    </div>
    <div class="head-actions">
      <button v-if="auth.isAdmin" class="btn" @click="scannerPreset">Scanner token</button>
      <button class="btn btn-primary" @click="openCreate">New token</button>
    </div>
  </div>

  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>

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
      <template v-if="issued.scanner">
        <p class="small dim" style="margin: 1rem 0 0.5rem">
          Put it in the <code>.env</code> next to <code>docker-compose.yml</code> and start the worker:
        </p>
        <CodeBlock
          caption="shell"
          :code="'# in .env\nMINIREG_SCANNER_TOKEN=<the token above>\n\ndocker compose --profile scanner up -d'"
        />
        <p class="small dim" style="margin: 0.5rem 0 0">
          It shows as checked in on
          <router-link :to="{ name: 'image-policy' }">Image policy</router-link> within a few seconds.
        </p>
      </template>
    </div>
  </div>

  <div class="card">
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else-if="!tokens.length" class="empty">
        You have no tokens yet. Installs and pulls normally need none; create one to publish
        packages, push images, use the CLI, or install from CI when anonymous reads are turned off.
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
                <div v-if="token.docker_repo_prefixes?.length" class="faint small">
                  push: {{ token.docker_repo_prefixes.join(', ') }}
                </div>
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

  <div
    v-if="showCreate"
    class="modal-backdrop"
    @click.self="showCreate = false"
    @keydown.esc="showCreate = false"
  >
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="new-token-title">
      <div class="modal-head">
        <h3 id="new-token-title">New API token</h3>
        <button class="btn btn-sm btn-ghost" aria-label="Close" @click="showCreate = false">✕</button>
      </div>
      <div class="modal-body">
        <div v-if="formError" class="alert alert-error" role="alert">{{ formError }}</div>
        <div class="field">
          <label for="tname">Name</label>
          <input id="tname" v-model="form.name" placeholder="e.g. ci-pipeline" />
          <p class="field-hint">A label so you can recognise this token later.</p>
        </div>

        <div class="field" role="group" aria-labelledby="tscopes">
          <label id="tscopes">Scopes</label>
          <label v-for="scope in availableScopes" :key="scope.value" class="check" style="margin-bottom: 0.3rem">
            <input
              type="checkbox"
              :checked="form.scopes.includes(scope.value)"
              @change="toggleScope(scope.value)"
            />
            <span><strong>{{ scope.label }}</strong> <span class="faint small">— {{ scope.hint }}</span></span>
          </label>
          <p v-if="isScanner" class="field-hint">
            A scanner token carries no other scope. Give it to the worker and nothing else.
          </p>
        </div>

        <div v-if="wantsPush" class="field">
          <label for="tprefix">Push only to (optional)</label>
          <input id="tprefix" v-model="form.prefixes" placeholder="local/team-a/, local/ci/" />
          <p class="field-hint">
            Repository prefixes under <code>local/</code>, comma-separated. Empty means anywhere you may push.
          </p>
        </div>

        <div class="field">
          <label for="texp">Expires after (days)</label>
          <input id="texp" v-model.number="form.expires_in_days" type="number" min="1" placeholder="never" />
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn" @click="showCreate = false">Cancel</button>
        <button
          class="btn btn-primary"
          :disabled="creating || !form.name || !form.scopes.length"
          @click="create"
        >
          {{ creating ? 'Creating…' : 'Create token' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.head-actions { display: flex; gap: 0.5rem; }
</style>
