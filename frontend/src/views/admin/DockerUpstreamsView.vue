<script setup>
/**
 * Container registries this one pulls through.
 *
 * Separate from the package Upstreams page because the model is different:
 * a Docker upstream's name is not a label but the first path segment of
 * every image it serves (`ghcr/aquasecurity/trivy`), there is no tier
 * fall-through between registries, and each one needs its CDN hosts listed,
 * because layer downloads are redirected off the registry and minireg
 * follows redirects only to hosts it has been told about.
 */
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { relativeTime } from '@/utils/format'

const upstreams = ref([])
const presets = ref([])
const config = ref(null)
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const testing = ref(null)

const showForm = ref(false)
const editing = ref(null)
const form = ref(blank())

// Preset dialog: Docker Hub wants a credential, the rest usually do not.
const presetDialog = ref(null)
const presetCredential = ref('')

const KINDS = [
  { value: 'oci', label: 'OCI / Docker registry' },
  { value: 'gitlab_oci', label: 'GitLab container registry' },
]

function blank() {
  return {
    name: '',
    kind: 'oci',
    url: '',
    registry_url: '',
    enabled: true,
    auth_type: 'none',
    credential: '',
    timeout_seconds: 30,
    verify_ssl: true,
    blob_hosts: '',
    auth_hosts: '',
    default: false,
    library_prefix: false,
  }
}

const docker = computed(() =>
  upstreams.value
    .filter((u) => u.ecosystem === 'docker')
    .sort((a, b) => Number(b.extra?.default || 0) - Number(a.extra?.default || 0) || a.name.localeCompare(b.name)),
)
const defaultName = computed(() => docker.value.find((u) => u.extra?.default)?.name || docker.value.find((u) => u.name === 'dockerhub')?.name)
const host = computed(() => config.value?.host || location.host)
const isPreset = computed(() => !!editing.value?.extra?.preset)
const unconfiguredPresets = computed(() => presets.value.filter((p) => !p.configured))

async function load() {
  loading.value = true
  error.value = null
  try {
    const [u, p] = await Promise.all([api.listUpstreams(), api.dockerPresets()])
    upstreams.value = u.upstreams
    presets.value = p.presets
  } catch (err) {
    error.value = err.detail || 'Could not load container upstreams.'
  } finally {
    loading.value = false
  }
  try {
    config.value = await api.dockerClientConfig()
  } catch {
    config.value = null
  }
}

const hostList = (text) =>
  (text || '')
    .split(/[\s,]+/)
    .map((h) => h.trim())
    .filter(Boolean)

function openCreate() {
  editing.value = null
  form.value = blank()
  showForm.value = true
}

function openEdit(upstream) {
  editing.value = upstream
  const extra = upstream.extra || {}
  form.value = {
    ...blank(),
    name: upstream.name,
    kind: upstream.kind,
    url: upstream.url,
    registry_url: extra.registry_url || '',
    enabled: upstream.enabled,
    auth_type: upstream.auth_type || 'none',
    credential: '',
    timeout_seconds: upstream.timeout_seconds,
    verify_ssl: upstream.verify_ssl,
    blob_hosts: (extra.blob_hosts || []).join('\n'),
    auth_hosts: (extra.auth_hosts || []).join('\n'),
    default: !!extra.default,
    library_prefix: !!extra.library_prefix,
  }
  showForm.value = true
}

async function save() {
  error.value = null
  const f = form.value
  const extra = {
    blob_hosts: hostList(f.blob_hosts),
    auth_hosts: hostList(f.auth_hosts),
    default: f.default,
    library_prefix: f.library_prefix,
  }
  if (f.kind === 'gitlab_oci') extra.registry_url = f.registry_url.trim()
  const payload = {
    url: f.url.trim(),
    enabled: f.enabled,
    auth_type: f.auth_type,
    timeout_seconds: f.timeout_seconds,
    verify_ssl: f.verify_ssl,
    extra,
  }
  if (f.credential) payload.credential = f.credential
  if (f.auth_type === 'none' && editing.value?.has_credential) payload.credential = ''
  try {
    if (editing.value) {
      await api.updateUpstream(editing.value.id, payload)
      message.value = `${f.name} updated.`
    } else {
      await api.createUpstream({ ...payload, name: f.name.trim(), ecosystem: 'docker', kind: f.kind, require_digest: true })
      message.value = `${f.name} added. Pull with ${host.value}/${f.name.trim()}/<image>:<tag>.`
    }
    showForm.value = false
    await load()
  } catch (err) {
    error.value = err.detail || 'Could not save the upstream.'
  }
}

function openPreset(preset) {
  presetDialog.value = preset
  presetCredential.value = ''
}

async function addPreset() {
  const preset = presetDialog.value
  try {
    await api.dockerAddPreset(preset.name, { credential: presetCredential.value || null })
    message.value = `${preset.label} added. Pull with ${host.value}/${preset.name === 'dockerhub' ? '' : preset.name + '/'}<image>:<tag>.`
    presetDialog.value = null
    presetCredential.value = ''
    await load()
  } catch (err) {
    error.value = err.detail || 'Could not add the preset.'
  }
}

async function test(upstream) {
  testing.value = upstream.id
  message.value = null
  try {
    const result = await api.testUpstream(upstream.id)
    message.value = result.healthy ? `${upstream.name} is reachable.` : `${upstream.name} failed: ${result.error}`
  } finally {
    testing.value = null
    await load()
  }
}

async function toggleEnabled(upstream) {
  await api.updateUpstream(upstream.id, { enabled: !upstream.enabled })
  message.value = upstream.enabled
    ? `${upstream.name} disabled. Pulls under ${upstream.name}/ are refused; cached images stay on disk.`
    : `${upstream.name} enabled.`
  await load()
}

async function makeDefault(upstream) {
  try {
    await api.updateUpstream(upstream.id, { extra: { default: true } })
    message.value = `Names without an upstream prefix now resolve to ${upstream.name}.`
    await load()
  } catch (err) {
    error.value = err.detail || 'Could not change the default.'
  }
}

async function remove(upstream) {
  if (!confirm(`Delete upstream "${upstream.name}"?`)) return
  try {
    await api.deleteUpstream(upstream.id)
  } catch (err) {
    if (err.status !== 409) {
      error.value = err.detail || 'Could not delete.'
      return
    }
    const again = confirm(
      `${err.detail}\n\nDelete "${upstream.name}" AND its cached images? Disabling keeps them.`,
    )
    if (!again) return
    await api.deleteUpstream(upstream.id, { purge: true })
  }
  message.value = `${upstream.name} deleted.`
  await load()
}

function pullExample(upstream) {
  if (upstream.name === defaultName.value) return `${host.value}/<image>:<tag>`
  return `${host.value}/${upstream.name}/<image>:<tag>`
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Container upstreams</h1>
      <p class="page-sub">
        Registries images are pulled through. The upstream's name is the image path prefix:
        <code>{{ host }}/ghcr/aquasecurity/trivy</code> comes from the <code>ghcr</code> upstream.
        Names without a known prefix go to the default upstream, normally Docker Hub.
      </p>
    </div>
    <div class="row-tight">
      <router-link class="btn" :to="{ name: 'image-policy' }">Image policy</router-link>
      <button class="btn btn-primary" @click="openCreate">Add registry</button>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-info">{{ message }}</div>

  <div v-if="unconfiguredPresets.length" class="card mb">
    <div class="card-head"><h3>Well-known registries</h3></div>
    <div class="card-body">
      <div class="preset-row">
        <button v-for="preset in unconfiguredPresets" :key="preset.name" class="btn btn-sm" :title="preset.url" @click="openPreset(preset)">
          + {{ preset.label }}
        </button>
      </div>
      <p class="field-hint" style="margin-bottom: 0">
        Presets come with the CDN hosts each registry redirects layer downloads to, checked against
        the live registries, and a reserved name no other upstream can take.
      </p>
    </div>
  </div>

  <div v-if="loading" class="empty">Loading…</div>

  <div v-else class="card">
    <div class="card-head">
      <h3>Configured</h3>
      <span class="faint small">{{ docker.length }}</span>
    </div>
    <div class="card-body tight">
      <div v-if="!docker.length" class="empty">
        No container upstreams yet. Add Docker Hub above to start pulling through this registry.
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Registry</th>
              <th>Pull as</th>
              <th>Health</th>
              <th>Rate limit</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="upstream in docker" :key="upstream.id" :style="upstream.enabled ? '' : 'opacity:.55'">
              <td>
                <strong class="mono">{{ upstream.name }}</strong>
                <div class="row-tight" style="margin-top: 0.2rem">
                  <span v-if="upstream.name === defaultName" class="badge badge-accent" title="Answers names with no upstream prefix">default</span>
                  <span v-if="upstream.extra?.preset" class="badge">preset</span>
                  <span v-if="upstream.kind === 'gitlab_oci'" class="badge">GitLab</span>
                  <span v-if="upstream.has_credential" class="badge" title="Credential configured">🔒 authenticated</span>
                  <span v-if="!upstream.enabled" class="badge badge-warn">disabled</span>
                </div>
              </td>
              <td class="mono small truncate" style="max-width: 240px" :title="upstream.extra?.registry_url || upstream.url">
                {{ upstream.extra?.registry_url || upstream.url }}
                <div class="faint small" :title="(upstream.extra?.blob_hosts || []).join(', ')">
                  {{ (upstream.extra?.blob_hosts || []).length }} CDN host{{ (upstream.extra?.blob_hosts || []).length === 1 ? '' : 's' }}
                </div>
              </td>
              <td class="mono small">{{ pullExample(upstream) }}</td>
              <td>
                <span class="badge" :class="upstream.healthy ? 'badge-ok' : 'badge-danger'">
                  {{ upstream.healthy ? 'healthy' : 'failing' }}
                </span>
                <div v-if="upstream.last_error" class="faint small truncate" style="max-width: 200px" :title="upstream.last_error">
                  {{ upstream.last_error }}
                </div>
                <div v-else-if="upstream.last_check_at" class="faint small">checked {{ relativeTime(upstream.last_check_at) }}</div>
              </td>
              <td class="small nowrap">
                <template v-if="upstream.ratelimit">
                  <span
                    class="sev"
                    :class="upstream.ratelimit.limit && upstream.ratelimit.remaining / upstream.ratelimit.limit < 0.2 ? 'sev-high' : 'sev-low'"
                  >
                    {{ upstream.ratelimit.remaining ?? '?' }} / {{ upstream.ratelimit.limit ?? '?' }}
                  </span>
                  <div class="faint small">{{ relativeTime(upstream.ratelimit.observed_at) }}</div>
                </template>
                <span v-else class="faint">—</span>
              </td>
              <td class="num nowrap">
                <button class="btn btn-sm" :disabled="testing === upstream.id" @click="test(upstream)">
                  {{ testing === upstream.id ? '…' : 'Test' }}
                </button>
                <button v-if="upstream.name !== defaultName && upstream.enabled" class="btn btn-sm" title="Answer names with no upstream prefix" @click="makeDefault(upstream)">
                  Make default
                </button>
                <button class="btn btn-sm" @click="toggleEnabled(upstream)">{{ upstream.enabled ? 'Disable' : 'Enable' }}</button>
                <button class="btn btn-sm" @click="openEdit(upstream)">Edit</button>
                <button class="btn btn-sm btn-danger" @click="remove(upstream)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div v-if="presetDialog" class="modal-backdrop" @click.self="presetDialog = null">
    <div class="modal" style="max-width: 560px">
      <div class="modal-head">
        <h3>Add {{ presetDialog.label }}</h3>
        <button class="btn btn-sm btn-ghost" @click="presetDialog = null">✕</button>
      </div>
      <div class="modal-body">
        <p class="small">
          Pulled as <code>{{ host }}/{{ presetDialog.name === 'dockerhub' ? '' : presetDialog.name + '/' }}&lt;image&gt;:&lt;tag&gt;</code>
          from <code>{{ presetDialog.url }}</code>.
        </p>
        <p v-if="presetDialog.note" class="field-hint">{{ presetDialog.note }}</p>
        <div class="field">
          <label for="preset-cred">Credential <span class="faint">(optional)</span></label>
          <input id="preset-cred" v-model="presetCredential" type="password" autocomplete="off" placeholder="username:access-token" />
          <p class="field-hint">
            <template v-if="presetDialog.name === 'dockerhub'">
              Strongly recommended: anonymous Docker Hub pulls are limited per IP address. Use a
              dedicated account with a read-only personal access token.
            </template>
            <template v-else>Only needed for private images.</template>
            Stored encrypted, sent only to the registry and its token service, never to CDN hosts.
          </p>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn" @click="presetDialog = null">Cancel</button>
        <button class="btn btn-primary" @click="addPreset">Add</button>
      </div>
    </div>
  </div>

  <div v-if="showForm" class="modal-backdrop" @click.self="showForm = false">
    <div class="modal" style="max-width: 640px">
      <div class="modal-head">
        <h3>{{ editing ? `Edit ${editing.name}` : 'Add a container registry' }}</h3>
        <button class="btn btn-sm btn-ghost" @click="showForm = false">✕</button>
      </div>
      <div class="modal-body">
        <div class="row" style="gap: 0.8rem">
          <div class="field" style="flex: 1">
            <label for="up-name">Name (image path prefix)</label>
            <input id="up-name" v-model="form.name" :disabled="!!editing" placeholder="harbor" />
            <p class="field-hint">
              Lowercase letters, digits and dashes. Images are pulled as
              <code>{{ host }}/{{ form.name || 'name' }}/&lt;image&gt;</code>. Cannot be changed later.
            </p>
          </div>
          <div class="field" style="flex: 1">
            <label for="up-kind">Type</label>
            <select id="up-kind" v-model="form.kind" :disabled="!!editing">
              <option v-for="k in KINDS" :key="k.value" :value="k.value">{{ k.label }}</option>
            </select>
          </div>
        </div>

        <div class="field">
          <label for="up-url">{{ form.kind === 'gitlab_oci' ? 'GitLab instance URL' : 'Registry URL' }}</label>
          <input id="up-url" v-model="form.url" :disabled="isPreset" :placeholder="form.kind === 'gitlab_oci' ? 'https://gitlab.example.com' : 'https://harbor.example.com'" />
          <p v-if="isPreset" class="field-hint">Preset registries keep their URL.</p>
        </div>
        <div v-if="form.kind === 'gitlab_oci'" class="field">
          <label for="up-reg">Container registry URL</label>
          <input id="up-reg" v-model="form.registry_url" placeholder="https://registry.gitlab.example.com" />
          <p class="field-hint">GitLab serves images from its own hostname; the token service stays on the instance.</p>
        </div>

        <div class="row" style="gap: 0.8rem">
          <div class="field" style="flex: 1">
            <label for="up-auth">Authentication</label>
            <select id="up-auth" v-model="form.auth_type">
              <option value="none">None (public images)</option>
              <option value="basic">Username and password / token</option>
              <option value="bearer">Token only</option>
            </select>
          </div>
          <div class="field" style="flex: 1">
            <label for="up-timeout">Timeout (s)</label>
            <input id="up-timeout" v-model.number="form.timeout_seconds" type="number" min="1" max="300" />
          </div>
        </div>
        <div v-if="form.auth_type !== 'none'" class="field">
          <label for="up-cred">Credential</label>
          <input
            id="up-cred"
            v-model="form.credential"
            type="password"
            autocomplete="off"
            :placeholder="editing?.has_credential ? 'unchanged — type to replace' : form.auth_type === 'basic' ? 'username:token' : 'token'"
          />
          <p class="field-hint">
            Stored encrypted and never returned. Sent to the registry and its token service only,
            never to the CDN hosts below.
          </p>
        </div>

        <div class="field">
          <label for="up-blob">CDN hosts layer downloads may redirect to</label>
          <textarea id="up-blob" v-model="form.blob_hosts" rows="3" placeholder="cdn.example.com&#10;*.s3.amazonaws.com" />
          <p class="field-hint">
            One per line; <code>*.</code> wildcards allowed. Most registries hand layer downloads to object
            storage. A redirect anywhere not listed is refused, which is what stops a hostile or
            compromised registry pointing minireg at an internal address. Check the registry's
            redirect target with <code>curl -sI</code> on a blob URL if unsure.
          </p>
        </div>
        <details class="mb">
          <summary class="small dim">Advanced</summary>
          <div class="field mt">
            <label for="up-authhosts">Extra token service hosts</label>
            <textarea id="up-authhosts" v-model="form.auth_hosts" rows="2" placeholder="auth.example.com" />
            <p class="field-hint">Only if the registry's token realm is on another host than the registry.</p>
          </div>
          <label class="check">
            <input v-model="form.library_prefix" type="checkbox" />
            Expand one-segment names with <code>library/</code> (Docker Hub-style)
          </label>
          <label class="check"><input v-model="form.verify_ssl" type="checkbox" /> Verify TLS certificates</label>
        </details>

        <label class="check">
          <input v-model="form.default" type="checkbox" />
          Default: answer image names with no upstream prefix
        </label>
        <p class="field-hint">Normally Docker Hub. Only one upstream can be the default.</p>
        <label class="check"><input v-model="form.enabled" type="checkbox" /> Enabled</label>
      </div>
      <div class="modal-foot">
        <button class="btn" @click="showForm = false">Cancel</button>
        <button
          class="btn btn-primary"
          :disabled="!form.name || !form.url || (form.kind === 'gitlab_oci' && !form.registry_url)"
          @click="save"
        >
          Save
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.preset-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}
textarea {
  width: 100%;
  font-family: var(--mono);
}
</style>
