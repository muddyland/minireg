<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { relativeTime } from '@/utils/format'
import { errorMessage } from '@/utils/errors'
import EcosystemBadge from '@/components/EcosystemBadge.vue'

const upstreams = ref([])
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const testing = ref(null)
// Upstream id whose enable/delete/index call is in flight.
const busy = ref(null)
const saving = ref(false)

const blank = () => ({
  name: '',
  ecosystem: 'npm',
  kind: 'npm',
  url: '',
  tier: 1,
  priority: 100,
  enabled: true,
  auth_type: 'none',
  credential: '',
  auth_header_name: '',
  timeout_seconds: 20,
  verify_ssl: true,
  name_patterns: '',
  require_digest: true,
  gitlab_project_id: '',
  gitlab_group_id: '',
  allow_publish: false,
  index_packages: false,
  web_url_template: '',
})

const showForm = ref(false)
const editing = ref(null)
const form = ref(blank())
const formError = ref(null)

const ECOSYSTEMS = ['npm', 'pypi', 'cargo']

const byEcosystem = computed(() =>
  Object.fromEntries(
    ECOSYSTEMS.map((eco) => [eco, upstreams.value.filter((u) => u.ecosystem === eco).sort(sortFn)]),
  ),
)

function sortFn(a, b) {
  return a.tier - b.tier || a.priority - b.priority
}

// GitLab hosts npm and PyPI package registries but has no cargo one, so
// cargo has a single kind. This mirrors _KINDS_FOR_ECOSYSTEM on the server,
// which is what actually rejects a mismatch.
const KINDS_BY_ECOSYSTEM = {
  npm: [
    { value: 'npm', label: 'npm registry' },
    { value: 'gitlab_npm', label: 'GitLab npm registry' },
  ],
  pypi: [
    { value: 'pypi', label: 'PyPI simple index' },
    { value: 'gitlab_pypi', label: 'GitLab PyPI registry' },
  ],
  cargo: [{ value: 'cargo', label: 'Cargo sparse index' }],
}

const kindOptions = computed(() => KINDS_BY_ECOSYSTEM[form.value.ecosystem] ?? [])

const isGitlab = computed(() => form.value.kind.startsWith('gitlab_'))

const URL_PLACEHOLDERS = {
  npm: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org/simple',
  cargo: 'https://index.crates.io',
}

const urlPlaceholder = computed(
  () => URL_PLACEHOLDERS[form.value.kind] ?? 'https://gitlab.example.com',
)

async function load() {
  loading.value = true
  try {
    upstreams.value = (await api.listUpstreams()).upstreams
  } catch (err) {
    error.value = errorMessage(err, 'Could not load upstreams.')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  formError.value = null
  editing.value = null
  form.value = blank()
  showForm.value = true
}

function openEdit(upstream) {
  formError.value = null
  editing.value = upstream
  form.value = {
    ...blank(),
    ...upstream,
    // Never round-trip the stored secret; blank means "leave unchanged".
    credential: '',
    gitlab_project_id: upstream.gitlab_project_id || '',
    gitlab_group_id: upstream.gitlab_group_id || '',
    auth_header_name: upstream.auth_header_name || '',
    web_url_template: upstream.web_url_template || '',
    name_patterns: (upstream.name_patterns || []).join(', '),
    require_digest: upstream.require_digest !== false,
  }
  showForm.value = true
}

function onEcosystemChange() {
  form.value.kind = kindOptions.value[0]?.value ?? 'npm'
}

async function save() {
  error.value = null
  formError.value = null
  const payload = { ...form.value }
  if (!payload.credential) delete payload.credential
  // The form takes a comma-separated string; the API takes a list.
  payload.name_patterns = (form.value.name_patterns || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
  for (const key of ['gitlab_project_id', 'gitlab_group_id', 'auth_header_name', 'web_url_template']) {
    if (!payload[key]) payload[key] = null
  }
  saving.value = true
  try {
    if (editing.value) {
      delete payload.ecosystem
      delete payload.kind
      await api.updateUpstream(editing.value.id, payload)
    } else {
      await api.createUpstream(payload)
    }
    showForm.value = false
    await load()
  } catch (err) {
    // Shown inside the dialog: the page alert is hidden behind the backdrop.
    formError.value = errorMessage(err, 'Could not save the upstream.')
  } finally {
    saving.value = false
  }
}

async function test(upstream) {
  testing.value = upstream.id
  error.value = null
  message.value = null
  try {
    const result = await api.testUpstream(upstream.id)
    message.value = result.healthy
      ? `${upstream.name} is reachable.`
      : `${upstream.name} failed: ${result.error}`
  } catch (err) {
    error.value = errorMessage(err, `Could not test ${upstream.name}.`)
  } finally {
    testing.value = null
  }
  // Refresh the health columns the test just updated; load() reports its own failure.
  await load()
}

async function reindex(upstream) {
  // Indexing public PyPI imports ~870k bare project names, which is a
  // legitimate thing to want but wrecks the dashboard if you did not mean it.
  const scoped = upstream.gitlab_project_id || upstream.gitlab_group_id
  const warning = scoped
    ? `Import the package list from "${upstream.name}" into the search index?`
    : `"${upstream.name}" is not scoped to a project or group, so this imports its ` +
      'ENTIRE package list — for public PyPI that is several hundred thousand names. ' +
      'They are name-only entries; metadata is still fetched on demand. Continue?'
  if (!confirm(warning)) return

  error.value = null
  message.value = null
  busy.value = upstream.id
  try {
    const result = await api.indexUpstream(upstream.id)
    message.value = `${upstream.name}: discovered ${result.discovered} packages, added ${result.added} new.`
    await load()
  } catch (err) {
    error.value = errorMessage(err, `Indexing ${upstream.name} failed.`)
  } finally {
    busy.value = null
  }
}

async function remove(upstream) {
  if (
    !confirm(
      `Delete upstream "${upstream.name}"?\n\n` +
        'Versions and cached files that only this upstream supplied are removed now, and ' +
        'installs pinned to them will fail. Locally published packages are kept.\n\n' +
        'To pause it without losing anything, disable it instead.'
    )
  )
    return
  error.value = null
  message.value = null
  busy.value = upstream.id
  try {
    await api.deleteUpstream(upstream.id)
    await load()
  } catch (err) {
    error.value = errorMessage(err, `Could not delete ${upstream.name}.`)
  } finally {
    busy.value = null
  }
}

async function toggleEnabled(upstream) {
  error.value = null
  message.value = null
  busy.value = upstream.id
  try {
    await api.updateUpstream(upstream.id, { enabled: !upstream.enabled })
    await load()
  } catch (err) {
    error.value = errorMessage(
      err,
      `Could not ${upstream.enabled ? 'disable' : 'enable'} ${upstream.name}.`,
    )
  } finally {
    busy.value = null
  }
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Upstreams</h1>
      <p class="page-sub">
        Tiers are consumed in ascending order. Every upstream in tier 1 is tried before tier 2,
        and so on until the package is found.
      </p>
    </div>
    <button class="btn btn-primary" @click="openCreate">Add upstream</button>
  </div>

  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
  <div v-if="message" class="alert alert-info" role="status">{{ message }}</div>

  <div v-if="loading" class="empty">Loading…</div>

  <template v-else>
    <div class="alert alert-info small">
      Container registries (Docker Hub, GHCR, Quay…) are configured on
      <router-link :to="{ name: 'docker-upstreams' }">Container registries</router-link>. They
      are kept separate because an image upstream's name is the image path prefix, there is no
      tier fall-through between registries, and each needs its CDN hosts listed. Container
      vulnerability rules live on <router-link :to="{ name: 'image-policy' }">Image policy</router-link>.
    </div>
    <div v-for="eco in ECOSYSTEMS" :key="eco" class="card mb">
      <div class="card-head">
        <h3>
          <EcosystemBadge :ecosystem="eco" />
          upstreams
        </h3>
        <span class="faint small">{{ byEcosystem[eco].length }} configured</span>
      </div>
      <div class="card-body tight">
        <div v-if="!byEcosystem[eco].length" class="empty">
          No {{ eco }} upstreams. Without one, only locally published packages resolve.
        </div>
        <div v-else class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tier</th>
                <th>Name</th>
                <th>URL</th>
                <th>Type</th>
                <th>Health</th>
                <th>Flags</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="upstream in byEcosystem[eco]" :key="upstream.id" :style="upstream.enabled ? '' : 'opacity:.5'">
                <td>
                  <span class="badge badge-accent">T{{ upstream.tier }}</span>
                  <span class="faint small">/{{ upstream.priority }}</span>
                </td>
                <td>
                  <strong>{{ upstream.name }}</strong>
                  <div v-if="!upstream.enabled" class="faint small">disabled</div>
                </td>
                <td class="mono small truncate" style="max-width: 260px" :title="upstream.url">
                  {{ upstream.url }}
                </td>
                <td>
                  <span class="badge">{{ upstream.kind.replace('_', ' ') }}</span>
                  <span
                    v-if="upstream.has_credential"
                    class="badge"
                    role="img"
                    title="Credential configured"
                    aria-label="Credential configured"
                  >🔒</span>
                </td>
                <td>
                  <span class="badge" :class="upstream.healthy ? 'badge-ok' : 'badge-danger'">
                    {{ upstream.healthy ? 'healthy' : 'failing' }}
                  </span>
                  <div v-if="upstream.last_error" class="faint small truncate" style="max-width: 200px" :title="upstream.last_error">
                    {{ upstream.last_error }}
                  </div>
                  <div v-else-if="upstream.last_check_at" class="faint small">
                    checked {{ relativeTime(upstream.last_check_at) }}
                  </div>
                </td>
                <td>
                  <span v-if="upstream.allow_publish" class="badge badge-warn">publish target</span>
                  <span v-if="upstream.index_packages" class="badge">indexed</span>
                </td>
                <td class="num nowrap">
                  <button class="btn btn-sm" :disabled="testing === upstream.id" @click="test(upstream)">
                    {{ testing === upstream.id ? '…' : 'Test' }}
                  </button>
                  <button
                    v-if="upstream.kind.startsWith('gitlab_') || upstream.kind === 'pypi'"
                    class="btn btn-sm"
                    title="Import this upstream's package list into the search index"
                    :disabled="busy === upstream.id"
                    @click="reindex(upstream)"
                  >
                    Index
                  </button>
                  <button class="btn btn-sm" :disabled="busy === upstream.id" @click="toggleEnabled(upstream)">
                    {{ upstream.enabled ? 'Disable' : 'Enable' }}
                  </button>
                  <button class="btn btn-sm" @click="openEdit(upstream)">Edit</button>
                  <button class="btn btn-sm btn-danger" :disabled="busy === upstream.id" @click="remove(upstream)">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>

  <div v-if="showForm" class="modal-backdrop" @click.self="showForm = false">
    <div class="modal">
      <div class="modal-head">
        <h3>{{ editing ? `Edit ${editing.name}` : 'Add upstream' }}</h3>
        <button class="btn btn-sm btn-ghost" aria-label="Close" @click="showForm = false">✕</button>
      </div>
      <div class="modal-body">
        <div class="field">
          <label for="up-name">Name</label>
          <input id="up-name" v-model="form.name" placeholder="e.g. npmjs-public" />
        </div>

        <div class="row" style="gap: 0.8rem">
          <div class="field" style="flex: 1">
            <label for="up-ecosystem">Ecosystem</label>
            <select id="up-ecosystem" v-model="form.ecosystem" :disabled="!!editing" @change="onEcosystemChange">
              <option value="npm">npm</option>
              <option value="pypi">PyPI</option>
              <option value="cargo">cargo</option>
            </select>
          </div>
          <div class="field" style="flex: 1">
            <label for="up-kind">Type</label>
            <select id="up-kind" v-model="form.kind" :disabled="!!editing">
              <option v-for="option in kindOptions" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
          </div>
        </div>

        <div class="field">
          <label for="up-url">URL</label>
          <input
            id="up-url"
            v-model="form.url"
            :placeholder="urlPlaceholder"
          />
          <p class="field-hint">
            For GitLab, the instance root — the <code>/api/v4</code> path is added automatically.
            <template v-if="form.ecosystem === 'cargo'">
              For cargo, the sparse index root, without the <code>sparse+</code>
              prefix — that is a scheme marker for the client, not part of the
              URL we fetch.
            </template>
          </p>
        </div>

        <div class="row" style="gap: 0.8rem">
          <div class="field" style="flex: 1">
            <label for="up-tier">Tier</label>
            <input id="up-tier" v-model.number="form.tier" type="number" min="1" max="100" />
            <p class="field-hint">Lower tiers are tried first.</p>
          </div>
          <div class="field" style="flex: 1">
            <label for="up-priority">Priority within tier</label>
            <input id="up-priority" v-model.number="form.priority" type="number" min="0" />
          </div>
          <div class="field" style="flex: 1">
            <label for="up-timeout">Timeout (s)</label>
            <input id="up-timeout" v-model.number="form.timeout_seconds" type="number" min="1" max="300" />
          </div>
        </div>

        <div class="field">
          <label for="up-auth">Authentication</label>
          <select id="up-auth" v-model="form.auth_type">
            <option value="none">None (public)</option>
            <option value="bearer">Bearer token</option>
            <option value="basic">Basic (user:password)</option>
            <option value="token_header">Custom header (GitLab PRIVATE-TOKEN)</option>
            <option v-if="isGitlab" value="job_token">GitLab CI job token</option>
          </select>
        </div>

        <div v-if="form.auth_type !== 'none'" class="field">
          <label for="up-credential">Credential</label>
          <input
            id="up-credential"
            v-model="form.credential"
            type="password"
            :placeholder="editing?.has_credential ? 'unchanged — type to replace' : 'token, or user:password for basic'"
          />
          <p class="field-hint">Stored encrypted; never returned by the API.</p>
        </div>

        <div v-if="form.auth_type === 'token_header'" class="field">
          <label for="up-header">Header name</label>
          <input id="up-header" v-model="form.auth_header_name" placeholder="PRIVATE-TOKEN" />
        </div>

        <template v-if="isGitlab">
          <div class="row" style="gap: 0.8rem">
            <div class="field" style="flex: 1">
              <label for="up-gitlab-project">GitLab project ID</label>
              <input id="up-gitlab-project" v-model="form.gitlab_project_id" placeholder="e.g. 42" />
              <p class="field-hint">Required to publish.</p>
            </div>
            <div class="field" style="flex: 1">
              <label for="up-gitlab-group">GitLab group ID</label>
              <input id="up-gitlab-group" v-model="form.gitlab_group_id" placeholder="optional" />
            </div>
          </div>
        </template>

        <div class="field">
          <label for="up-web-url">Package page URL (optional)</label>
          <input
            id="up-web-url"
            v-model="form.web_url_template"
            :placeholder="
              form.ecosystem === 'npm'
                ? 'https://npm.internal/package/{name}'
                : 'https://pypi.internal/project/{normalized_name}'
            "
          />
          <p class="field-hint">
            Where a person should click to read about a package on this upstream. Placeholders:
            <code>{name}</code>, <code>{normalized_name}</code>. Derived automatically for
            npmjs.com and pypi.org; otherwise the index URL is shown.
          </p>
        </div>

        <label class="check"><input v-model="form.enabled" type="checkbox" /> Enabled</label>
        <label class="check"><input v-model="form.verify_ssl" type="checkbox" /> Verify TLS certificates</label>
        <label class="check">
          <input v-model="form.require_digest" type="checkbox" />
          Require a published digest for every artifact
        </label>
        <div class="field">
          <label for="up-name-patterns">Reserved names</label>
          <input
            id="up-name-patterns"
            v-model="form.name_patterns"
            type="text"
            placeholder="@corp/*, corp-*"
          />
          <p class="field-hint">
            Comma-separated glob patterns. When set, only this upstream answers for
            matching names, so a public registry can never take over an internal
            package. Leave empty to serve anything.
          </p>
        </div>
        <label class="check">
          <input v-model="form.allow_publish" type="checkbox" />
          Mirror local publishes to this upstream
        </label>
        <label class="check">
          <input v-model="form.index_packages" type="checkbox" />
          Include this upstream's package list in search
        </label>
      </div>
      <div class="modal-foot">
        <span v-if="formError" class="alert alert-error small" role="alert" style="margin: 0; flex: 1">
          {{ formError }}
        </span>
        <button class="btn" @click="showForm = false">Cancel</button>
        <button class="btn btn-primary" :disabled="saving || !form.name || !form.url" @click="save">Save</button>
      </div>
    </div>
  </div>
</template>
