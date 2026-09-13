<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import api from '@/api/client'
import { ecosystemBadge, formatDate } from '@/utils/format'

const rules = ref([])
const settings = ref(null)
const loading = ref(true)
const error = ref(null)
const message = ref(null)

const showRule = ref(false)
const ruleForm = ref({ ecosystem: '', pattern: '', action: 'block', version_spec: '', reason: '' })

const tester = ref({ ecosystem: 'npm', name: '', version: '', result: null })

// Live range preview, resolved by the backend so it can never disagree with
// the engine that actually enforces the rule.
const specPreview = ref(null)
const specError = ref(null)
const specProbe = ref('')
const specProbeResult = ref(null)
let specTimer = null

const specPlaceholder = computed(() =>
  ruleForm.value.ecosystem === 'pypi' ? 'e.g. <2.0 or >=1.0,<2.0' : 'e.g. <4.17.21 or ^1.2.3',
)

async function refreshSpecPreview() {
  const spec = ruleForm.value.version_spec?.trim()
  if (!spec) {
    specPreview.value = null
    specError.value = null
    specProbeResult.value = null
    return
  }
  try {
    const result = await api.previewSpec({
      ecosystem: ruleForm.value.ecosystem || null,
      version_spec: spec,
      probe_version: specProbe.value.trim() || null,
    })
    specPreview.value = result.valid ? result.expanded : null
    specError.value = result.valid ? null : result.error
    specProbeResult.value = result.matches
  } catch {
    specPreview.value = null
    specError.value = null
  }
}

// Debounced so typing a range does not fire a request per keystroke.
watch(
  () => [ruleForm.value.version_spec, ruleForm.value.ecosystem, specProbe.value],
  () => {
    clearTimeout(specTimer)
    specTimer = setTimeout(refreshSpecPreview, 250)
  },
)
const cve = ref({
  enabled: false,
  min_score: 7,
  max_score: 10,
  block_unscored: false,
  require_fix_available: false,
})
const allowlistMode = ref(false)

const blockRules = computed(() => rules.value.filter((r) => r.action === 'block'))
const allowRules = computed(() => rules.value.filter((r) => r.action === 'allow'))

async function load() {
  loading.value = true
  try {
    const [r, s] = await Promise.all([api.listRules(), api.getSettings()])
    rules.value = r.rules
    settings.value = s
    cve.value = { ...s.cve_policy }
    allowlistMode.value = s.allowlist_mode
  } catch (err) {
    error.value = err.detail || 'Could not load policy.'
  } finally {
    loading.value = false
  }
}

const saveError = ref(null)

async function saveRule() {
  error.value = null
  saveError.value = null
  try {
    await api.createRule({
      ecosystem: ruleForm.value.ecosystem || null,
      pattern: ruleForm.value.pattern,
      action: ruleForm.value.action,
      version_spec: ruleForm.value.version_spec || null,
      reason: ruleForm.value.reason || null,
    })
    showRule.value = false
    ruleForm.value = { ecosystem: '', pattern: '', action: 'block', version_spec: '', reason: '' }
    specPreview.value = null
    specProbe.value = ''
    await load()
  } catch (err) {
    saveError.value = err.detail || 'Could not create the rule.'
  }
}

async function deleteRule(rule) {
  if (!confirm(`Delete the ${rule.action} rule for "${rule.pattern}"?`)) return
  await api.deleteRule(rule.id)
  await load()
}

async function toggleRule(rule) {
  await api.updateRule(rule.id, { enabled: !rule.enabled })
  await load()
}

async function runTest() {
  tester.value.result = null
  try {
    tester.value.result = await api.testRule({
      ecosystem: tester.value.ecosystem,
      name: tester.value.name,
      version: tester.value.version || undefined,
    })
  } catch (err) {
    error.value = err.detail || 'Test failed.'
  }
}

async function saveCve() {
  error.value = null
  message.value = null
  try {
    await api.updateCvePolicy(cve.value)
    message.value = 'CVE policy saved.'
    await load()
  } catch (err) {
    error.value = err.detail || 'Could not save the CVE policy.'
  }
}

async function saveAllowlist() {
  await api.updateAllowlistMode(allowlistMode.value)
  message.value = allowlistMode.value
    ? 'Allowlist mode is ON — only allowed packages resolve.'
    : 'Allowlist mode is OFF.'
  await load()
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Package policy</h1>
      <p class="page-sub">
        Block rules are always enforced — on metadata, on downloads, and on publish. Nothing
        overrides them.
      </p>
    </div>
    <button class="btn btn-primary" @click="showRule = true">Add rule</button>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-ok">{{ message }}</div>
  <div v-if="loading" class="empty">Loading…</div>

  <template v-else>
    <div class="grid grid-2 mb">
      <div class="card">
        <div class="card-head">
          <h3>CVE score policy</h3>
          <span class="badge" :class="cve.enabled ? 'badge-warn' : ''">
            {{ cve.enabled ? 'enforcing' : 'off' }}
          </span>
        </div>
        <div class="card-body">
          <p class="dim small mb">
            Blocks any package version whose highest CVSS base score falls inside the range. Scores
            come from OSV.dev. Malicious-package advisories are always scored critical, whatever
            severity they carry.
          </p>

          <label class="check mb">
            <input v-model="cve.enabled" type="checkbox" />
            Enforce the CVE score policy
          </label>

          <div class="row" style="gap: 0.8rem">
            <div class="field" style="flex: 1">
              <label>Block from</label>
              <input v-model.number="cve.min_score" type="number" min="0" max="10" step="0.1" />
            </div>
            <div class="field" style="flex: 1">
              <label>Block up to</label>
              <input v-model.number="cve.max_score" type="number" min="0" max="10" step="0.1" />
            </div>
          </div>
          <p class="field-hint" style="margin-top: -0.5rem">
            e.g. 7.0–10.0 blocks high and critical. 0–10 blocks anything with a CVE.
          </p>

          <label class="check mt">
            <input v-model="cve.block_unscored" type="checkbox" />
            Also block versions that could not be scanned
          </label>
          <p class="field-hint">Fail-closed. Safer, but a slow OSV will block installs.</p>

          <label class="check">
            <input v-model="cve.require_fix_available" type="checkbox" />
            Only block when a fixed version exists upstream
          </label>
          <p class="field-hint">Avoids blocking things nobody can currently remediate.</p>

          <button class="btn btn-primary mt" @click="saveCve">Save CVE policy</button>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <h3>Allowlist mode</h3>
          <span class="badge" :class="allowlistMode ? 'badge-warn' : ''">
            {{ allowlistMode ? 'default deny' : 'default allow' }}
          </span>
        </div>
        <div class="card-body">
          <p class="dim small mb">
            With allowlist mode on, a package must match an <strong>allow</strong> rule to resolve at
            all. Use it for locked-down environments.
          </p>
          <label class="check mb">
            <input v-model="allowlistMode" type="checkbox" />
            Require packages to be explicitly allowed
          </label>
          <div v-if="allowlistMode && !allowRules.length" class="alert alert-warn small">
            You have no allow rules. Turning this on will block every package.
          </div>
          <button class="btn btn-primary" @click="saveAllowlist">Save</button>

          <hr style="border: none; border-top: 1px solid var(--border); margin: 1.1rem 0" />

          <h4 class="small">Test a package against the policy</h4>
          <div class="row" style="gap: 0.5rem; margin-bottom: 0.5rem">
            <select v-model="tester.ecosystem" style="width: auto">
              <option value="npm">npm</option>
              <option value="pypi">PyPI</option>
              <option value="cargo">cargo</option>
            </select>
            <input v-model="tester.name" placeholder="package name" style="flex: 1" />
            <input v-model="tester.version" placeholder="version" style="width: 110px" />
            <button class="btn" :disabled="!tester.name" @click="runTest">Test</button>
          </div>
          <div v-if="tester.result" class="alert small" :class="tester.result.allowed ? 'alert-ok' : 'alert-error'">
            <strong>{{ tester.result.allowed ? 'Allowed' : 'Blocked' }}</strong>
            <template v-if="tester.result.reason"> — {{ tester.result.reason }}</template>
            <template v-if="tester.result.source"> ({{ tester.result.source }})</template>
          </div>
        </div>
      </div>
    </div>

    <div class="card mb">
      <div class="card-head">
        <h3>Block rules</h3>
        <span class="faint small">
          {{ blockRules.length }} {{ blockRules.length === 1 ? 'rule' : 'rules' }} — always enforced
        </span>
      </div>
      <div class="card-body tight">
        <div v-if="!blockRules.length" class="empty">No packages are blocked.</div>
        <div v-else class="table-wrap">
          <table>
            <thead>
              <tr><th>Pattern</th><th>Ecosystem</th><th>Versions</th><th>Reason</th><th>Added</th><th></th></tr>
            </thead>
            <tbody>
              <tr v-for="rule in blockRules" :key="rule.id" :style="rule.enabled ? '' : 'opacity:.5'">
                <td class="mono">{{ rule.pattern }}</td>
                <td>
                  <span class="badge" :class="rule.ecosystem ? ecosystemBadge(rule.ecosystem) : ''">
                    {{ rule.ecosystem || 'all' }}
                  </span>
                </td>
                <td class="mono small">
                  {{ rule.version_spec || 'all' }}
                  <div
                    v-if="rule.version_spec_expanded && rule.version_spec_expanded !== rule.version_spec"
                    class="faint"
                    style="font-size: 0.75rem"
                  >
                    {{ rule.version_spec_expanded }}
                  </div>
                </td>
                <td class="dim small">{{ rule.reason || '—' }}</td>
                <td class="faint small nowrap">
                  {{ formatDate(rule.created_at) }}<span v-if="rule.created_by"> by {{ rule.created_by }}</span>
                </td>
                <td class="num nowrap">
                  <button class="btn btn-sm" @click="toggleRule(rule)">
                    {{ rule.enabled ? 'Disable' : 'Enable' }}
                  </button>
                  <button class="btn btn-sm btn-danger" @click="deleteRule(rule)">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h3>Allow rules</h3>
        <span class="faint small">
          {{ allowRules.length }} {{ allowRules.length === 1 ? 'rule' : 'rules' }} — only meaningful in allowlist mode
        </span>
      </div>
      <div class="card-body tight">
        <div v-if="!allowRules.length" class="empty">No allow rules.</div>
        <div v-else class="table-wrap">
          <table>
            <thead>
              <tr><th>Pattern</th><th>Ecosystem</th><th>Versions</th><th>Reason</th><th></th></tr>
            </thead>
            <tbody>
              <tr v-for="rule in allowRules" :key="rule.id" :style="rule.enabled ? '' : 'opacity:.5'">
                <td class="mono">{{ rule.pattern }}</td>
                <td><span class="badge">{{ rule.ecosystem || 'all' }}</span></td>
                <td class="mono small">{{ rule.version_spec || 'all' }}</td>
                <td class="dim small">{{ rule.reason || '—' }}</td>
                <td class="num nowrap">
                  <button class="btn btn-sm" @click="toggleRule(rule)">
                    {{ rule.enabled ? 'Disable' : 'Enable' }}
                  </button>
                  <button class="btn btn-sm btn-danger" @click="deleteRule(rule)">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>

  <div v-if="showRule" class="modal-backdrop" @click.self="showRule = false">
    <div class="modal">
      <div class="modal-head">
        <h3>Add policy rule</h3>
        <button class="btn btn-sm btn-ghost" @click="showRule = false">✕</button>
      </div>
      <div class="modal-body">
        <div class="field">
          <label>Action</label>
          <select v-model="ruleForm.action">
            <option value="block">Block — never serve this package</option>
            <option value="allow">Allow — permit in allowlist mode</option>
          </select>
        </div>
        <div class="field">
          <label>Ecosystem</label>
          <select v-model="ruleForm.ecosystem">
            <option value="">Both</option>
            <option value="npm">npm only</option>
            <option value="pypi">PyPI only</option>
            <option value="cargo">cargo only</option>
          </select>
        </div>
        <div class="field">
          <label>Name pattern</label>
          <input v-model="ruleForm.pattern" placeholder="e.g. event-stream, or @evilcorp/*" />
          <p class="field-hint">
            Glob against the normalized name. <code>*</code> matches any run of characters.
          </p>
        </div>
        <div class="field">
          <label>Version range (optional)</label>
          <input v-model="ruleForm.version_spec" :placeholder="specPlaceholder" />
          <p class="field-hint">
            Leave blank to cover every version.
            <template v-if="ruleForm.ecosystem === 'pypi'">
              PEP 440 specifier — <code>==1.2.3</code>, <code>&lt;2.0</code>,
              <code>&gt;=1.0,&lt;2.0</code>, <code>~=1.4.2</code>.
            </template>
            <template v-else>
              Full semver range — <code>&lt;4.17.21</code>, <code>^1.2.3</code>,
              <code>~1.2</code>, <code>1.x</code>, <code>&gt;=3.0.0 &lt;3.0.2</code>,
              <code>1.x || 2.x</code>.
              <template v-if="ruleForm.ecosystem === 'cargo'">
                Note a bare <code>1.2.3</code> pins that exact version here,
                unlike in <code>Cargo.toml</code> where it means
                <code>^1.2.3</code> — the expansion below shows what it resolves
                to.
              </template>
            </template>
          </p>

          <div v-if="specPreview" class="alert alert-info small" style="margin-top: 0.5rem">
            Matches <code>{{ specPreview }}</code>
            <span class="faint"> — prereleases inside the range are blocked too.</span>
          </div>
          <div v-else-if="specError" class="alert alert-error small" style="margin-top: 0.5rem">
            {{ specError }}
          </div>

          <div v-if="ruleForm.version_spec" class="row-tight" style="margin-top: 0.5rem">
            <input
              v-model="specProbe"
              placeholder="test a version…"
              style="width: 160px"
              class="small"
            />
            <span v-if="specProbe && specProbeResult !== null" class="badge" :class="specProbeResult ? 'badge-danger' : 'badge-ok'">
              {{ specProbeResult ? 'would be blocked' : 'not affected' }}
            </span>
          </div>
        </div>
        <div class="field">
          <label>Reason</label>
          <input v-model="ruleForm.reason" placeholder="Shown to users who are blocked" />
        </div>
      </div>
      <div class="modal-foot">
        <span v-if="saveError" class="alert alert-error small" style="margin: 0; flex: 1">
          {{ saveError }}
        </span>
        <button class="btn" @click="showRule = false">Cancel</button>
        <button
          class="btn btn-primary"
          :disabled="!ruleForm.pattern || Boolean(specError)"
          @click="saveRule"
        >
          Add rule
        </button>
      </div>
    </div>
  </div>
</template>
