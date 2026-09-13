<script setup>
import { computed, ref } from 'vue'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

// Deliberately not seeded from the query string. A link that pre-fills the
// code and jumps straight to the confirm step is how a device-flow approval
// gets phished: the recipient never types the code, so they never check that
// it is the one their own terminal is showing.
const code = ref('')
const pending = ref(null)
const error = ref(null)
const busy = ref(false)
// 'idle' | 'approved' | 'denied'
const outcome = ref('idle')
const scopes = ref(['read'])

function toggleScope(scope) {
  const set = new Set(scopes.value)
  set.has(scope) ? set.delete(scope) : set.add(scope)
  scopes.value = [...set]
}

async function lookup() {
  error.value = null
  pending.value = null
  const value = code.value.trim()
  if (!value) return
  busy.value = true
  try {
    pending.value = await api.cliPending(value)
    // Start at read only. The requested scopes are shown so the person can see
    // what the tool asked for, but pre-ticking `admin` meant a one-click
    // approval handed out the strongest token the approver could mint.
    // Widening is a deliberate action; the server caps it either way.
    scopes.value = ['read']
    if (pending.value.already_approved) {
      error.value = 'That code has already been used.'
      pending.value = null
    }
  } catch (err) {
    error.value = err.detail || 'That code is not valid.'
  } finally {
    busy.value = false
  }
}

async function decide(approve) {
  busy.value = true
  error.value = null
  try {
    await api.cliApprove({
      user_code: pending.value.user_code,
      approve,
      scopes: scopes.value,
    })
    outcome.value = approve ? 'approved' : 'denied'
  } catch (err) {
    error.value = err.detail || 'Could not complete the request.'
  } finally {
    busy.value = false
  }
}

const requestedScopes = computed(() => pending.value?.requested_scopes || ['read'])
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Authorize the command line tool</h1>
      <p class="page-sub">
        Confirm the code shown in your terminal. Only approve a request you started yourself.
      </p>
    </div>
  </div>

  <div style="max-width: 560px">
    <div v-if="outcome === 'approved'" class="card">
      <div class="card-body" style="text-align: center; padding: 2rem 1.5rem">
        <div style="font-size: 2rem; line-height: 1">✓</div>
        <h2 style="margin-top: 0.6rem">Approved</h2>
        <p class="dim">
          Your terminal should be signed in within a few seconds. You can close this page.
        </p>
        <router-link :to="{ name: 'cli' }" class="btn mt">CLI documentation</router-link>
      </div>
    </div>

    <div v-else-if="outcome === 'denied'" class="card">
      <div class="card-body" style="text-align: center; padding: 2rem 1.5rem">
        <h2>Request denied</h2>
        <p class="dim">No token was issued. The terminal will report that it was refused.</p>
      </div>
    </div>

    <template v-else>
      <div v-if="error" class="alert alert-error">{{ error }}</div>

      <div v-if="!pending" class="card">
        <div class="card-body">
          <form @submit.prevent="lookup">
            <div class="field">
              <label for="usercode">Code from your terminal</label>
              <input
                id="usercode"
                v-model="code"
                type="text"
                class="control-lg code-input"
                placeholder="XXXX-XXXX"
                autocomplete="off"
                autocapitalize="characters"
                spellcheck="false"
                maxlength="12"
                autofocus
              />
              <p class="field-hint">
                Shown by <code>minireg login</code>. Case and dashes do not matter.
              </p>
            </div>
            <button class="btn btn-primary btn-block control-lg" :disabled="busy || !code.trim()">
              {{ busy ? 'Checking…' : 'Continue' }}
            </button>
          </form>
        </div>
      </div>

      <div v-else class="card">
        <div class="card-head">
          <h3>Confirm this request</h3>
          <span class="badge badge-accent mono">{{ pending.user_code }}</span>
        </div>
        <div class="card-body">
          <p class="dim small mb">
            A command line tool is asking to sign in as
            <strong>{{ auth.user?.username }}</strong>. Approve this only if you started it
            yourself, on the machine in front of you.
          </p>

          <div class="alert alert-warn small mb">
            The details below are self-reported by the tool that asked. They are not verified,
            so a matching hostname is not proof the request is yours.
          </div>

          <div class="detail-grid mb">
            <span class="dim">Hostname</span>
            <span class="mono">{{ pending.hostname || 'not reported' }}</span>
            <span class="dim">Platform</span>
            <span class="mono small">{{ pending.platform || 'not reported' }}</span>
            <span class="dim">From IP</span>
            <span class="mono">{{ pending.ip || 'unknown' }}</span>
            <span class="dim">Requested</span>
            <span class="mono small">{{ requestedScopes.join(', ') }}</span>
          </div>

          <div class="field">
            <label>Grant this tool</label>
            <p
              v-if="(pending.requested_scopes || []).length > 1"
              class="field-hint"
              style="margin-top: -0.15rem; margin-bottom: 0.4rem"
            >
              It asked for <strong>{{ (pending.requested_scopes || []).join(', ') }}</strong>.
            </p>
            <label class="check">
              <input type="checkbox" checked disabled />
              <span><strong>read</strong> <span class="faint small">— install and search</span></span>
            </label>
            <label v-if="auth.canPublish" class="check">
              <input
                type="checkbox"
                :checked="scopes.includes('publish')"
                @change="toggleScope('publish')"
              />
              <span><strong>publish</strong> <span class="faint small">— publish new versions</span></span>
            </label>
            <label v-if="auth.isAdmin" class="check">
              <input
                type="checkbox"
                :checked="scopes.includes('admin')"
                @change="toggleScope('admin')"
              />
              <span><strong>admin</strong> <span class="faint small">— full administrative API</span></span>
            </label>
            <p class="field-hint">
              A token can never do more than your own account can.
            </p>
          </div>

          <div class="alert alert-warn small">
            If you did not just run <code>minireg login</code>, deny this request.
          </div>

          <div class="row" style="justify-content: flex-end">
            <button class="btn btn-danger" :disabled="busy" @click="decide(false)">Deny</button>
            <button class="btn btn-primary" :disabled="busy" @click="decide(true)">
              {{ busy ? 'Working…' : 'Approve' }}
            </button>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.code-input {
  font-family: var(--mono);
  font-size: 1.25rem;
  letter-spacing: 0.16em;
  text-align: center;
  text-transform: uppercase;
}

.detail-grid {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.35rem 1rem;
  font-size: 0.87rem;
  align-items: baseline;
}
</style>
