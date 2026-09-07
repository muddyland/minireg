<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandMark from '@/components/BrandMark.vue'
import NavIcon from '@/components/NavIcon.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const showPassword = ref(false)
const error = ref(null)
const busy = ref(false)

async function submit() {
  error.value = null
  busy.value = true
  try {
    await auth.login(username.value, password.value)
    router.push(route.query.next || { name: 'search' })
  } catch (err) {
    error.value = err.detail || 'Sign-in failed.'
  } finally {
    busy.value = false
  }
}

function ssoLogin() {
  const next = route.query.next || '/search'
  window.location.href = `/api/auth/oidc/login?next=${encodeURIComponent(next)}`
}

onMounted(() => auth.loadOidcStatus())
</script>

<template>
  <div class="login-page">
    <div class="login-shell">
      <header class="login-head">
        <BrandMark :size="52" />
        <h1>minireg</h1>
        <p class="page-sub">npm, PyPI &amp; cargo package registry</p>
      </header>

      <div class="card">
        <div class="card-body">
          <div v-if="error" class="alert alert-error">{{ error }}</div>

          <form @submit.prevent="submit">
            <div class="field">
              <label for="username">Username</label>
              <input
                id="username"
                v-model="username"
                type="text"
                class="control-lg"
                autocomplete="username"
                autocapitalize="none"
                spellcheck="false"
                autofocus
                required
              />
            </div>

            <div class="field">
              <label for="password">Password</label>
              <div class="input-affix">
                <input
                  id="password"
                  v-model="password"
                  :type="showPassword ? 'text' : 'password'"
                  class="control-lg"
                  autocomplete="current-password"
                  required
                />
                <button
                  type="button"
                  class="affix-btn"
                  :title="showPassword ? 'Hide password' : 'Show password'"
                  :aria-label="showPassword ? 'Hide password' : 'Show password'"
                  @click="showPassword = !showPassword"
                >
                  <NavIcon :name="showPassword ? 'eye-off' : 'eye'" :size="16" />
                </button>
              </div>
            </div>

            <button
              class="btn btn-primary btn-block control-lg"
              style="margin-top: 0.35rem"
              :disabled="busy || !username || !password"
              type="submit"
            >
              {{ busy ? 'Signing in…' : 'Sign in' }}
            </button>
          </form>

          <template v-if="auth.oidc.enabled">
            <div class="divider"><span>or</span></div>
            <button class="btn btn-block control-lg" @click="ssoLogin">
              <BrandMark :size="16" :tile="false" />
              Sign in with SSO
            </button>
          </template>
        </div>
      </div>

      <p class="login-foot">
        Package downloads may not require sign-in; the web UI always does.
      </p>
    </div>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 1.5rem;
  /* A faint wash off the accent so the card reads as raised without a
     heavy shadow. */
  background:
    radial-gradient(1100px 520px at 50% -12%, var(--accent-soft), transparent 70%),
    var(--bg);
}

.login-shell { width: 100%; max-width: 372px; }

.login-head {
  text-align: center;
  margin-bottom: 1.5rem;
}
.login-head h1 {
  margin: 0.75rem 0 0.15rem;
  font-size: 1.65rem;
  letter-spacing: -0.02em;
}

.divider {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  margin: 1.05rem 0 0.85rem;
  color: var(--text-faint);
  font-size: 0.8rem;
}
.divider::before,
.divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}

.login-foot {
  text-align: center;
  margin-top: 1.1rem;
  font-size: 0.8rem;
  color: var(--text-faint);
}
</style>
