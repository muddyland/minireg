<script setup>
import { ref } from 'vue'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'

const auth = useAuthStore()
const form = ref({ current_password: '', new_password: '', confirm: '' })
const message = ref(null)
const error = ref(null)

async function changePassword() {
  message.value = null
  error.value = null
  if (form.value.new_password !== form.value.confirm) {
    error.value = 'The new passwords do not match.'
    return
  }
  try {
    await api.changePassword(form.value.current_password, form.value.new_password)
    message.value = 'Password changed.'
    form.value = { current_password: '', new_password: '', confirm: '' }
  } catch (err) {
    error.value = err.detail || 'Could not change the password.'
  }
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Account</h1>
      <p class="page-sub">Your profile and credentials.</p>
    </div>
  </div>

  <div class="grid grid-2">
    <div class="card">
      <div class="card-head"><h3>Profile</h3></div>
      <div class="card-body small">
        <div class="row" style="justify-content: space-between">
          <span class="dim">Username</span><strong>{{ auth.user?.username }}</strong>
        </div>
        <div class="row" style="justify-content: space-between">
          <span class="dim">Email</span><span>{{ auth.user?.email || '—' }}</span>
        </div>
        <div class="row" style="justify-content: space-between">
          <span class="dim">Sign-in method</span>
          <span class="badge">{{ auth.user?.provider === 'oidc' ? 'SSO' : 'local password' }}</span>
        </div>
        <div class="row" style="justify-content: space-between">
          <span class="dim">Role</span>
          <span class="badge" :class="auth.isAdmin ? 'badge-accent' : ''">
            {{ auth.isAdmin ? 'administrator' : 'user' }}
          </span>
        </div>
        <div class="row" style="justify-content: space-between">
          <span class="dim">Can publish</span>
          <span class="badge" :class="auth.canPublish ? 'badge-ok' : ''">
            {{ auth.canPublish ? 'yes' : 'no' }}
          </span>
        </div>
        <div class="row" style="justify-content: space-between">
          <span class="dim">Last sign-in</span>
          <span>{{ formatDateTime(auth.user?.last_login_at) }}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Change password</h3></div>
      <div class="card-body">
        <div v-if="auth.user?.provider === 'oidc'" class="alert alert-info">
          Your password is managed by your identity provider and cannot be changed here.
        </div>
        <template v-else>
          <div v-if="message" class="alert alert-ok">{{ message }}</div>
          <div v-if="error" class="alert alert-error">{{ error }}</div>
          <form @submit.prevent="changePassword">
            <div class="field">
              <label for="cur">Current password</label>
              <input id="cur" v-model="form.current_password" type="password" autocomplete="current-password" />
            </div>
            <div class="field">
              <label for="new">New password</label>
              <input id="new" v-model="form.new_password" type="password" autocomplete="new-password" />
              <p class="field-hint">At least 12 characters.</p>
            </div>
            <div class="field">
              <label for="conf">Confirm new password</label>
              <input id="conf" v-model="form.confirm" type="password" autocomplete="new-password" />
            </div>
            <button
              class="btn btn-primary"
              type="submit"
              :disabled="!form.current_password || form.new_password.length < 12"
            >
              Change password
            </button>
          </form>
        </template>
      </div>
    </div>
  </div>
</template>
