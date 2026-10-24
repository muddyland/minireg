<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatDate, relativeTime } from '@/utils/format'
import { errorMessage } from '@/utils/errors'

const auth = useAuthStore()
const users = ref([])
const loading = ref(true)
const error = ref(null)
const formError = ref(null)
const saving = ref(false)
// User id whose enable/delete call is in flight.
const busy = ref(null)

const showForm = ref(false)
const editing = ref(null)
const form = ref({
  username: '',
  email: '',
  full_name: '',
  password: '',
  is_admin: false,
  can_publish: false,
  is_active: true,
})

async function load() {
  loading.value = true
  try {
    users.value = (await api.listUsers()).users
  } catch (err) {
    error.value = errorMessage(err, 'Could not load users.')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  formError.value = null
  editing.value = null
  form.value = {
    username: '',
    email: '',
    full_name: '',
    password: '',
    is_admin: false,
    can_publish: false,
    is_active: true,
  }
  showForm.value = true
}

function openEdit(user) {
  formError.value = null
  editing.value = user
  form.value = { ...user, password: '' }
  showForm.value = true
}

async function save() {
  error.value = null
  formError.value = null
  saving.value = true
  try {
    if (editing.value) {
      const payload = {
        email: form.value.email || null,
        full_name: form.value.full_name || null,
        is_admin: form.value.is_admin,
        can_publish: form.value.can_publish,
        is_active: form.value.is_active,
      }
      if (form.value.password) payload.password = form.value.password
      await api.updateUser(editing.value.id, payload)
    } else {
      await api.createUser({
        username: form.value.username,
        email: form.value.email || null,
        full_name: form.value.full_name || null,
        password: form.value.password || null,
        is_admin: form.value.is_admin,
        can_publish: form.value.can_publish,
        is_active: form.value.is_active,
      })
    }
    showForm.value = false
    await load()
  } catch (err) {
    // Shown inside the dialog: the page alert is hidden behind the backdrop.
    formError.value = errorMessage(err, 'Could not save the user.')
  } finally {
    saving.value = false
  }
}

async function remove(user) {
  if (!confirm(`Delete "${user.username}"? Their API tokens are revoked too.`)) return
  error.value = null
  busy.value = user.id
  try {
    await api.deleteUser(user.id)
    await load()
  } catch (err) {
    error.value = errorMessage(err, `Could not delete ${user.username}.`)
  } finally {
    busy.value = null
  }
}

async function toggleActive(user) {
  error.value = null
  busy.value = user.id
  try {
    await api.updateUser(user.id, { is_active: !user.is_active })
    await load()
  } catch (err) {
    error.value = errorMessage(
      err,
      `Could not ${user.is_active ? 'disable' : 'enable'} ${user.username}.`,
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
      <h1>Users</h1>
      <p class="page-sub">
        Local accounts and accounts provisioned through SSO. SSO group membership is re-applied on
        every sign-in.
      </p>
    </div>
    <button class="btn btn-primary" @click="openCreate">Add user</button>
  </div>

  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>

  <div class="card">
    <div class="card-body tight">
      <div v-if="loading" class="empty">Loading…</div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Source</th>
              <th>Permissions</th>
              <th class="num">Tokens</th>
              <th>Last sign-in</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id" :style="user.is_active ? '' : 'opacity:.5'">
              <td>
                <strong>{{ user.username }}</strong>
                <span v-if="user.id === auth.user?.id" class="badge">you</span>
                <div v-if="user.full_name" class="faint small">{{ user.full_name }}</div>
              </td>
              <td class="small dim">{{ user.email || '—' }}</td>
              <td>
                <span class="badge">{{ user.provider === 'oidc' ? 'SSO' : 'local' }}</span>
              </td>
              <td>
                <span v-if="user.is_admin" class="badge badge-accent">admin</span>
                <span v-if="user.can_publish" class="badge badge-ok">publish</span>
                <span v-if="!user.is_active" class="badge badge-danger">disabled</span>
                <span v-if="!user.is_admin && !user.can_publish" class="badge">read only</span>
              </td>
              <td class="num">{{ user.token_count }}</td>
              <td class="dim small nowrap">
                {{ user.last_login_at ? relativeTime(user.last_login_at) : 'never' }}
              </td>
              <td class="faint small nowrap">{{ formatDate(user.created_at) }}</td>
              <td class="num nowrap">
                <button class="btn btn-sm" @click="openEdit(user)">Edit</button>
                <button
                  class="btn btn-sm"
                  :disabled="user.id === auth.user?.id || busy === user.id"
                  @click="toggleActive(user)"
                >
                  {{ user.is_active ? 'Disable' : 'Enable' }}
                </button>
                <button
                  class="btn btn-sm btn-danger"
                  :disabled="user.id === auth.user?.id || busy === user.id"
                  @click="remove(user)"
                >
                  Delete
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div v-if="showForm" class="modal-backdrop" @click.self="showForm = false">
    <div class="modal">
      <div class="modal-head">
        <h3>{{ editing ? `Edit ${editing.username}` : 'Add user' }}</h3>
        <button class="btn btn-sm btn-ghost" aria-label="Close" @click="showForm = false">✕</button>
      </div>
      <div class="modal-body">
        <div v-if="!editing" class="field">
          <label for="user-username">Username</label>
          <input id="user-username" v-model="form.username" autocomplete="off" />
        </div>
        <div class="field">
          <label for="user-email">Email</label>
          <input id="user-email" v-model="form.email" type="email" autocomplete="off" />
          <p class="field-hint">
            An SSO login with a matching email is linked to this account automatically.
          </p>
        </div>
        <div class="field">
          <label for="user-full-name">Full name</label>
          <input id="user-full-name" v-model="form.full_name" autocomplete="off" />
        </div>
        <div v-if="editing?.provider !== 'oidc'" class="field">
          <label for="user-password">{{ editing ? 'New password' : 'Password' }}</label>
          <input
            id="user-password"
            v-model="form.password"
            type="password"
            autocomplete="new-password"
            :placeholder="editing ? 'leave blank to keep current' : 'at least 12 characters'"
          />
          <p v-if="!editing" class="field-hint">
            Leave blank for an SSO-only account that cannot sign in with a password.
          </p>
        </div>

        <label class="check"><input v-model="form.is_active" type="checkbox" /> Account is active</label>
        <label class="check">
          <input v-model="form.can_publish" type="checkbox" />
          May publish packages
        </label>
        <label class="check">
          <input v-model="form.is_admin" type="checkbox" />
          Administrator (implies publish)
        </label>
      </div>
      <div class="modal-foot">
        <span v-if="formError" class="alert alert-error small" role="alert" style="margin: 0; flex: 1">
          {{ formError }}
        </span>
        <button class="btn" @click="showForm = false">Cancel</button>
        <button class="btn btn-primary" :disabled="saving || (!editing && !form.username)" @click="save">Save</button>
      </div>
    </div>
  </div>
</template>
