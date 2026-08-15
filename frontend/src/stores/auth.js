import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '@/api/client'

export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  const scopes = ref([])
  const oidc = ref({ enabled: false, login_url: null })
  // `null` means "we have not checked yet", which is different from "logged
  // out" -- the router must wait rather than bounce the user to /login.
  const ready = ref(false)
  const loading = ref(false)

  const isAuthenticated = computed(() => user.value !== null)
  const isAdmin = computed(() => Boolean(user.value?.is_admin))
  const canPublish = computed(() => Boolean(user.value?.can_publish || user.value?.is_admin))

  async function loadSession() {
    loading.value = true
    try {
      const data = await api.me()
      user.value = data.user
      scopes.value = data.scopes || []
    } catch {
      user.value = null
      scopes.value = []
    } finally {
      ready.value = true
      loading.value = false
    }
  }

  async function loadOidcStatus() {
    try {
      oidc.value = await api.oidcStatus()
    } catch {
      oidc.value = { enabled: false, login_url: null }
    }
  }

  async function login(username, password) {
    const data = await api.login(username, password)
    user.value = data.user
    await loadSession()
    return data.user
  }

  async function logout() {
    try {
      await api.logout()
    } finally {
      user.value = null
      scopes.value = []
    }
  }

  return {
    user,
    scopes,
    oidc,
    ready,
    loading,
    isAuthenticated,
    isAdmin,
    canPublish,
    loadSession,
    loadOidcStatus,
    login,
    logout,
  }
})
