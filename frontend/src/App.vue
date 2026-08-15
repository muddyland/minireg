<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandMark from '@/components/BrandMark.vue'
import NavIcon from '@/components/NavIcon.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const theme = ref(document.documentElement.getAttribute('data-theme') || 'light')

const isLogin = computed(() => route.name === 'login')

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  document.documentElement.setAttribute('data-theme', theme.value)
  localStorage.setItem('minireg-theme', theme.value)
}

async function logout() {
  await auth.logout()
  router.push({ name: 'login' })
}

onMounted(() => auth.loadOidcStatus())
</script>

<template>
  <router-view v-if="isLogin" />

  <div v-else-if="auth.ready" class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <BrandMark :size="30" />
        <div>
          <div class="brand-name">minireg</div>
          <div class="faint" style="font-size: 0.7rem">npm + pypi registry</div>
        </div>
      </div>

      <nav class="nav">
        <div class="nav-section">Browse</div>
        <router-link class="nav-link" :to="{ name: 'search' }">
          <NavIcon name="search" /> Search
        </router-link>
        <router-link class="nav-link" :to="{ name: 'setup' }">
          <NavIcon name="setup" /> Client setup
        </router-link>
        <router-link class="nav-link" :to="{ name: 'tokens' }">
          <NavIcon name="key" /> API tokens
        </router-link>
        <router-link class="nav-link" :to="{ name: 'cli' }">
          <NavIcon name="terminal" /> CLI tool
        </router-link>

        <template v-if="auth.isAdmin">
          <div class="nav-section">Administration</div>
          <router-link class="nav-link" :to="{ name: 'dashboard' }">
            <NavIcon name="dashboard" /> Dashboard
          </router-link>
          <router-link class="nav-link" :to="{ name: 'upstreams' }">
            <NavIcon name="upstreams" /> Upstreams
          </router-link>
          <router-link class="nav-link" :to="{ name: 'policy' }">
            <NavIcon name="shield" /> Package policy
          </router-link>
          <router-link class="nav-link" :to="{ name: 'security' }">
            <NavIcon name="alert" /> Vulnerabilities
          </router-link>
          <router-link class="nav-link" :to="{ name: 'admin-packages' }">
            <NavIcon name="package" /> Packages
          </router-link>
          <router-link class="nav-link" :to="{ name: 'storage' }">
            <NavIcon name="storage" /> Storage
          </router-link>
          <router-link class="nav-link" :to="{ name: 'users' }">
            <NavIcon name="users" /> Users
          </router-link>
          <router-link class="nav-link" :to="{ name: 'audit' }">
            <NavIcon name="audit" /> Audit log
          </router-link>
        </template>
      </nav>

      <div class="sidebar-footer">
        <router-link :to="{ name: 'account' }" class="nav-link">
          <NavIcon name="account" />
          <span class="truncate">{{ auth.user?.username }}</span>
          <span v-if="auth.isAdmin" class="badge badge-accent" style="margin-left: auto">admin</span>
        </router-link>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="row small dim">
          <span v-if="auth.user?.provider === 'oidc'" class="badge">SSO</span>
          <span>Signed in as <strong>{{ auth.user?.username }}</strong></span>
        </div>
        <div class="row">
          <button class="btn btn-sm btn-ghost" :title="`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`" @click="toggleTheme">
            {{ theme === 'dark' ? '☀' : '☾' }}
          </button>
          <button class="btn btn-sm" @click="logout">Sign out</button>
        </div>
      </header>

      <main class="content">
        <router-view />
      </main>
    </div>
  </div>

  <div v-else class="empty">Loading…</div>
</template>
