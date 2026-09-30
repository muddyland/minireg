<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandMark from '@/components/BrandMark.vue'
import EcosystemIcon from '@/components/EcosystemIcon.vue'
import NavIcon from '@/components/NavIcon.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const theme = ref(document.documentElement.getAttribute('data-theme') || 'light')

const isLogin = computed(() => route.name === 'login')

// Which sidebar section the current page belongs to, so its header is
// highlighted -- including detail pages that have no nav entry of their own
// (a package page is under Packages, an image page under Containers).
const SECTIONS = {
  packages: ['search', 'package', 'admin-packages', 'upstreams', 'policy', 'security', 'downloads'],
  containers: ['images', 'image', 'docker-upstreams', 'image-policy'],
  account: ['tokens', 'cli', 'cli-login', 'account'],
  system: ['storage', 'users', 'audit'],
}
const section = computed(
  () => Object.keys(SECTIONS).find((key) => SECTIONS[key].includes(route.name)) || null,
)

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
      <router-link class="brand" :to="{ name: 'home' }">
        <BrandMark :size="30" />
        <div>
          <div class="brand-name">minireg</div>
          <div class="brand-ecos">
            <EcosystemIcon ecosystem="npm" class="eco-npm" :size="11" />
            <EcosystemIcon ecosystem="pypi" class="eco-pypi" :size="11" />
            <EcosystemIcon ecosystem="cargo" class="eco-cargo" :size="11" />
            <EcosystemIcon ecosystem="docker" class="eco-docker" :size="11" />
          </div>
        </div>
      </router-link>

      <nav class="nav">
        <router-link class="nav-link" :to="{ name: 'home' }">
          <NavIcon name="home" /> Home
        </router-link>
        <router-link v-if="auth.isAdmin" class="nav-link" :to="{ name: 'dashboard' }">
          <NavIcon name="dashboard" /> Dashboard
        </router-link>
        <router-link class="nav-link" :to="{ name: 'setup' }">
          <NavIcon name="setup" /> Client setup
        </router-link>

        <div class="nav-section" :class="{ current: section === 'packages' }">Packages</div>
        <router-link class="nav-link" :class="{ 'router-link-active': route.name === 'package' }" :to="{ name: 'search' }">
          <NavIcon name="search" /> Search
        </router-link>
        <template v-if="auth.isAdmin">
          <router-link class="nav-link" :to="{ name: 'admin-packages' }">
            <NavIcon name="package" /> Manage packages
          </router-link>
          <router-link class="nav-link" :to="{ name: 'upstreams' }">
            <NavIcon name="upstreams" /> Upstreams
          </router-link>
          <router-link class="nav-link" :to="{ name: 'policy' }">
            <NavIcon name="shield" /> Policy
          </router-link>
          <router-link class="nav-link" :to="{ name: 'security' }">
            <NavIcon name="alert" /> Vulnerabilities
          </router-link>
          <router-link class="nav-link" :to="{ name: 'downloads' }">
            <NavIcon name="downloads" /> Requests
          </router-link>
        </template>

        <div class="nav-section" :class="{ current: section === 'containers' }">Containers</div>
        <router-link class="nav-link" :class="{ 'router-link-active': route.name === 'image' }" :to="{ name: 'images' }">
          <NavIcon name="container" /> Images
        </router-link>
        <template v-if="auth.isAdmin">
          <router-link class="nav-link" :to="{ name: 'docker-upstreams' }">
            <NavIcon name="registry" /> Registries
          </router-link>
          <router-link class="nav-link" :to="{ name: 'image-policy' }">
            <NavIcon name="shield" /> Policy &amp; scanning
          </router-link>
        </template>

        <div class="nav-section" :class="{ current: section === 'account' }">Account</div>
        <router-link class="nav-link" :to="{ name: 'tokens' }">
          <NavIcon name="key" /> API tokens
        </router-link>
        <router-link class="nav-link" :to="{ name: 'cli' }">
          <NavIcon name="terminal" /> CLI tool
        </router-link>

        <template v-if="auth.isAdmin">
          <div class="nav-section" :class="{ current: section === 'system' }">System</div>
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
          <router-link
            class="btn btn-sm btn-ghost topbar-icon"
            :to="{ name: 'help' }"
            title="Documentation"
            aria-label="Documentation"
          >
            <NavIcon name="help" :size="16" />
          </router-link>
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
