import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { public: true } },
  { path: '/', redirect: '/search' },

  { path: '/search', name: 'search', component: () => import('@/views/SearchView.vue') },
  {
    path: '/packages/:ecosystem/:name(.*)',
    name: 'package',
    component: () => import('@/views/PackageView.vue'),
  },
  { path: '/setup', name: 'setup', component: () => import('@/views/SetupView.vue') },
  { path: '/cli', name: 'cli', component: () => import('@/views/CliView.vue') },
  { path: '/cli-login', name: 'cli-login', component: () => import('@/views/CliLoginView.vue') },
  { path: '/tokens', name: 'tokens', component: () => import('@/views/TokensView.vue') },
  { path: '/account', name: 'account', component: () => import('@/views/AccountView.vue') },
  { path: '/help', name: 'help', component: () => import('@/views/HelpView.vue') },
  { path: '/help/:slug', name: 'help-page', component: () => import('@/views/HelpView.vue') },

  { path: '/admin', name: 'dashboard', component: () => import('@/views/admin/DashboardView.vue'), meta: { admin: true } },
  { path: '/admin/users', name: 'users', component: () => import('@/views/admin/UsersView.vue'), meta: { admin: true } },
  { path: '/admin/upstreams', name: 'upstreams', component: () => import('@/views/admin/UpstreamsView.vue'), meta: { admin: true } },
  { path: '/admin/policy', name: 'policy', component: () => import('@/views/admin/PolicyView.vue'), meta: { admin: true } },
  { path: '/admin/security', name: 'security', component: () => import('@/views/admin/SecurityView.vue'), meta: { admin: true } },
  { path: '/admin/packages', name: 'admin-packages', component: () => import('@/views/admin/PackagesView.vue'), meta: { admin: true } },
  { path: '/admin/storage', name: 'storage', component: () => import('@/views/admin/StorageView.vue'), meta: { admin: true } },
  { path: '/admin/downloads', name: 'downloads', component: () => import('@/views/admin/DownloadsView.vue'), meta: { admin: true } },
  { path: '/admin/audit', name: 'audit', component: () => import('@/views/admin/AuditView.vue'), meta: { admin: true } },

  { path: '/:pathMatch(.*)*', redirect: '/search' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  // Documentation cross-references carry anchors. The target renders after
  // the page is fetched, so the element does not exist yet at navigation
  // time; the docs view scrolls to it once it has content.
  scrollBehavior: (to, from) => (to.hash ? false : { top: 0 }),
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  // Resolve the session once, before the first guarded navigation, so a hard
  // refresh on a deep link does not bounce through /login.
  if (!auth.ready) await auth.loadSession()

  if (to.meta.public) {
    return auth.isAuthenticated && to.name === 'login' ? { name: 'search' } : true
  }
  if (!auth.isAuthenticated) {
    return { name: 'login', query: { next: to.fullPath } }
  }
  if (to.meta.admin && !auth.isAdmin) {
    return { name: 'search' }
  }
  return true
})

export default router
