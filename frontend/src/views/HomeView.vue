<script setup>
/**
 * Landing page: what this registry is, how to point a client at it, and the
 * handful of commands people come back for. Everything with a URL in it is
 * generated from /api/client-config, so the snippets match this deployment
 * rather than a hostname baked into the docs. Depth lives in the shipped
 * documentation; each section here links to the page that covers it.
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '@/api/client'
import BrandMark from '@/components/BrandMark.vue'
import EcosystemIcon from '@/components/EcosystemIcon.vue'
import NavIcon from '@/components/NavIcon.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()

const config = ref(null)
const configError = ref(null)
const query = ref('')
const copied = ref(null)

const ecosystems = computed(() => {
  const c = config.value
  if (!c) return []
  const cards = [
    {
      key: 'npm',
      name: 'npm',
      clients: 'npm, yarn, pnpm',
      snippet: `npm config set registry ${c.npm.registry}`,
      note: 'Or commit the same line to the project’s .npmrc.',
      doc: { slug: 'usage', hash: '#npm' },
    },
    {
      key: 'pypi',
      name: 'PyPI',
      clients: 'pip, uv, poetry, twine',
      snippet: `pip config set global.index-url ${c.pip.index_url}`,
      note: 'uv: --index-url · poetry: poetry source add',
      doc: { slug: 'usage', hash: '#python' },
    },
  ]
  if (c.cargo) {
    cards.push({
      key: 'cargo',
      name: 'cargo',
      clients: 'crates.io, read-only mirror',
      snippet: c.cargo.config_toml,
      note: 'In .cargo/config.toml. No token needed.',
      doc: { slug: 'usage', hash: '#rust-cargo' },
    })
  }
  return cards
})

const origin = computed(() => config.value?.public_url || window.location.origin)

const quickRef = computed(() => [
  {
    title: 'Install the CLI',
    command: `curl -fsSL ${origin.value}/api/cli/install.sh | sh`,
    doc: { slug: 'cli', hash: '#install' },
  },
  {
    title: 'Sign in and configure every client',
    command: 'minireg login\nminireg configure',
    doc: { slug: 'cli', hash: '#configuring-package-managers' },
  },
  {
    title: 'Audit a project’s lockfile',
    command: 'minireg audit --fail-on high',
    doc: { slug: 'cli', hash: '#auditing' },
  },
  {
    title: 'Publish an npm package',
    command: `npm publish --registry ${config.value?.npm.registry || `${origin.value}/npm/`}`,
    doc: { slug: 'usage', hash: '#npm' },
  },
  {
    title: 'Publish a Python package',
    command: `twine upload --repository-url ${config.value?.twine.repository_url || `${origin.value}/pypi/legacy/`} \\\n  -u __token__ -p "$MINIREG_TOKEN" dist/*`,
    doc: { slug: 'usage', hash: '#publishing-with-twine' },
  },
])

const docLinks = [
  { slug: 'usage', title: 'Using the registry', summary: 'Every client, CI, Docker builds' },
  { slug: 'cli', title: 'The CLI', summary: 'Install, sign in, configure, audit' },
  { slug: 'policy', title: 'Package policy', summary: 'Why a version is blocked' },
  { slug: 'troubleshooting', title: 'Troubleshooting', summary: 'When something does not resolve' },
]

function search() {
  router.push({ name: 'search', query: query.value.trim() ? { q: query.value.trim() } : {} })
}

async function copy(text, key) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
    setTimeout(() => (copied.value = null), 1600)
  } catch {
    copied.value = null
  }
}

function docRoute(doc) {
  return { name: 'help-page', params: { slug: doc.slug }, hash: doc.hash || '' }
}

onMounted(async () => {
  try {
    config.value = await api.clientConfig()
  } catch (err) {
    configError.value = err.detail || 'Could not load the client configuration.'
  }
})
</script>

<template>
  <section class="hero card mb">
    <div class="card-body hero-body">
      <div class="hero-text">
        <div class="row-tight hero-kicker">
          <BrandMark :size="22" />
          <span>minireg</span>
        </div>
        <h1 class="hero-title">One registry for npm, PyPI and cargo.</h1>
        <p class="hero-lead">
          minireg sits between your package managers and the public registries. It caches every
          package it serves, checks each version against known vulnerabilities, blocks what policy
          says to block, and hosts your own npm and Python packages alongside the public ones.
        </p>
        <form class="row hero-search" @submit.prevent="search">
          <input v-model="query" type="search" placeholder="Search packages…" aria-label="Search packages" />
          <button class="btn btn-primary" type="submit">Search</button>
        </form>
        <div class="row-tight hero-links">
          <router-link :to="{ name: 'setup' }" class="btn btn-sm">
            <NavIcon name="setup" :size="15" /> Client setup
          </router-link>
          <router-link :to="{ name: 'help' }" class="btn btn-sm">
            <NavIcon name="help" :size="15" /> Documentation
          </router-link>
          <router-link v-if="auth.isAdmin" :to="{ name: 'dashboard' }" class="btn btn-sm btn-ghost">
            <NavIcon name="dashboard" :size="15" /> Dashboard
          </router-link>
        </div>
      </div>

      <ul class="hero-points">
        <li>
          <NavIcon name="storage" :size="18" />
          <div><strong>Cached.</strong> Packages are fetched once and served locally after that.</div>
        </li>
        <li>
          <NavIcon name="shield" :size="18" />
          <div><strong>Checked.</strong> Every version is scanned for known CVEs; policy can refuse the risky ones.</div>
        </li>
        <li>
          <NavIcon name="package" :size="18" />
          <div><strong>Yours too.</strong> <code>npm publish</code> and <code>twine upload</code> work here.</div>
        </li>
      </ul>
    </div>
  </section>

  <div class="section-head">
    <h2>Point your client at it</h2>
    <router-link :to="{ name: 'setup' }" class="small">Full setup for every client →</router-link>
  </div>

  <div v-if="configError" class="alert alert-error">{{ configError }}</div>
  <div v-else-if="!config" class="empty">Loading…</div>
  <div v-else class="grid grid-3 mb eco-grid">
    <div v-for="eco in ecosystems" :key="eco.key" class="card eco-card" :class="`eco-card-${eco.key}`">
      <div class="card-head">
        <div class="row-tight">
          <span class="eco-mark" :class="`eco-${eco.key}`">
            <EcosystemIcon :ecosystem="eco.key" :size="20" />
          </span>
          <div>
            <h3 style="margin: 0">{{ eco.name }}</h3>
            <div class="faint small">{{ eco.clients }}</div>
          </div>
        </div>
      </div>
      <div class="card-body eco-card-body">
        <div class="copy-block">
          <pre>{{ eco.snippet }}</pre>
          <button class="btn btn-sm" @click="copy(eco.snippet, eco.key)">
            {{ copied === eco.key ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <p class="field-hint">{{ eco.note }}</p>
        <router-link :to="docRoute(eco.doc)" class="small eco-card-more">Read more</router-link>
      </div>
    </div>
  </div>

  <div class="grid home-lower">
    <div class="card">
      <div class="card-head">
        <h3>Quick reference</h3>
        <router-link :to="{ name: 'cli' }" class="small">CLI tool →</router-link>
      </div>
      <div class="card-body tight">
        <div v-for="(item, index) in quickRef" :key="item.title" class="qref-row">
          <div class="qref-head">
            <span class="qref-title">{{ item.title }}</span>
            <router-link :to="docRoute(item.doc)" class="small faint">docs</router-link>
          </div>
          <div class="copy-block">
            <pre>{{ item.command }}</pre>
            <button class="btn btn-sm" @click="copy(item.command, `q${index}`)">
              {{ copied === `q${index}` ? 'Copied' : 'Copy' }}
            </button>
          </div>
        </div>
        <p class="field-hint qref-foot">
          Publishing and the CLI need an API token from
          <router-link :to="{ name: 'tokens' }">API tokens</router-link>. Installing does not.
        </p>
      </div>
    </div>

    <div class="stack">
      <div class="card">
        <div class="card-head">
          <h3>Documentation</h3>
          <router-link :to="{ name: 'help' }" class="small">All pages →</router-link>
        </div>
        <div class="card-body tight">
          <router-link
            v-for="doc in docLinks"
            :key="doc.slug"
            class="doc-link"
            :to="{ name: 'help-page', params: { slug: doc.slug } }"
          >
            <span class="doc-link-title">{{ doc.title }}</span>
            <span class="doc-link-summary">{{ doc.summary }}</span>
          </router-link>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>If an install fails</h3></div>
        <div class="card-body small dim">
          <p style="margin-top: 0">
            <strong>“No matching version”</strong>, <code>ETARGET</code> or a 403 on an old pin
            usually means that version is <strong>blocked</strong> by vulnerability policy, not
            missing. Blocked versions are removed from the metadata.
          </p>
          <p style="margin-bottom: 0">
            Search for the package to see which versions are allowed and why, then upgrade. See
            <router-link :to="{ name: 'help-page', params: { slug: 'troubleshooting' } }">Troubleshooting</router-link>.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hero-body {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) minmax(240px, 1fr);
  gap: 2rem;
  padding: 1.6rem 1.6rem;
  align-items: center;
}
.hero-kicker { font-weight: 650; color: var(--text-dim); gap: 0.45rem; margin-bottom: 0.5rem; }
.hero-title { font-size: 1.65rem; line-height: 1.2; letter-spacing: -0.02em; margin: 0 0 0.6rem; }
.hero-lead { color: var(--text-dim); margin: 0 0 1.1rem; max-width: 62ch; }
.hero-search { flex-wrap: nowrap; max-width: 520px; }
.hero-search input { flex: 1; min-width: 0; height: var(--control-h-lg); }
.hero-search .btn { height: var(--control-h-lg); }
.hero-links { margin-top: 0.8rem; flex-wrap: wrap; gap: 0.4rem; }
.hero-links .btn { display: inline-flex; align-items: center; gap: 0.4rem; }
.hero-links a:hover { text-decoration: none; }

.hero-points { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.9rem; }
.hero-points li { display: flex; gap: 0.7rem; align-items: flex-start; color: var(--text-dim); font-size: 0.9rem; }
.hero-points li :deep(.nav-icon) { color: var(--accent); margin-top: 0.1rem; }
.hero-points strong { color: var(--text); }

.section-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 1rem; margin: 0.4rem 0 0.7rem;
}
.section-head h2 { font-size: 1.05rem; margin: 0; }

.eco-mark {
  display: grid; place-items: center;
  width: 34px; height: 34px; border-radius: var(--radius-sm);
  margin-right: 0.35rem;
  background: color-mix(in srgb, currentColor 13%, transparent);
}
.eco-card { border-top: 3px solid var(--border); display: flex; flex-direction: column; }
/* The three setup cards share a row height (the cargo snippet is the
   tallest), and "Read more" sits on one line across them. */
.eco-grid { align-items: stretch; }
.eco-card-body { flex: 1; display: flex; flex-direction: column; }
.eco-card-more { margin-top: auto; padding-top: 0.6rem; }
.eco-card-npm { border-top-color: var(--npm); }
.eco-card-pypi { border-top-color: var(--pypi); }
.eco-card-cargo { border-top-color: var(--cargo); }
.eco-card pre { white-space: pre-wrap; overflow-wrap: anywhere; padding-right: 4.5rem; }

.home-lower { grid-template-columns: minmax(0, 1.6fr) minmax(260px, 1fr); align-items: stretch; }
/* The right column ends level with Quick reference: its last card takes up
   the difference. */
.stack { display: flex; flex-direction: column; gap: 1rem; }
.stack > .card:last-child { flex: 1; }

.qref-row { padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); }
.qref-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 0.35rem; }
.qref-title { font-weight: 600; font-size: 0.88rem; }
.qref-row pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; padding-right: 4.5rem; }
.qref-foot { padding: 0.7rem 1rem; margin: 0; }

.doc-link {
  display: flex; flex-direction: column;
  padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
  color: var(--text);
}
.doc-link:last-child { border-bottom: none; }
.doc-link:hover { background: var(--surface-2); text-decoration: none; }
.doc-link-title { font-weight: 600; font-size: 0.88rem; }
.doc-link-summary { color: var(--text-faint); font-size: 0.8rem; }

@media (max-width: 1000px) {
  .hero-body, .home-lower { grid-template-columns: 1fr; }
}
</style>
