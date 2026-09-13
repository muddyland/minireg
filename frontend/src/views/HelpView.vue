<script setup>
/**
 * The shipped documentation, rendered in the app.
 *
 * This registry is often deployed where there is no route to the internet and
 * no access to the repository it was built from, so the docs travel inside
 * the image and are served from /api/help.
 *
 * The markdown is our own, baked in at build time and not editable by anyone
 * at runtime, so it is rendered as trusted content. If that ever stops being
 * true — user-supplied pages, an editable knowledge base — this needs a
 * sanitiser before the `v-html` below.
 */
import { computed, nextTick, ref, watch } from 'vue'
import { marked } from 'marked'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api/client'

const route = useRoute()
const router = useRouter()

const pages = ref([])
const page = ref(null)
const loading = ref(true)
const error = ref(null)

const slug = computed(() => route.params.slug || pages.value[0]?.slug || null)

function slugify(text) {
  return String(text)
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
}

const renderer = {
  // Headings get ids so in-page anchors work, and a self-link so a reader can
  // copy a link to a specific section.
  heading({ tokens, depth }) {
    const text = this.parser.parseInline(tokens)
    const id = slugify(this.parser.parseInline(tokens).replace(/<[^>]*>/g, ''))
    return `<h${depth} id="${id}"><a class="anchor" href="#${id}">#</a>${text}</h${depth}>`
  },
  // Links between docs are written as they read on disk (`configuration.md`,
  // `policy.md#unscanned-versions`). In here they have to point at the
  // in-app route instead, or every cross-reference is a dead end.
  link({ href, title, tokens }) {
    const text = this.parser.parseInline(tokens)
    let target = href || ''
    let attrs = ''
    const local = target.match(/^(?:\.\/)?(?:docs\/)?([a-z0-9-]+)\.md(#.*)?$/i)
    if (local) {
      target = `/help/${local[1].toLowerCase()}${local[2] || ''}`
    } else if (/^https?:\/\//i.test(target)) {
      attrs = ' target="_blank" rel="noopener noreferrer"'
    }
    const titleAttr = title ? ` title="${title}"` : ''
    return `<a href="${target}"${titleAttr}${attrs}>${text}</a>`
  },
}

marked.use({ renderer, gfm: true, breaks: false })

const rendered = computed(() => (page.value ? marked.parse(page.value.markdown) : ''))

async function loadIndex() {
  try {
    pages.value = (await api.helpPages()).pages || []
  } catch (err) {
    error.value = err.detail || 'Could not load the documentation index.'
  }
}

async function loadPage(target) {
  if (!target) return
  loading.value = true
  error.value = null
  try {
    page.value = await api.helpPage(target)
  } catch (err) {
    page.value = null
    error.value = err.detail || 'That page is not available.'
  } finally {
    loading.value = false
  }
}

// Intercept clicks on rewritten cross-references so they navigate in-app
// rather than reloading the whole SPA.
function onContentClick(event) {
  const anchor = event.target.closest('a')
  if (!anchor) return
  const href = anchor.getAttribute('href') || ''
  if (href.startsWith('/help/')) {
    event.preventDefault()
    router.push(href)
  } else if (href.startsWith('#')) {
    event.preventDefault()
    document.getElementById(href.slice(1))?.scrollIntoView({ behavior: 'smooth' })
  }
}

// The router does not scroll for us here: a cross-reference's target only
// exists after the page has been fetched and rendered.
async function scrollToHash() {
  if (!route.hash) return
  await nextTick()
  document.getElementById(route.hash.slice(1))?.scrollIntoView({ behavior: 'smooth' })
}

watch(
  slug,
  async (value) => {
    if (!pages.value.length) await loadIndex()
    await loadPage(value || pages.value[0]?.slug)
    await scrollToHash()
  },
  { immediate: true },
)

// Same page, different section.
watch(() => route.hash, scrollToHash)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Documentation</h1>
      <p class="page-sub">
        Shipped with this build, so it matches the version you are running.
      </p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>

  <div class="help-layout">
    <nav class="help-index card">
      <div class="card-body tight">
        <router-link
          v-for="entry in pages"
          :key="entry.slug"
          class="help-index-link"
          :class="{ active: entry.slug === slug }"
          :to="{ name: 'help-page', params: { slug: entry.slug } }"
        >
          <span class="help-index-title">{{ entry.title }}</span>
          <span v-if="entry.summary" class="help-index-summary">{{ entry.summary }}</span>
        </router-link>
      </div>
    </nav>

    <article class="card help-page">
      <div v-if="loading" class="card-body dim">Loading…</div>
      <!-- eslint-disable-next-line vue/no-v-html -->
      <div v-else class="card-body markdown" @click="onContentClick" v-html="rendered"></div>
    </article>
  </div>
</template>
