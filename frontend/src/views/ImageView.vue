<script setup>
/**
 * One image repository. Each tag is a row; expanding it shows everything
 * about that image (TagDetails): platforms, vulnerabilities, packages from
 * the SBOM, layers with their build steps, config and scan history.
 *
 * The open tag is kept in the URL (?tag=), so a link can point straight at it.
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api/client'
import TagDetails from '@/components/TagDetails.vue'
import { useAuthStore } from '@/stores/auth'
import { SEVERITIES, formatBytes, relativeTime, shortDigest, trivySeverityClass } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const name = computed(() => route.params.name)

const repo = ref(null)
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const watchInput = ref('')
const tagFilter = ref('')
// Bumped after admin actions so open panels drop their cached data.
const generation = ref(0)

const open = ref(new Set(route.query.tag ? [String(route.query.tag)] : []))

async function load() {
  loading.value = true
  error.value = null
  try {
    repo.value = await api.dockerRepository(name.value)
    watchInput.value = (repo.value.watched_tags || []).join(', ')
    // Nothing chosen: open the newest tag, so the page is never just a list.
    if (!open.value.size && repo.value.tags.length) open.value = new Set([repo.value.tags[0].tag])
  } catch (err) {
    error.value = err.status === 404 ? 'This repository has not been pulled or pushed yet.' : err.detail
  } finally {
    loading.value = false
  }
}

function toggle(tag) {
  const next = new Set(open.value)
  next.has(tag) ? next.delete(tag) : next.add(tag)
  open.value = next
  const only = next.size === 1 ? [...next][0] : undefined
  router.replace({ query: { ...route.query, tag: only } })
}

const tags = computed(() => {
  const q = tagFilter.value.trim().toLowerCase()
  return (repo.value?.tags || []).filter((t) => !q || t.tag.toLowerCase().includes(q))
})

/** The scan summary a tag row shows: its own (single image) or the worst platform's. */
function rowScan(tag) {
  const images = tag.manifest.is_index
    ? tag.platforms.filter((p) => !p.attestation && p.manifest).map((p) => p.manifest)
    : [tag.manifest]
  const scanned = images.filter((m) => m.scan_status === 'scanned')
  const pending = images.some((m) => ['queued', 'scanning'].includes(m.scan_status))
  const blocked = images.find((m) => m.policy_block_reason)
  const worst = {}
  let kev = 0
  for (const m of scanned) {
    kev = Math.max(kev, m.kev_count || 0)
    for (const s of SEVERITIES) worst[s] = Math.max(worst[s] || 0, (m.severity_counts || {})[s] || 0)
  }
  const size = Math.max(0, ...images.map((m) => m.total_size || 0))
  return { scanned: scanned.length, total: images.length, pending, blocked, worst, kev, size }
}

async function update(payload, note) {
  message.value = null
  try {
    await api.dockerUpdateRepository(name.value, payload)
    message.value = note
    await load()
  } catch (err) {
    error.value = err.detail || 'Update failed.'
  }
}

function toggleQuarantine() {
  if (repo.value.quarantined) return update({ quarantined: false }, 'Quarantine lifted.')
  const reason = prompt('Why is this repository being quarantined? The reason is shown to anyone whose pull is refused.')
  if (reason === null) return
  return update({ quarantined: true, quarantine_reason: reason }, 'Repository quarantined; pulls are refused.')
}

function saveWatch() {
  const list = watchInput.value.split(',').map((t) => t.trim()).filter(Boolean)
  return update({ watched_tags: list }, list.length ? `Watching ${list.join(', ')}.` : 'No longer watching any tags.')
}

async function refresh(tag) {
  message.value = null
  try {
    const result = await api.dockerRefreshTag(name.value, tag)
    message.value = `${tag}: ${result.source}, ${result.layers_fetched} layers fetched, scans queued for ${result.platforms.join(', ') || 'the image'}.`
    generation.value++
    await load()
  } catch (err) {
    error.value = err.detail || 'Refresh failed.'
  }
}

watch(name, () => {
  open.value = new Set()
  load()
})
onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <div class="small dim"><router-link :to="{ name: 'images' }">Images</router-link> /</div>
      <h1 class="mono" style="word-break: break-all">{{ name }}</h1>
      <p v-if="repo" class="page-sub">
        <span v-if="repo.local" class="badge badge-accent">pushed here</span>
        <span v-else class="badge">cached from {{ repo.upstream }}</span>
        <span v-if="repo.quarantined" class="badge badge-danger">quarantined</span>
        <span v-if="repo.pinned" class="badge">pinned</span>
        <span class="faint small">
          · {{ repo.tags.length }} tag{{ repo.tags.length === 1 ? '' : 's' }} · {{ repo.pull_count }} pulls · last
          {{ relativeTime(repo.last_pulled_at || repo.last_pushed_at) }}
        </span>
      </p>
    </div>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-if="message" class="alert alert-ok">{{ message }}</div>
  <div v-if="loading && !repo" class="empty">Loading…</div>

  <template v-if="repo">
    <div v-if="repo.quarantined" class="alert alert-error">
      Pulls from this repository are refused<span v-if="repo.quarantine_reason">: {{ repo.quarantine_reason }}</span>.
    </div>

    <div v-if="auth.isAdmin" class="card admin-strip mb">
      <div class="admin-strip-body">
        <span class="admin-label">Administration</span>
        <button class="btn btn-sm" title="Exempt from storage eviction" @click="update({ pinned: !repo.pinned }, repo.pinned ? 'Unpinned.' : 'Pinned: exempt from eviction.')">
          {{ repo.pinned ? 'Unpin' : 'Pin' }}
        </button>
        <button
          class="btn btn-sm"
          :class="repo.quarantined ? '' : 'btn-danger'"
          title="Refuse every pull, with a reason shown to the client; recorded in the audit log"
          @click="toggleQuarantine"
        >
          {{ repo.quarantined ? 'Lift quarantine' : 'Quarantine' }}
        </button>
        <template v-if="!repo.local">
          <span class="admin-sep" />
          <label for="watch-tags" class="small dim nowrap" title="Revalidated, pre-fetched and rescanned hourly; never evicted">Watched tags</label>
          <input id="watch-tags" v-model="watchInput" class="watch-input" placeholder="3.12-slim, latest" @keyup.enter="saveWatch" />
          <button class="btn btn-sm" @click="saveWatch">Save</button>
        </template>
      </div>
    </div>

    <div class="image-layout">
      <div class="card tags-card">
        <div class="card-head">
          <h3>Tags</h3>
          <input
            v-if="repo.tags.length > 6"
            v-model="tagFilter"
            type="search"
            class="tag-filter"
            placeholder="Filter tags…"
          />
        </div>
        <div v-if="!repo.tags.length" class="empty">No tags cached yet.</div>
        <ul v-else class="tag-list">
          <li v-for="tag in tags" :key="tag.tag" :class="{ open: open.has(tag.tag) }">
            <div
              class="tag-row"
              role="button"
              tabindex="0"
              :aria-expanded="open.has(tag.tag)"
              @click="toggle(tag.tag)"
              @keydown.enter.prevent="toggle(tag.tag)"
              @keydown.space.prevent="toggle(tag.tag)"
            >
              <span class="chev" aria-hidden="true">›</span>
              <span class="tag-id">
                <span class="tag-name mono">{{ tag.tag }}</span>
                <span class="tag-digest mono faint" :title="tag.manifest.digest">{{ shortDigest(tag.manifest.digest) }}</span>
              </span>
              <span class="tag-platforms small">
                <template v-if="tag.manifest.is_index">
                  {{ tag.platforms.filter((p) => !p.attestation).length }}
                  platform{{ tag.platforms.filter((p) => !p.attestation).length === 1 ? '' : 's' }}
                </template>
                <template v-else>{{ tag.manifest.platform || 'single platform' }}</template>
              </span>
              <span class="tag-scan">
                <template v-for="s in [rowScan(tag)]" :key="'s'">
                  <span v-if="s.blocked" class="badge badge-danger" :title="s.blocked.policy_block_reason">blocked</span>
                  <template v-if="s.scanned">
                    <span v-if="s.kev" class="sev-mini kev" title="Known exploited (CISA KEV)">KEV {{ s.kev }}</span>
                    <span
                      v-for="sev in ['CRITICAL', 'HIGH', 'MEDIUM']"
                      v-show="s.worst[sev]"
                      :key="sev"
                      class="sev-mini"
                      :class="trivySeverityClass(sev)"
                      :title="`${sev.toLowerCase()} (worst platform)`"
                    >{{ sev[0] }} {{ s.worst[sev] }}</span>
                    <span v-if="!s.kev && !s.worst.CRITICAL && !s.worst.HIGH && !s.worst.MEDIUM" class="badge badge-ok">clean</span>
                  </template>
                  <span v-else-if="s.pending" class="badge badge-warn">scanning</span>
                  <span v-else class="faint small">not scanned</span>
                </template>
              </span>
              <span class="tag-size small faint nowrap">{{ rowScan(tag).size ? formatBytes(rowScan(tag).size) : '' }}</span>
              <span class="tag-checked faint small nowrap" :title="`Checked against the upstream ${relativeTime(tag.checked_at)}`">
                {{ relativeTime(tag.updated_at || tag.checked_at) }}
              </span>
              <span class="tag-actions" @click.stop>
                <button
                  v-if="auth.isAdmin && !repo.local"
                  class="btn btn-sm btn-ghost"
                  title="Revalidate upstream now, pre-fetch layers, queue scans"
                  @click="refresh(tag.tag)"
                >Refresh</button>
              </span>
            </div>
            <TagDetails
              v-if="open.has(tag.tag)"
              :key="`${tag.tag}:${tag.manifest.digest}:${generation}`"
              :repo="repo"
              :tag="tag"
              @message="(m) => (message = m)"
              @error="(e) => (error = e)"
            />
          </li>
        </ul>
        <div v-if="repo.tags.length && !tags.length" class="empty small">No tags match.</div>
      </div>

    </div>

    <div v-if="repo.digests?.length" class="card mt">
      <div class="card-head">
        <h3>Untagged digests</h3>
        <span class="faint small">{{ repo.digests.length }}</span>
      </div>
      <div class="card-body tight">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Digest</th><th>Kind</th><th>Platform</th><th>Scan</th><th class="num">Size</th><th>Last used</th></tr></thead>
            <tbody>
              <tr v-for="m in repo.digests" :key="m.digest">
                <td class="mono small" :title="m.digest">{{ shortDigest(m.digest) }}</td>
                <td class="small">{{ m.kind }}</td>
                <td class="small">{{ m.platform || '—' }}</td>
                <td class="small">{{ m.scan_status.replace('_', ' ') }}</td>
                <td class="num small">{{ formatBytes(m.total_size) }}</td>
                <td class="faint small">{{ relativeTime(m.last_accessed_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>
</template>

<style scoped>
/* The expanded tag needs the full width, so administration is a strip above
   the list rather than a sidebar beside it. */
.admin-strip-body {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 0.6rem;
  padding: 0.55rem 1rem;
}
.admin-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-faint);
  margin-right: 0.3rem;
}
.admin-sep {
  width: 1px;
  height: 1.4rem;
  background: var(--border);
  margin: 0 0.4rem;
}
/* The global input rule (six :not()s, specificity 0,6,1) sets width: 100%;
   only an id out-ranks it without !important. */
#watch-tags {
  width: 260px;
  height: 30px;
}
.tag-filter {
  width: 220px;
  height: 30px;
}
.tag-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.tag-list > li + li {
  border-top: 1px solid var(--border);
}
.tag-row {
  display: grid;
  grid-template-columns: 1rem minmax(8rem, 1fr) 7.5rem minmax(12rem, 18rem) 4.5rem 6.5rem 5.5rem;
  gap: 0.9rem;
  align-items: center;
  padding: 0.6rem 1rem;
  cursor: pointer;
  user-select: none;
}
.tag-row:hover {
  background: var(--surface-2);
}
.tag-row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
li.open > .tag-row {
  background: var(--accent-soft);
}
.chev {
  display: inline-block;
  color: var(--text-faint);
  font-size: 1.1rem;
  line-height: 1;
  transition: transform 0.12s ease;
}
li.open .chev {
  transform: rotate(90deg);
  color: var(--accent);
}
.tag-id {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.tag-name {
  font-weight: 650;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tag-digest {
  font-size: 0.74rem;
}
.tag-scan {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
  align-items: center;
}
.sev-mini {
  font-size: 0.76rem;
  font-weight: 650;
  padding: 0.05rem 0.42rem;
  border-radius: 999px;
  background: color-mix(in srgb, currentColor 12%, transparent);
  white-space: nowrap;
}
.sev-mini.kev {
  color: var(--critical);
  outline: 1px solid color-mix(in srgb, currentColor 45%, transparent);
}
.tag-actions {
  justify-self: end;
}

@media (max-width: 900px) {
  .tag-row {
    grid-template-columns: 1rem minmax(0, 1fr) auto auto;
  }
  .tag-platforms,
  .tag-size,
  .tag-checked {
    display: none;
  }
}
</style>
