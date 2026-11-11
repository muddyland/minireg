<script setup>
/**
 * One image repository, as two pages:
 *
 * - the repository (no ?tag=): its tags as a list, one row each with
 *   platforms, worst findings, size and age, plus untagged digests;
 * - one tag (?tag=1.27): everything about that image (TagDetails).
 *
 * Tags used to expand inline; with a platform picker, a pull command, five
 * tabs and up to a thousand findings inside a list row the page ran to tens
 * of thousands of pixels and lost its place. The query parameter keeps old
 * ?tag= links working, and the back button returns to the list.
 *
 * Administration (pin, quarantine, watched tags, refresh, rescans) is in
 * the ⋯ menu in the header: needed now and then, not on every visit.
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api/client'
import ActionMenu from '@/components/ActionMenu.vue'
import TagDetails from '@/components/TagDetails.vue'
import { useAuthStore } from '@/stores/auth'
import { errorMessage } from '@/utils/errors'
import { SEVERITIES, formatBytes, relativeTime, shortDigest, trivySeverityClass } from '@/utils/format'

const route = useRoute()
const auth = useAuthStore()
const name = computed(() => route.params.name)
const selectedTag = computed(() => (route.query.tag ? String(route.query.tag) : null))

const repo = ref(null)
const loading = ref(true)
const error = ref(null)
const message = ref(null)
const updating = ref(false)
const tagFilter = ref('')
// Bumped after a refresh or rescan so the tag page reloads its data.
const generation = ref(0)
// The platform shown on the tag page; kept here so a reload keeps it.
const platformDigest = ref(null)

const currentTag = computed(() => repo.value?.tags.find((t) => t.tag === selectedTag.value) || null)
const watched = computed(() => new Set(repo.value?.watched_tags || []))

async function load() {
  loading.value = true
  error.value = null
  try {
    repo.value = await api.dockerRepository(name.value)
  } catch (err) {
    error.value =
      err.status === 404
        ? 'This repository has not been pulled or pushed yet.'
        : errorMessage(err, 'Could not load this repository.')
  } finally {
    loading.value = false
  }
}

const tagLink = (tag) => ({ name: 'image', params: { name: name.value }, query: { tag } })
const repoLink = computed(() => ({ name: 'image', params: { name: name.value } }))

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
const platformCount = (tag) => tag.platforms.filter((p) => !p.attestation).length

// Attestations (BuildKit provenance/SBOM) are recorded, never scanned or
// run; listed among untagged digests they were half the table.
const showAttestations = ref(false)
const attestationCount = computed(() => (repo.value?.digests || []).filter((m) => m.kind === 'attestation').length)
const digests = computed(() =>
  (repo.value?.digests || []).filter((m) => showAttestations.value || m.kind !== 'attestation'),
)

// -- admin actions ------------------------------------------------------------
async function update(payload, note) {
  message.value = null
  error.value = null
  updating.value = true
  try {
    await api.dockerUpdateRepository(name.value, payload)
  } catch (err) {
    error.value = errorMessage(err, 'Update failed.')
    return false
  } finally {
    updating.value = false
  }
  message.value = note
  await load()
  return true
}

// Quarantining asks for the reason pulls are refused with, in a dialog.
const quarantineOpen = ref(false)
const quarantineReason = ref('')
const quarantineError = ref(null)
const quarantining = ref(false)

function toggleQuarantine() {
  if (repo.value.quarantined) return update({ quarantined: false }, 'Quarantine lifted.')
  quarantineReason.value = ''
  quarantineError.value = null
  quarantineOpen.value = true
}

async function confirmQuarantine() {
  quarantineError.value = null
  quarantining.value = true
  try {
    await api.dockerUpdateRepository(name.value, {
      quarantined: true,
      quarantine_reason: quarantineReason.value.trim(),
    })
  } catch (err) {
    quarantineError.value = errorMessage(err, 'Could not quarantine this repository.')
    return
  } finally {
    quarantining.value = false
  }
  quarantineOpen.value = false
  message.value = 'Repository quarantined; pulls are refused.'
  await load()
}

const watchOpen = ref(false)
const watchInput = ref('')
function editWatched() {
  watchInput.value = (repo.value.watched_tags || []).join(', ')
  watchOpen.value = true
}
async function saveWatch() {
  const list = watchInput.value.split(',').map((t) => t.trim()).filter(Boolean)
  if (await update({ watched_tags: list }, list.length ? `Watching ${list.join(', ')}.` : 'No longer watching any tags.')) {
    watchOpen.value = false
  }
}
function toggleWatchTag(tag) {
  const list = [...watched.value]
  const next = watched.value.has(tag) ? list.filter((t) => t !== tag) : [...list, tag]
  return update(
    { watched_tags: next },
    watched.value.has(tag) ? `Stopped watching ${tag}.` : `Watching ${tag}: revalidated, pre-fetched and rescanned hourly, never evicted.`,
  )
}

async function refresh(tag) {
  message.value = null
  error.value = null
  updating.value = true
  try {
    const result = await api.dockerRefreshTag(name.value, tag)
    message.value = `${tag}: ${result.source}, ${result.layers_fetched} layers fetched, scans queued for ${result.platforms.join(', ') || 'the image'}.`
  } catch (err) {
    error.value = errorMessage(err, `Could not refresh ${tag}.`)
    return
  } finally {
    updating.value = false
  }
  generation.value++
  await load()
}

async function rescan(full) {
  message.value = null
  error.value = null
  try {
    const result = await api.dockerRescan(platformDigest.value, full)
    message.value = result.queued
      ? `Rescan queued (${result.mode === 'sbom' ? 'against the stored SBOM, no image pull' : 'full image scan'}).`
      : 'A scan is already queued for this image.'
  } catch (err) {
    error.value = errorMessage(err, 'Could not queue a rescan.')
    return
  }
  generation.value++
}

watch(name, () => {
  repo.value = null
  load()
})
watch(selectedTag, () => {
  platformDigest.value = null
  message.value = null
  error.value = null
})
onMounted(load)
</script>

<template>
  <div class="page-head">
    <div class="ph-main">
      <div class="small dim crumbs">
        <router-link :to="{ name: 'images' }">Images</router-link> /
        <template v-if="selectedTag">
          <router-link class="mono" :to="repoLink">{{ name }}</router-link> /
        </template>
      </div>
      <h1 class="mono ph-title">
        <template v-if="selectedTag">{{ name.split('/').pop() }}<span class="tag-colon">:</span>{{ selectedTag }}</template>
        <template v-else>{{ name }}</template>
      </h1>
      <p v-if="repo" class="page-sub">
        <span v-if="repo.local" class="badge badge-accent">pushed here</span>
        <span v-else class="badge">cached from {{ repo.upstream }}</span>
        <span v-if="repo.quarantined" class="badge badge-danger">quarantined</span>
        <span v-if="repo.pinned" class="badge" title="Exempt from storage eviction">pinned</span>
        <template v-if="currentTag">
          <span v-if="watched.has(currentTag.tag)" class="badge" title="Revalidated, pre-fetched and rescanned hourly; never evicted">watched</span>
          <span class="faint small">
            · updated {{ relativeTime(currentTag.updated_at || currentTag.checked_at) }}
            <template v-if="!repo.local && currentTag.checked_at"> · checked against {{ repo.upstream }} {{ relativeTime(currentTag.checked_at) }}</template>
          </span>
        </template>
        <span v-else class="faint small">
          · {{ repo.tags.length }} tag{{ repo.tags.length === 1 ? '' : 's' }} · {{ repo.pull_count }} pulls · last
          {{ relativeTime(repo.last_pulled_at || repo.last_pushed_at) }}
          <template v-if="repo.watched_tags?.length"> · watching {{ repo.watched_tags.join(', ') }}</template>
        </span>
      </p>
    </div>

    <ActionMenu v-if="auth.isAdmin && repo" label="Image actions">
      <template v-if="currentTag">
        <button v-if="!repo.local" class="menu-item" role="menuitem" :disabled="updating" @click="refresh(currentTag.tag)">
          Refresh from upstream
          <span class="menu-hint">Revalidate the tag, pre-fetch its layers, queue scans</span>
        </button>
        <button class="menu-item" role="menuitem" :disabled="!platformDigest" @click="rescan(false)">
          Rescan
          <span class="menu-hint">Match the stored SBOM against today's vulnerability database</span>
        </button>
        <button class="menu-item" role="menuitem" :disabled="!platformDigest" @click="rescan(true)">
          Full rescan
          <span class="menu-hint">Pull and scan this platform again from scratch</span>
        </button>
        <button v-if="!repo.local" class="menu-item" role="menuitem" :disabled="updating" @click="toggleWatchTag(currentTag.tag)">
          {{ watched.has(currentTag.tag) ? 'Stop watching this tag' : 'Watch this tag' }}
          <span class="menu-hint">Revalidated, pre-fetched and rescanned hourly; never evicted</span>
        </button>
        <hr class="menu-sep" />
      </template>
      <button
        class="menu-item"
        role="menuitem"
        :disabled="updating"
        @click="update({ pinned: !repo.pinned }, repo.pinned ? 'Unpinned.' : 'Pinned: exempt from eviction.')"
      >
        {{ repo.pinned ? 'Unpin repository' : 'Pin repository' }}
        <span class="menu-hint">Exempt every tag from storage eviction</span>
      </button>
      <button v-if="!repo.local" class="menu-item" role="menuitem" @click="editWatched">Edit watched tags…</button>
      <hr class="menu-sep" />
      <button class="menu-item" :class="{ danger: !repo.quarantined }" role="menuitem" :disabled="updating" @click="toggleQuarantine">
        {{ repo.quarantined ? 'Lift quarantine' : 'Quarantine repository…' }}
        <span v-if="!repo.quarantined" class="menu-hint">Refuse every pull, with a reason; recorded in the audit log</span>
      </button>
    </ActionMenu>
  </div>

  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
  <div v-if="message" class="alert alert-ok" role="status">{{ message }}</div>
  <div v-if="loading && !repo" class="empty">Loading…</div>

  <template v-if="repo">
    <div v-if="repo.quarantined" class="alert alert-error">
      Pulls from this repository are refused<span v-if="repo.quarantine_reason">: {{ repo.quarantine_reason }}</span>.
    </div>

    <!-- one tag -->
    <template v-if="selectedTag">
      <div v-if="!currentTag" class="card">
        <div class="empty">
          Tag <span class="mono">{{ selectedTag }}</span> is not cached in this repository.
          <router-link :to="repoLink">See its tags</router-link>
        </div>
      </div>
      <TagDetails
        v-else
        :key="`${currentTag.tag}:${currentTag.manifest.digest}:${generation}`"
        v-model:digest="platformDigest"
        :repo="repo"
        :tag="currentTag"
      />
    </template>

    <!-- the repository -->
    <template v-else>
      <div class="card tags-card">
        <div class="card-head">
          <h3>Tags</h3>
          <input
            v-if="repo.tags.length > 6"
            id="tag-filter"
            v-model="tagFilter"
            type="search"
            placeholder="Filter tags…"
            aria-label="Filter tags"
          />
        </div>
        <div v-if="!repo.tags.length" class="empty">No tags cached yet.</div>
        <ul v-else class="tag-list">
          <li v-for="tag in tags" :key="tag.tag">
            <router-link class="tag-row" :to="tagLink(tag.tag)">
              <span class="tag-id">
                <span class="tag-name mono">
                  {{ tag.tag }}
                  <span v-if="watched.has(tag.tag)" class="badge watched" title="Revalidated, pre-fetched and rescanned hourly; never evicted">watched</span>
                </span>
                <span class="tag-digest mono faint" :title="tag.manifest.digest">{{ shortDigest(tag.manifest.digest) }}</span>
              </span>
              <span class="tag-platforms small">
                <template v-if="tag.manifest.is_index">{{ platformCount(tag) }} platform{{ platformCount(tag) === 1 ? '' : 's' }}</template>
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
              <span class="chev" aria-hidden="true">›</span>
            </router-link>
          </li>
        </ul>
        <div v-if="repo.tags.length && !tags.length" class="empty small">No tags match.</div>
      </div>

      <div v-if="repo.digests?.length" class="card mt">
        <div class="card-head">
          <h3>Untagged digests</h3>
          <label v-if="attestationCount" class="check small" style="margin: 0" title="BuildKit provenance and SBOM attestations: recorded, not scanned">
            <input v-model="showAttestations" type="checkbox" /> Show {{ attestationCount }} attestation{{ attestationCount === 1 ? '' : 's' }}
          </label>
        </div>
        <div v-if="!digests.length" class="empty small">
          Only attestations: build records attached to images, recorded but never scanned or run.
        </div>
        <div v-else class="card-body tight">
          <div class="table-wrap">
            <table>
              <thead><tr><th>Digest</th><th>Kind</th><th>Platform</th><th>Scan</th><th class="num">Size</th><th>Last used</th></tr></thead>
              <tbody>
                <tr v-for="m in digests" :key="m.digest">
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

  <div v-if="watchOpen" class="modal-backdrop" @click.self="watchOpen = false" @keydown.esc="watchOpen = false">
    <form class="modal" role="dialog" aria-modal="true" aria-labelledby="watch-title" @submit.prevent="saveWatch">
      <div class="modal-head">
        <h3 id="watch-title">Watched tags</h3>
        <button type="button" class="btn btn-sm btn-ghost" aria-label="Close" @click="watchOpen = false">✕</button>
      </div>
      <div class="modal-body">
        <div class="field">
          <label for="watch-tags">Tags, comma separated</label>
          <input id="watch-tags" v-model="watchInput" placeholder="3.12-slim, latest" autofocus />
          <p class="field-hint">Watched tags are revalidated against the upstream, pre-fetched and rescanned every hour, and never evicted.</p>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn" @click="watchOpen = false">Cancel</button>
        <button type="submit" class="btn btn-primary" :disabled="updating">Save</button>
      </div>
    </form>
  </div>

  <div
    v-if="quarantineOpen"
    class="modal-backdrop"
    @click.self="quarantineOpen = false"
    @keydown.esc="quarantineOpen = false"
  >
    <form
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="quarantine-title"
      @submit.prevent="confirmQuarantine"
    >
      <div class="modal-head">
        <h3 id="quarantine-title">Quarantine repository</h3>
        <button type="button" class="btn btn-sm btn-ghost" aria-label="Close" @click="quarantineOpen = false">✕</button>
      </div>
      <div class="modal-body">
        <div v-if="quarantineError" class="alert alert-error" role="alert">{{ quarantineError }}</div>
        <p class="small dim" style="margin-top: 0">
          Every pull from <span class="mono">{{ name }}</span> is refused until the quarantine is lifted.
          The change is recorded in the audit log.
        </p>
        <div class="field">
          <label for="quarantine-reason">Reason</label>
          <input
            id="quarantine-reason"
            v-model="quarantineReason"
            placeholder="e.g. compromised upstream tag, under investigation"
            autofocus
          />
          <p class="field-hint">Shown to anyone whose pull is refused.</p>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn" @click="quarantineOpen = false">Cancel</button>
        <button type="submit" class="btn btn-danger" :disabled="quarantining">
          {{ quarantining ? 'Quarantining…' : 'Quarantine' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.ph-main {
  min-width: 0;
  flex: 1;
}
/* .mono shrinks text to 0.86em of its parent, which made a mono h1 smaller
   than the breadcrumb; set the heading size explicitly. */
.ph-title {
  font-size: 1.45rem;
  word-break: break-all;
}
.tag-colon {
  color: var(--text-faint);
  margin: 0 0.05em;
}
.crumbs a.mono {
  word-break: break-all;
}
/* The global input rule (six :not()s, specificity 0,6,1) sets width: 100%;
   only an id out-ranks it without !important. */
#tag-filter {
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
  grid-template-columns: minmax(8rem, 1fr) 7.5rem minmax(12rem, 18rem) 4.5rem 6.5rem 1rem;
  gap: 0.9rem;
  align-items: center;
  padding: 0.6rem 1rem;
  color: inherit;
  text-decoration: none;
}
.tag-row:hover {
  background: var(--surface-2);
  text-decoration: none;
}
.tag-row:hover .chev {
  color: var(--accent);
  transform: translateX(2px);
}
.tag-row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
.chev {
  color: var(--text-faint);
  font-size: 1.1rem;
  line-height: 1;
  justify-self: end;
  transition: transform 0.12s ease;
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
.badge.watched {
  font-family: var(--font-sans, inherit);
  font-weight: 500;
  margin-left: 0.35rem;
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

@media (max-width: 900px) {
  .tag-row {
    grid-template-columns: minmax(0, 1fr) auto 1rem;
  }
  .tag-platforms,
  .tag-size,
  .tag-checked {
    display: none;
  }
}
</style>
