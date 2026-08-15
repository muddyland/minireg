<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'
import { formatBytes, formatNumber, percent } from '@/utils/format'

const stats = ref(null)
const loading = ref(true)
const message = ref(null)
const busy = ref(false)

const purgeOptions = ref({ ecosystem: '', older_than_days: 30, unused_only: true })

const diskUsed = computed(() =>
  stats.value ? percent(stats.value.disk.used, stats.value.disk.total) : 0,
)
const dedupeRatio = computed(() => {
  if (!stats.value?.blobs.logical_bytes) return 0
  return percent(stats.value.blobs.deduplicated_bytes, stats.value.blobs.logical_bytes)
})

async function load() {
  loading.value = true
  stats.value = await api.storageStats()
  loading.value = false
}

async function purge() {
  const scope = purgeOptions.value.unused_only ? 'never-downloaded' : 'all eligible'
  if (
    !confirm(
      `Evict ${scope} cached artifacts older than ${purgeOptions.value.older_than_days} days? ` +
        'Locally published files are never evicted. Anything removed re-downloads on next request.',
    )
  )
    return

  busy.value = true
  try {
    const result = await api.purgeCache({
      ecosystem: purgeOptions.value.ecosystem || undefined,
      older_than_days: purgeOptions.value.older_than_days || undefined,
      unused_only: purgeOptions.value.unused_only,
    })
    message.value = `Purged ${result.files_purged} files, freeing ${formatBytes(result.bytes_freed)}.`
    await load()
  } finally {
    busy.value = false
  }
}

async function gc() {
  busy.value = true
  try {
    const result = await api.garbageCollect()
    message.value = `Removed ${result.orphan_blobs_removed} orphaned blobs and ${result.tmp_files_removed} stale temp files.`
    await load()
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Storage</h1>
      <p class="page-sub">
        Artifacts are content-addressed, so identical files across packages and ecosystems are
        stored once.
      </p>
    </div>
    <button class="btn" :disabled="busy" @click="gc">Run garbage collection</button>
  </div>

  <div v-if="message" class="alert alert-ok">{{ message }}</div>
  <div v-if="loading" class="empty">Loading…</div>

  <template v-else-if="stats">
    <div class="grid grid-4 mb">
      <div class="card stat">
        <div class="stat-label">Cached artifacts</div>
        <div class="stat-value">{{ formatNumber(stats.blobs.count) }}</div>
        <div class="stat-meta">{{ formatNumber(stats.blobs.total_accesses) }} total reads</div>
      </div>
      <div class="card stat">
        <div class="stat-label">Physical size</div>
        <div class="stat-value">{{ formatBytes(stats.blobs.physical_bytes) }}</div>
        <div class="stat-meta">on disk after deduplication</div>
      </div>
      <div class="card stat">
        <div class="stat-label">Saved by dedup</div>
        <div class="stat-value">{{ formatBytes(stats.blobs.deduplicated_bytes) }}</div>
        <div class="stat-meta">{{ dedupeRatio }}% of logical size</div>
      </div>
      <div class="card stat">
        <div class="stat-label">Disk free</div>
        <div class="stat-value">{{ formatBytes(stats.disk.free) }}</div>
        <div class="stat-meta">of {{ formatBytes(stats.disk.total) }} total</div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-head"><h3>Volume usage</h3></div>
        <div class="card-body">
          <div class="row" style="justify-content: space-between; margin-bottom: 0.4rem">
            <span class="small dim">{{ formatBytes(stats.disk.used) }} used</span>
            <span class="small dim">{{ diskUsed }}%</span>
          </div>
          <div class="meter">
            <div
              class="meter-fill"
              :class="diskUsed > 90 ? 'danger' : diskUsed > 75 ? 'warn' : ''"
              :style="{ width: `${diskUsed}%` }"
            />
          </div>
          <p v-if="diskUsed > 85" class="alert alert-warn small mt">
            The storage volume is nearly full. Purge unused artifacts or grow the volume.
          </p>

          <h4 class="small mt">By ecosystem</h4>
          <div v-if="!stats.by_ecosystem.length" class="faint small">Nothing cached yet.</div>
          <div v-else class="bars">
            <div v-for="row in stats.by_ecosystem" :key="row.ecosystem" class="bar-row">
              <span class="small">
                <span class="badge" :class="row.ecosystem === 'npm' ? 'badge-npm' : 'badge-pypi'">
                  {{ row.ecosystem }}
                </span>
                {{ formatNumber(row.files) }} files
              </span>
              <div class="bar-track">
                <div
                  class="bar-fill"
                  :class="row.ecosystem"
                  :style="{
                    width: `${percent(row.bytes, Math.max(...stats.by_ecosystem.map((r) => r.bytes)))}%`,
                  }"
                />
              </div>
              <span class="small nowrap faint">{{ formatBytes(row.bytes) }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>Cache eviction</h3></div>
        <div class="card-body">
          <p class="dim small mb">
            Evicted artifacts are re-downloaded from their upstream on the next request. Files
            published directly to this registry are never evicted — there is nowhere to fetch them
            from.
          </p>

          <div class="field">
            <label>Ecosystem</label>
            <select v-model="purgeOptions.ecosystem">
              <option value="">Both</option>
              <option value="npm">npm only</option>
              <option value="pypi">PyPI only</option>
            </select>
          </div>
          <div class="field">
            <label>Cached more than (days ago)</label>
            <input v-model.number="purgeOptions.older_than_days" type="number" min="1" />
          </div>
          <label class="check mb">
            <input v-model="purgeOptions.unused_only" type="checkbox" />
            Only artifacts that were never downloaded
          </label>

          <button class="btn btn-danger" :disabled="busy" @click="purge">
            {{ busy ? 'Working…' : 'Purge cached artifacts' }}
          </button>

          <hr style="border: none; border-top: 1px solid var(--border); margin: 1.1rem 0" />
          <h4 class="small">On-disk detail</h4>
          <div class="row small" style="justify-content: space-between">
            <span class="dim">Blob files on disk</span>
            <span>{{ formatNumber(stats.disk.blob_files_on_disk) }}</span>
          </div>
          <div class="row small" style="justify-content: space-between">
            <span class="dim">Bytes on disk</span>
            <span>{{ formatBytes(stats.disk.blob_bytes_on_disk) }}</span>
          </div>
          <div class="row small" style="justify-content: space-between">
            <span class="dim">Logical size (all references)</span>
            <span>{{ formatBytes(stats.blobs.logical_bytes) }}</span>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>
