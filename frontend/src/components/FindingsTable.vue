<script setup>
/**
 * Image findings as a table; a click on a row shows its detail (fix,
 * layer, advisory, and what the severity means).
 *
 * One severity is shown: the rating Trivy reports, which for OS packages is
 * the distribution's own (Debian, Alpine, ...) and is what image policy
 * enforces. NVD's CVSS score is often far higher for the same CVE, because
 * the distribution judged its own build; showing both side by side read as
 * a contradiction ("low · CVSS 9.8"), so the score is in the tooltip and
 * the detail, with that explanation.
 */
import { ref } from 'vue'
import { safeHttpUrl } from '@/utils/url'
import { shortDigest, trivySeverityClass } from '@/utils/format'

const props = defineProps({
  findings: { type: Array, required: true },
  layers: { type: Array, default: () => [] },
  showPackage: { type: Boolean, default: true },
  showFix: { type: Boolean, default: true },
})
const emit = defineEmits(['show-layer'])
const expanded = ref(null)

const keyOf = (f) => `${f.vuln_id}|${f.pkg_name}|${f.installed_version}`
const BANDS = [[9, 'CRITICAL'], [7, 'HIGH'], [4, 'MEDIUM'], [0.1, 'LOW']]
const RANK = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

function cvssBand(score) {
  return score == null ? null : (BANDS.find(([t]) => score >= t) || [0, 'LOW'])[1]
}
/** The distribution rated it at least a band below what CVSS says. */
function ratedDown(f) {
  const band = cvssBand(f.cvss)
  return band !== null && RANK[band] > (RANK[f.severity] ?? 0)
}
function severityTitle(f) {
  if (f.cvss == null) return `${f.severity.toLowerCase()}: the rating image policy uses`
  if (ratedDown(f))
    return `Rated ${f.severity.toLowerCase()} for this build (the rating image policy uses); NVD scores it CVSS ${f.cvss.toFixed(1)}`
  return `${f.severity.toLowerCase()}, CVSS ${f.cvss.toFixed(1)}`
}
function layerNumber(digest) {
  return props.layers.findIndex((l) => l.digest === digest) + 1 || '?'
}
const columns = 3 + (props.showPackage ? 2 : 0) + (props.showFix ? 1 : 0)
</script>

<template>
  <div class="table-wrap">
    <table class="ft-table">
      <thead>
        <tr>
          <th>Vulnerability</th>
          <th>Severity</th>
          <template v-if="showPackage"><th>Package</th><th>Installed</th></template>
          <th v-if="showFix">Fixed in</th>
          <th>Title</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="f in findings" :key="keyOf(f)">
          <tr
            class="clickable"
            tabindex="0"
            :aria-expanded="expanded === keyOf(f)"
            @click="expanded = expanded === keyOf(f) ? null : keyOf(f)"
            @keydown.enter.prevent="expanded = expanded === keyOf(f) ? null : keyOf(f)"
          >
            <td class="mono nowrap">
              {{ f.vuln_id }}
              <span v-if="f.kev" class="badge badge-danger" title="CISA Known Exploited Vulnerability">KEV</span>
              <span v-if="f.denied" class="badge badge-danger">denied</span>
              <span v-if="f.accepted" class="badge badge-warn">risk accepted</span>
            </td>
            <td class="nowrap">
              <span class="sev" :class="trivySeverityClass(f.severity)" :title="severityTitle(f)">
                {{ f.severity.toLowerCase() }}<span v-if="ratedDown(f)" class="rated" aria-hidden="true">*</span>
              </span>
            </td>
            <template v-if="showPackage">
              <td class="mono small">{{ f.pkg_name }}</td>
              <td class="mono small">{{ f.installed_version || '—' }}</td>
            </template>
            <td v-if="showFix" class="mono small" :class="{ 'fix-available': f.fixed_version }">{{ f.fixed_version || '—' }}</td>
            <td class="small ft-title"><div class="truncate" :title="f.title">{{ f.title || '—' }}</div></td>
          </tr>
          <tr v-if="expanded === keyOf(f)" class="ft-subrow">
            <td :colspan="columns">
              <div class="detail-grid small">
                <span class="dim">Title</span><span>{{ f.title || '—' }}</span>
                <span class="dim">Package</span><span class="mono">{{ f.pkg_name }} {{ f.installed_version }} ({{ f.pkg_type }})</span>
                <span class="dim">Severity</span>
                <span>
                  {{ f.severity.toLowerCase() }}<template v-if="f.cvss != null"> · CVSS {{ f.cvss.toFixed(1) }}</template>
                  <div v-if="ratedDown(f)" class="faint">
                    The advisory for this package<template v-if="f.pkg_type"> ({{ f.pkg_type }})</template> rates it
                    lower than NVD's score, usually because the build shipped here is not affected the same way.
                    Image policy uses that rating.
                  </div>
                </span>
                <span class="dim">Fix</span>
                <span>
                  <template v-if="f.fixed_version">Upgrade to <span class="mono">{{ f.fixed_version }}</span>, usually by rebuilding on a newer base image.</template>
                  <template v-else>No fixed version published yet.</template>
                </span>
                <span class="dim">Introduced in</span>
                <span class="mono">
                  <template v-if="f.layer_digest">
                    layer {{ layerNumber(f.layer_digest) }} · {{ shortDigest(f.layer_digest) }}
                    <a href="#" class="small" @click.prevent="emit('show-layer', f.layer_digest)">show layer</a>
                  </template>
                  <template v-else>—</template>
                </span>
                <span class="dim">Advisory</span>
                <span><a v-if="safeHttpUrl(f.url)" :href="safeHttpUrl(f.url)" target="_blank" rel="noopener noreferrer">{{ f.url }}</a><template v-else>{{ f.url || '—' }}</template></span>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.ft-table {
  width: 100%;
  background: var(--surface);
}
/* The title is the only column that may give: it truncates (full text is
   one click away) so the table never runs off the card. */
.ft-title {
  width: 100%;
  max-width: 0;
}
.fix-available {
  color: var(--ok);
}
tr.clickable {
  cursor: pointer;
}
tr.clickable:hover td,
tr.clickable:focus-visible td {
  background: var(--surface-2);
  outline: none;
}
.ft-subrow td {
  background: var(--surface-2);
  padding: 0.7rem 1rem 0.9rem;
}
.detail-grid {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 0.35rem 1rem;
  align-items: baseline;
}
.detail-grid > span {
  overflow-wrap: anywhere;
}
.rated {
  margin-left: 1px;
  opacity: 0.7;
}
.badge {
  margin-left: 0.3rem;
}
</style>
