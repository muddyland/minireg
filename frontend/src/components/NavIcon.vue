<script setup>
/**
 * The sidebar icon set.
 *
 * These were Unicode glyphs (⌕ ⚙ ⚿ ▦), which pick a different font on every
 * platform and land on different baselines and widths. Inline SVG on a shared
 * 24-unit grid keeps them optically consistent everywhere.
 */
defineProps({
  name: { type: String, required: true },
  size: { type: Number, default: 17 },
})

const PATHS = {
  search: ['M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z', 'M16.2 16.2 20.5 20.5'],
  help: [
    'M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17z',
    'M9.6 9.4a2.5 2.5 0 1 1 3.3 2.4c-.6.2-.9.7-.9 1.3v.6',
    'M12 16.8h.01',
  ],
  setup: ['M4 7h10', 'M18 7h2', 'M4 17h4', 'M12 17h8', 'M16 4.5v5', 'M8 14.5v5'],
  key: [
    'M15.5 4a4.5 4.5 0 1 1-3.1 7.75L4.5 19.6V21H7v-2h2v-2h2l1.4-1.4A4.5 4.5 0 0 1 15.5 4z',
    'M17 8.2h.01',
  ],
  dashboard: ['M4 20V12', 'M9.3 20V5', 'M14.7 20v-6', 'M20 20V9'],
  upstreams: ['M12 3v11', 'M8 10.5 12 14.5 16 10.5', 'M4 17.5v1.5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-1.5'],
  shield: ['M12 3 5 6v5.5c0 4.2 2.9 7.9 7 9.5 4.1-1.6 7-5.3 7-9.5V6l-7-3z'],
  alert: ['M12 4 2.8 20h18.4L12 4z', 'M12 10v4.2', 'M12 17.3h.01'],
  package: [
    'M12 3 20.5 7.75 12 12.5 3.5 7.75 12 3z',
    'M20.5 7.75v8.5L12 21v-8.5',
    'M3.5 7.75v8.5L12 21',
  ],
  storage: [
    'M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3z',
    'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6',
    'M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  ],
  users: [
    'M9 11.5a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5z',
    'M2.5 20.5a6.5 6.5 0 0 1 13 0',
    'M16.5 4.6a3.75 3.75 0 0 1 0 6.9',
    'M18 14.2a6.5 6.5 0 0 1 3.5 5.8',
  ],
  audit: ['M6 3h9l3.5 3.5V21H6V3z', 'M14.6 3v4h4', 'M9 12h6', 'M9 16h6'],
  account: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M4.5 20.5a7.5 7.5 0 0 1 15 0'],
  terminal: ['M3.5 4.5h17v15h-17z', 'M7 9.5l3 2.5-3 2.5', 'M13 15h4'],
  eye: ['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z', 'M12 14.6a2.6 2.6 0 1 0 0-5.2 2.6 2.6 0 0 0 0 5.2z'],
  'eye-off': [
    'M9.9 5.8A8.6 8.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a15.7 15.7 0 0 1-3 3.8',
    'M6.4 7.7A15.6 15.6 0 0 0 2.5 12S6 18.5 12 18.5c1.4 0 2.7-.35 3.8-.9',
    'M10.2 10.3a2.6 2.6 0 0 0 3.6 3.7',
    'M4 4l16 16',
  ],
}
</script>

<template>
  <svg
    class="nav-icon"
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.7"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path v-for="(d, index) in PATHS[name] || []" :key="index" :d="d" />
  </svg>
</template>

<style scoped>
.nav-icon {
  flex: none;
  opacity: 0.9;
}
</style>
