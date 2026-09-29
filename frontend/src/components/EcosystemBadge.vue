<script setup>
/**
 * The ecosystem pill shown next to every package, advisory, rule and
 * upstream: brand mark plus name, in the ecosystem's colour. An empty
 * ecosystem renders a neutral "all" pill (policy rules that apply
 * everywhere).
 */
import EcosystemIcon from '@/components/EcosystemIcon.vue'
import { ecosystemBadge, ecosystemLabel } from '@/utils/format'

defineProps({
  ecosystem: { type: String, default: '' },
  // Shown instead of the ecosystem name when set.
  label: { type: String, default: '' },
})
</script>

<template>
  <span class="badge" :class="ecosystem ? ecosystemBadge(ecosystem) : ''">
    <EcosystemIcon v-if="ecosystem" :ecosystem="ecosystem" :size="11" />
    {{ label || (ecosystem ? ecosystemLabel(ecosystem) : 'all') }}
  </span>
</template>
