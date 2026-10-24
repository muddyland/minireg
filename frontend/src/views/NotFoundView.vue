<script setup>
/**
 * Unknown routes used to redirect silently to Home, so a mistyped or stale
 * link looked like the app had ignored the click.
 */
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Page not found</h1>
      <p class="page-sub">
        Nothing lives at <code>{{ route.fullPath }}</code>. The link may be mistyped or out of date.
      </p>
    </div>
  </div>
  <div class="row">
    <router-link class="btn btn-primary" :to="{ name: 'home' }">Go to Home</router-link>
    <router-link class="btn" :to="{ name: 'search' }">Search packages</router-link>
    <router-link class="btn" :to="{ name: 'help' }">Documentation</router-link>
  </div>
</template>
