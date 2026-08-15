<script setup>
/**
 * The minireg mark: an isometric package, drawn as three faces of a box.
 *
 * A package cube reads instantly at 24px and stays ecosystem-neutral, which
 * matters here because the registry serves npm and PyPI equally -- borrowing
 * either one's iconography would misrepresent what this is.
 */
defineProps({
  size: { type: Number, default: 26 },
  // Draws the tile behind the glyph. Off when the mark sits on its own.
  tile: { type: Boolean, default: true },
})
</script>

<template>
  <span
    class="brand-mark"
    :class="{ 'brand-mark-plain': !tile }"
    :style="{
      width: `${size}px`,
      height: `${size}px`,
      borderRadius: `${Math.round(size * 0.26)}px`,
    }"
    aria-hidden="true"
  >
    <svg
      :width="Math.round(size * 0.62)"
      :height="Math.round(size * 0.62)"
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <!-- Top face, catching the light. -->
      <path d="M16 2.5 L29 9.75 L16 17 L3 9.75 Z" fill="currentColor" fill-opacity="0.95" />
      <!-- Right face. -->
      <path d="M29 9.75 L29 22.25 L16 29.5 L16 17 Z" fill="currentColor" fill-opacity="0.72" />
      <!-- Left face, furthest from the light. -->
      <path d="M3 9.75 L3 22.25 L16 29.5 L16 17 Z" fill="currentColor" fill-opacity="0.5" />
      <!-- Lid seam: the detail that turns a cube into a package. -->
      <path
        d="M9.5 6.1 L22.5 13.4"
        stroke="currentColor"
        stroke-opacity="0.45"
        stroke-width="1.4"
        stroke-linecap="round"
      />
    </svg>
  </span>
</template>

<style scoped>
.brand-mark {
  display: inline-grid;
  place-items: center;
  flex: none;
  background: linear-gradient(135deg, var(--accent), var(--pypi));
  color: #fff;
  box-shadow: 0 1px 2px rgba(16, 24, 40, 0.18);
}

/* Untiled: the glyph inherits the surrounding text colour. */
.brand-mark-plain {
  background: none;
  box-shadow: none;
  color: var(--accent);
}
</style>
