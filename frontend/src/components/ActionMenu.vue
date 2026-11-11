<script setup>
/**
 * A "⋯" button with a drop-down of actions, for controls that are needed
 * now and then (pin, quarantine, rescan) and should not crowd the page.
 *
 * Items go in the default slot as <button class="menu-item">; a click on any
 * of them closes the menu. <hr class="menu-sep"> separates groups.
 * Closes on Escape and on a click outside; arrow keys move between items.
 */
import { nextTick, onBeforeUnmount, ref } from 'vue'

defineProps({
  label: { type: String, default: 'More actions' },
})

const open = ref(false)
const root = ref(null)
const list = ref(null)

function items() {
  return [...(list.value?.querySelectorAll('.menu-item:not([disabled])') || [])]
}

async function toggle() {
  open.value = !open.value
  if (open.value) {
    document.addEventListener('pointerdown', onOutside, true)
    await nextTick()
    items()[0]?.focus()
  } else {
    close()
  }
}

function close(refocus = false) {
  open.value = false
  document.removeEventListener('pointerdown', onOutside, true)
  if (refocus) root.value?.querySelector('.menu-trigger')?.focus()
}

function onOutside(event) {
  if (!root.value?.contains(event.target)) close()
}

function onKey(event) {
  if (event.key === 'Escape') {
    event.preventDefault()
    close(true)
    return
  }
  if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
  event.preventDefault()
  const all = items()
  const at = all.indexOf(document.activeElement)
  const next = event.key === 'ArrowDown' ? (at + 1) % all.length : (at - 1 + all.length) % all.length
  all[next]?.focus()
}

function onClick(event) {
  if (event.target.closest('.menu-item')) close(true)
}

onBeforeUnmount(() => document.removeEventListener('pointerdown', onOutside, true))
</script>

<template>
  <div ref="root" class="action-menu" @keydown="onKey">
    <button
      type="button"
      class="btn btn-sm menu-trigger"
      :aria-label="label"
      :title="label"
      aria-haspopup="menu"
      :aria-expanded="open"
      @click="toggle"
    >
      <span aria-hidden="true">⋯</span>
    </button>
    <div v-if="open" ref="list" class="menu-list" role="menu" @click="onClick">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.action-menu {
  position: relative;
  display: inline-block;
}
.menu-trigger {
  min-width: 2.2rem;
  font-size: 1.05rem;
  line-height: 1;
  letter-spacing: 0.05em;
}
.menu-list {
  position: absolute;
  right: 0;
  top: calc(100% + 4px);
  z-index: 30;
  min-width: 15rem;
  padding: 0.3rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  box-shadow: 0 8px 24px rgb(0 0 0 / 0.14);
}
.menu-list :slotted(.menu-item) {
  display: block;
  width: 100%;
  padding: 0.45rem 0.7rem;
  border: none;
  border-radius: 6px;
  background: none;
  color: var(--text);
  font: inherit;
  font-size: 0.88rem;
  text-align: left;
  cursor: pointer;
  white-space: nowrap;
}
.menu-list :slotted(.menu-item:hover),
.menu-list :slotted(.menu-item:focus-visible) {
  background: var(--surface-2);
  outline: none;
}
.menu-list :slotted(.menu-item[disabled]) {
  color: var(--text-faint);
  cursor: default;
  background: none;
}
.menu-list :slotted(.menu-item.danger) {
  color: var(--danger);
}
.menu-list :slotted(.menu-hint) {
  display: block;
  font-size: 0.76rem;
  color: var(--text-faint);
  white-space: normal;
}
.menu-list :slotted(.menu-sep) {
  border: none;
  border-top: 1px solid var(--border);
  margin: 0.3rem 0;
}
</style>
