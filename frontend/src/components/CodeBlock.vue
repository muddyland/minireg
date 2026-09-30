<script setup>
/**
 * A copyable snippet: a command, a config file, a URL.
 *
 * Replaces the `.copy-block` markup that every setup view repeated with its
 * own copy state. With a caption the button sits in a header strip, so it
 * never covers the end of a long line; without one it floats top-right like
 * the old block did.
 */
import { ref } from 'vue'

const props = defineProps({
  code: { type: String, required: true },
  // Shown in the header strip: a filename (".npmrc") or "shell".
  caption: { type: String, default: '' },
  // Secondary label beside the caption ("Podman", "Windows").
  note: { type: String, default: '' },
  // Wrap long lines (URLs break at "/" etc., never mid-word) instead of
  // scrolling. Off for files whose layout matters, like TOML.
  wrap: { type: Boolean, default: true },
})

const copied = ref(false)
let timer = null

async function copy() {
  try {
    await navigator.clipboard.writeText(props.code)
    copied.value = true
    clearTimeout(timer)
    timer = setTimeout(() => (copied.value = false), 1600)
  } catch {
    copied.value = false
  }
}
</script>

<template>
  <div class="code-block" :class="{ captioned: !!caption }">
    <div v-if="caption" class="code-block-head">
      <span class="code-block-caption">
        {{ caption }}<span v-if="note" class="code-block-note">{{ note }}</span>
      </span>
      <button class="btn btn-sm btn-ghost" type="button" @click="copy">
        {{ copied ? 'Copied' : 'Copy' }}
      </button>
    </div>
    <pre :class="{ wrap }">{{ code }}</pre>
    <button v-if="!caption" class="btn btn-sm code-block-float" type="button" @click="copy">
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
  </div>
</template>

<style scoped>
.code-block {
  position: relative;
}
.code-block pre.wrap {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.code-block:not(.captioned) pre {
  padding-right: 4.8rem;
}
.code-block-float {
  position: absolute;
  top: 0.4rem;
  right: 0.4rem;
}
.captioned {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.captioned pre {
  border: none;
  border-radius: 0;
}
.code-block-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.2rem 0.35rem 0.2rem 0.75rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.code-block-caption {
  font-family: var(--mono);
  font-size: 0.76rem;
  color: var(--text-dim);
  overflow-wrap: anywhere;
}
.code-block-note {
  font-family: var(--font, inherit);
  color: var(--text-faint);
  margin-left: 0.6rem;
}
</style>
