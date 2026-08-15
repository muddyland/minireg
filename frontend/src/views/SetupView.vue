<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'

const config = ref(null)
const tab = ref('npm')
const copied = ref(null)

async function copy(text, key) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
    setTimeout(() => (copied.value = null), 1600)
  } catch {
    copied.value = null
  }
}

onMounted(async () => {
  config.value = await api.clientConfig()
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Client setup</h1>
      <p class="page-sub">
        Point your package managers at this registry. Replace
        <code>&lt;your-token&gt;</code> with a token from
        <router-link :to="{ name: 'tokens' }">API tokens</router-link>.
      </p>
    </div>
  </div>

  <div v-if="!config" class="empty">Loading…</div>

  <template v-else>
    <div class="tabs">
      <button class="tab" :class="{ active: tab === 'npm' }" @click="tab = 'npm'">npm / yarn / pnpm</button>
      <button class="tab" :class="{ active: tab === 'pip' }" @click="tab = 'pip'">pip / uv / poetry</button>
      <button class="tab" :class="{ active: tab === 'publish' }" @click="tab = 'publish'">Publishing</button>
    </div>

    <template v-if="tab === 'npm'">
      <div class="card mb">
        <div class="card-head">
          <h3>Configure npm</h3>
          <span class="badge badge-npm">npm</span>
        </div>
        <div class="card-body">
          <p class="dim small mb">Run these once per machine:</p>
          <div class="copy-block mb">
            <pre>{{ config.npm.commands.join('\n') }}</pre>
            <button class="btn btn-sm" @click="copy(config.npm.commands.join('\n'), 'npm-cmd')">
              {{ copied === 'npm-cmd' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <h4 class="small">Or commit an <code>.npmrc</code></h4>
          <div class="copy-block">
            <pre>{{ config.npm.npmrc }}</pre>
            <button class="btn btn-sm" @click="copy(config.npm.npmrc, 'npmrc')">
              {{ copied === 'npmrc' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <h4 class="small mt">Route only one scope through the registry</h4>
          <pre>{{ config.npm.scoped_example }}</pre>
          <p class="field-hint">
            Useful when you want internal <code>@myscope/*</code> packages here but everything else
            straight from npmjs.
          </p>
        </div>
      </div>
    </template>

    <template v-if="tab === 'pip'">
      <div class="card mb">
        <div class="card-head">
          <h3>Configure pip</h3>
          <span class="badge badge-pypi">PyPI</span>
        </div>
        <div class="card-body">
          <div class="copy-block mb">
            <pre>{{ config.pip.commands.join('\n') }}</pre>
            <button class="btn btn-sm" @click="copy(config.pip.commands.join('\n'), 'pip-cmd')">
              {{ copied === 'pip-cmd' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <h4 class="small">Or a <code>pip.conf</code> / <code>pip.ini</code></h4>
          <div class="copy-block">
            <pre>{{ config.pip.pip_conf }}</pre>
            <button class="btn btn-sm" @click="copy(config.pip.pip_conf, 'pipconf')">
              {{ copied === 'pipconf' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <h4 class="small mt">If the registry requires authentication for reads</h4>
          <pre>{{ config.pip.authenticated_index_url }}</pre>
        </div>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-head"><h3>uv</h3></div>
          <div class="card-body"><pre>{{ config.uv.commands.join('\n') }}</pre></div>
        </div>
        <div class="card">
          <div class="card-head"><h3>Poetry</h3></div>
          <div class="card-body"><pre>{{ config.poetry.commands.join('\n') }}</pre></div>
        </div>
      </div>
    </template>

    <template v-if="tab === 'publish'">
      <div class="alert alert-info">
        Publishing always requires an API token with the <strong>publish</strong> scope. Password
        authentication is not accepted for publishing.
      </div>

      <div class="card mb">
        <div class="card-head"><h3>Publish an npm package</h3></div>
        <div class="card-body">
          <pre>{{ config.npm.commands[1] }}
npm publish --registry {{ config.npm.registry }}</pre>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>Publish a Python package (twine)</h3></div>
        <div class="card-body">
          <div class="copy-block mb">
            <pre>{{ config.twine.commands.join('\n') }}</pre>
            <button class="btn btn-sm" @click="copy(config.twine.commands.join('\n'), 'twine-cmd')">
              {{ copied === 'twine-cmd' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <h4 class="small">Or a <code>~/.pypirc</code></h4>
          <div class="copy-block">
            <pre>{{ config.twine.pypirc }}</pre>
            <button class="btn btn-sm" @click="copy(config.twine.pypirc, 'pypirc')">
              {{ copied === 'pypirc' ? 'Copied' : 'Copy' }}
            </button>
          </div>
        </div>
      </div>
    </template>
  </template>
</template>
