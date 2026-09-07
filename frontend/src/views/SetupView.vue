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
      <button v-if="config.cargo" class="tab" :class="{ active: tab === 'cargo' }" @click="tab = 'cargo'">cargo</button>
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

    <template v-if="tab === 'cargo'">
      <div class="card mb">
        <div class="card-head">
          <h3>Configure cargo</h3>
          <span class="badge badge-cargo">cargo</span>
        </div>
        <div class="card-body">
          <p class="dim small mb">
            Cargo has no <code>config set</code> equivalent — the redirect has to live in a file.
            Put this in <code>{{ config.cargo.config_path }}</code>:
          </p>
          <div class="copy-block mb">
            <pre>{{ config.cargo.config_toml }}</pre>
            <button class="btn btn-sm" @click="copy(config.cargo.config_toml, 'cargo-toml')">
              {{ copied === 'cargo-toml' ? 'Copied' : 'Copy' }}
            </button>
          </div>

          <p class="field-hint">
            This is <em>source replacement</em>: it redirects every crates.io dependency without
            editing a single <code>Cargo.toml</code>. Commit it as
            <code>.cargo/config.toml</code> at the repository root and it applies to everyone who
            builds the project.
          </p>

          <h4 class="small mt">Two details that are load-bearing</h4>
          <ul class="field-hint" style="margin: 0.3rem 0 0; padding-left: 1.1rem">
            <li>
              <code>sparse+</code> tells cargo the index is served over HTTP. Without it cargo
              tries to <code>git clone</code> the URL and fails like a network error.
            </li>
            <li>
              The trailing slash. Without it cargo joins the shard paths against the parent
              segment, and every crate 404s while <code>config.json</code> keeps working.
            </li>
          </ul>

          <h4 class="small mt">No token needed</h4>
          <p class="field-hint">
            Reads are anonymous, and cargo only sends credentials to an index that declares
            <code>auth-required</code>. Nothing here is a secret.
          </p>
        </div>
      </div>

      <div class="alert alert-info">
        {{ config.cargo.note }}
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

      <div v-if="config.cargo" class="card mt">
        <div class="card-head">
          <h3>Publish a crate</h3>
          <span class="badge badge-cargo">cargo</span>
        </div>
        <div class="card-body">
          <p class="field-hint" style="margin: 0">
            Not supported, and not an oversight. Cargo mirrors a registry through source
            replacement, and it requires the replacement to serve exactly what crates.io serves —
            every crate is checked against the checksum in <code>Cargo.lock</code>. A crate that is
            not on crates.io can never resolve through a replaced source, so anything published
            here would be unreachable from the clients configured above. Hosting private crates
            needs a separate registry entry and a <code>registry = "…"</code> key on each
            dependency, which is a different thing from mirroring.
          </p>
        </div>
      </div>
    </template>
  </template>
</template>
