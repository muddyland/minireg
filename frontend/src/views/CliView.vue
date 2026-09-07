<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '@/api/client'

const config = ref(null)
const copied = ref(null)

const base = computed(() => config.value?.public_url || window.location.origin)
const installCommand = computed(() => `curl -fsSL ${base.value}/api/cli/install.sh | sh`)

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

const COMMANDS = [
  {
    command: 'minireg login',
    summary: 'Authenticate through the browser. No password is typed into the terminal.',
  },
  {
    command: 'minireg configure',
    summary: 'Point npm, pip and cargo at this registry, credentials included.',
  },
  {
    command: 'minireg audit',
    summary:
      "Check this project's lockfiles — npm, Python and Cargo.lock — against known CVEs and this registry's policy.",
  },
  { command: 'minireg search <query>', summary: 'Search the package index.' },
  { command: 'minireg info <package>', summary: 'Versions, CVEs, and upstream sources.' },
  { command: 'minireg whoami', summary: 'Show who the stored token belongs to.' },
]
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Command line tool</h1>
      <p class="page-sub">
        A single-file client for this registry — configure your package managers, and audit a
        project's dependencies against the CVE data this registry already holds.
      </p>
    </div>
    <a class="btn btn-primary" :href="`${base}/api/cli/download`" download="minireg">
      Download
    </a>
  </div>

  <div class="grid grid-2 mb">
    <div class="card">
      <div class="card-head"><h3>Install</h3></div>
      <div class="card-body">
        <p class="dim small mb">
          Requires Python 3.9 or newer — nothing else. The installer drops one script into
          <code>~/.local/bin</code> and pre-fills this registry's URL.
        </p>
        <div class="copy-block">
          <pre>{{ installCommand }}</pre>
          <button class="btn btn-sm" @click="copy(installCommand, 'install')">
            {{ copied === 'install' ? 'Copied' : 'Copy' }}
          </button>
        </div>

        <h4 class="small mt">Or install it by hand</h4>
        <pre>curl -fsSL {{ base }}/api/cli/download -o ~/.local/bin/minireg
chmod +x ~/.local/bin/minireg</pre>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>First run</h3></div>
      <div class="card-body">
        <pre>minireg login
minireg configure
minireg audit</pre>
        <p class="field-hint">
          <code>login</code> prints a short code and opens this site. You approve it here, under
          the session you are already signed in with — including SSO — and the CLI receives an API
          token scoped to your account. The token is stored at
          <code>~/.config/minireg/config.json</code> with mode <code>600</code>.
        </p>

        <div class="alert alert-info small" style="margin-top: 0.85rem; margin-bottom: 0">
          Tokens issued this way appear under
          <router-link :to="{ name: 'tokens' }">API tokens</router-link>, named after the machine
          that requested them. Revoke one there to sign that machine out.
        </div>
      </div>
    </div>
  </div>

  <div class="card mb">
    <div class="card-head"><h3>Commands</h3></div>
    <div class="card-body tight">
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th style="width: 280px">Command</th><th>What it does</th></tr>
          </thead>
          <tbody>
            <tr v-for="entry in COMMANDS" :key="entry.command">
              <td class="mono">{{ entry.command }}</td>
              <td class="dim">{{ entry.summary }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="grid grid-2">
    <div class="card">
      <div class="card-head"><h3>Auditing a project</h3></div>
      <div class="card-body">
        <p class="dim small mb">
          Run it in a project directory. It reads whichever lockfile it finds and asks the registry
          what it knows about every pinned dependency.
        </p>
        <pre>minireg audit                     # this directory
minireg audit ./services/api      # somewhere else
minireg audit --fail-on high      # exit 2 on high or critical
minireg audit --json              # machine readable</pre>

        <h4 class="small mt">Lockfiles it understands</h4>
        <div class="row-tight">
          <span class="badge badge-npm">package-lock.json</span>
          <span class="badge badge-npm">npm-shrinkwrap.json</span>
          <span class="badge badge-pypi">poetry.lock</span>
          <span class="badge badge-pypi">uv.lock</span>
          <span class="badge badge-pypi">Pipfile.lock</span>
          <span class="badge badge-pypi">requirements.txt</span>
        </div>
        <p class="field-hint">
          Only pinned versions can be audited — a range like <code>&gt;=4.0</code> has no single
          version to check, so it is skipped and counted as unscanned.
        </p>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Use in CI</h3></div>
      <div class="card-body">
        <p class="dim small mb">
          There is no browser in CI, so skip <code>login</code> and pass a token from
          <router-link :to="{ name: 'tokens' }">API tokens</router-link> through the environment.
        </p>
        <div class="copy-block">
          <pre>export MINIREG_URL={{ base }}
export MINIREG_TOKEN="$CI_REGISTRY_TOKEN"

minireg configure
minireg audit --fail-on high</pre>
          <button
            class="btn btn-sm"
            @click="
              copy(
                `export MINIREG_URL=${base}\nexport MINIREG_TOKEN=\&quot;$CI_REGISTRY_TOKEN\&quot;\n\nminireg configure\nminireg audit --fail-on high`,
                'ci',
              )
            "
          >
            {{ copied === 'ci' ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <p class="field-hint">
          <code>--fail-on</code> exits <code>2</code> when a CVE at that severity or above is
          found, or when a dependency is blocked by this registry's policy. Anything else exits
          <code>0</code>.
        </p>
      </div>
    </div>
  </div>
</template>
