<script setup>
/**
 * Client setup: point each package manager, and Docker, at this registry.
 *
 * Every URL comes from /api/client-config (and /api/docker/client-config),
 * so the snippets are this deployment's, not a hostname baked into docs.
 * Each tab is the same shape: the one command most people need, the file to
 * commit instead, how to check it worked, and the details that trip people
 * up -- with the endpoints and token status in a rail alongside.
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api/client'
import CodeBlock from '@/components/CodeBlock.vue'
import EcosystemIcon from '@/components/EcosystemIcon.vue'
import NavIcon from '@/components/NavIcon.vue'

const route = useRoute()
const router = useRouter()
const config = ref(null)
const error = ref(null)
// Loaded separately: container images can be switched off, and then this
// simply 404s and the tab is not shown.
const docker = ref(null)
const tab = ref(route.query.tab || 'npm')
// Which container runtime the mirror snippet is for.
const runtime = ref('docker')

const TABS = computed(() =>
  [
    { key: 'npm', label: 'npm', sub: 'npm · yarn · pnpm', eco: 'npm' },
    { key: 'pip', label: 'Python', sub: 'pip · uv · poetry', eco: 'pypi' },
    config.value?.cargo && { key: 'cargo', label: 'cargo', sub: 'crates.io mirror', eco: 'cargo' },
    docker.value && { key: 'docker', label: 'Containers', sub: 'Docker · containerd · Podman', eco: 'docker' },
    { key: 'publish', label: 'Publishing', sub: 'npm · twine · images', icon: 'package' },
  ].filter(Boolean),
)

const uvToml = computed(() =>
  config.value
    ? ['[[tool.uv.index]]', 'name = "minireg"', `url = "${config.value.uv.index_url}"`, 'default = true'].join('\n')
    : '',
)

// The rail: what this tab talks to.
const endpoints = computed(() => {
  const c = config.value
  if (!c) return []
  switch (tab.value) {
    case 'npm':
      return [{ label: 'Registry', value: c.npm.registry }]
    case 'pip':
      return [{ label: 'Simple index', value: c.pip.index_url }]
    case 'cargo':
      return [{ label: 'Sparse index', value: c.cargo.registry }]
    case 'docker':
      return docker.value
        ? [
            { label: 'Registry host', value: docker.value.host },
            { label: 'Hub mirror', value: docker.value.mirror_url },
          ]
        : []
    default:
      return [
        { label: 'npm', value: c.npm.registry },
        { label: 'Python upload', value: c.twine.repository_url },
        ...(docker.value
          ? [{ label: 'Images', value: `${docker.value.host}/${docker.value.local_namespace}/…` }]
          : []),
      ]
  }
})

const TOKEN_NOTES = {
  npm: 'Installing needs no token while anonymous reads are on. Publishing needs one with the publish scope.',
  pip: 'Installing needs no token while anonymous reads are on. Publishing needs one with the publish scope.',
  cargo: 'Never needed. The mirror is read-only and cargo sends no credentials to it.',
  docker: 'Pulls need none while anonymous reads are on. Pushes need a token with the docker:push scope as the password.',
  publish: 'Every publish or push needs an API token. Account passwords are refused.',
}

watch(tab, (value) => router.replace({ query: { ...route.query, tab: value } }))

onMounted(async () => {
  try {
    config.value = await api.clientConfig()
  } catch (err) {
    error.value = err.detail || 'Could not load the client configuration.'
    return
  }
  try {
    docker.value = await api.dockerClientConfig()
  } catch {
    docker.value = null
  }
  if (!TABS.value.some((t) => t.key === tab.value)) tab.value = 'npm'
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Client setup</h1>
      <p class="page-sub">
        Point your package managers and container runtime at this registry. Every snippet already
        carries this registry's address. Where a token is needed, create one on
        <router-link :to="{ name: 'tokens' }">API tokens</router-link> and use it for
        <code>&lt;your-token&gt;</code>.
      </p>
    </div>
    <router-link class="btn" :to="{ name: 'cli' }">
      <NavIcon name="terminal" :size="15" /> Or let the CLI do it
    </router-link>
  </div>

  <div v-if="error" class="alert alert-error">{{ error }}</div>
  <div v-else-if="!config" class="empty">Loading…</div>

  <template v-else>
    <div class="client-tabs" role="tablist">
      <button
        v-for="t in TABS"
        :key="t.key"
        class="client-tab"
        :class="[{ active: tab === t.key }, t.eco ? `client-tab-${t.eco}` : '']"
        role="tab"
        :aria-selected="tab === t.key"
        @click="tab = t.key"
      >
        <span class="client-tab-mark" :class="t.eco ? `mark-${t.eco}` : ''">
          <EcosystemIcon v-if="t.eco" :ecosystem="t.eco" :size="18" />
          <NavIcon v-else :name="t.icon" :size="18" />
        </span>
        <span>
          <span class="client-tab-label">{{ t.label }}</span>
          <span class="client-tab-sub">{{ t.sub }}</span>
        </span>
      </button>
    </div>

    <div class="setup-layout">
      <div class="setup-main">
        <!-- npm ------------------------------------------------------------ -->
        <template v-if="tab === 'npm'">
          <section class="card step-card">
            <div class="step-head"><span class="step-num">1</span><h3>Point npm at the registry</h3></div>
            <div class="step-body">
              <CodeBlock caption="shell" :code="config.npm.commands[0]" />
              <p class="field-hint">yarn 1 and pnpm read the same setting.</p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head"><span class="step-num">2</span><h3>Or commit it to the project</h3></div>
            <div class="step-body">
              <CodeBlock caption=".npmrc" :code="config.npm.npmrc" />
              <p class="field-hint">
                A project <code>.npmrc</code> works for everyone who clones the repository and in CI. The
                second line reads a token from <code>$MINIREG_TOKEN</code> and is only needed to publish.
              </p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head"><span class="step-num">3</span><h3>Check it</h3></div>
            <div class="step-body">
              <CodeBlock caption="shell" code="npm config get registry" />
              <p class="field-hint">
                Prints the registry URL. After the next install the <code>resolved</code> URLs in
                <code>package-lock.json</code> point here.
              </p>
            </div>
          </section>

          <section class="card">
            <div class="card-head"><h3>Only some packages</h3></div>
            <div class="card-body">
              <CodeBlock caption="shell" :code="config.npm.scoped_example" />
              <p class="field-hint">Routes only <code>@myscope/*</code> here; everything else stays on npmjs.</p>
            </div>
          </section>
        </template>

        <!-- Python --------------------------------------------------------- -->
        <template v-if="tab === 'pip'">
          <section class="card step-card">
            <div class="step-head"><span class="step-num">1</span><h3>Point pip at the index</h3></div>
            <div class="step-body">
              <CodeBlock caption="shell" :code="config.pip.commands[0]" />
              <p class="field-hint">
                For a single install, <code>{{ config.pip.commands[1] }}</code>. In CI, set
                <code>PIP_INDEX_URL</code>.
              </p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head"><span class="step-num">2</span><h3>Or use a config file</h3></div>
            <div class="step-body">
              <CodeBlock caption="pip.conf" note="pip.ini on Windows" :code="config.pip.pip_conf" :wrap="false" />
            </div>
          </section>

          <div class="grid grid-2">
            <section class="card">
              <div class="card-head"><h3>uv</h3></div>
              <div class="card-body">
                <CodeBlock caption="pyproject.toml" :code="uvToml" :wrap="false" />
                <p class="field-hint">Then <code>uv lock</code>, so the lockfile records this index.</p>
              </div>
            </section>
            <section class="card">
              <div class="card-head"><h3>Poetry</h3></div>
              <div class="card-body">
                <CodeBlock caption="shell" :code="config.poetry.commands.join('\n')" />
                <p class="field-hint">Then <code>poetry lock</code>. The second line is only for reads that need a token.</p>
              </div>
            </section>
          </div>

          <section class="card">
            <div class="card-head"><h3>If reads need a token</h3></div>
            <div class="card-body">
              <CodeBlock caption="index URL" :code="config.pip.authenticated_index_url" />
              <p class="field-hint">Only when anonymous reads are switched off. Keep it out of committed files.</p>
            </div>
          </section>
        </template>

        <!-- cargo ---------------------------------------------------------- -->
        <template v-if="tab === 'cargo'">
          <section class="card step-card">
            <div class="step-head"><span class="step-num">1</span><h3>Replace crates.io</h3></div>
            <div class="step-body">
              <CodeBlock caption=".cargo/config.toml" :code="config.cargo.config_toml" :wrap="false" />
              <p class="field-hint">
                Commit it at the repository root so it applies to everyone who builds the project, or put it
                in <code>~/.cargo/config.toml</code> for your machine. Keep these tables at the end of the file.
              </p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head"><span class="step-num">2</span><h3>Check it</h3></div>
            <div class="step-body">
              <CodeBlock caption="shell" code="cargo fetch -v" />
              <p class="field-hint">The output names this registry's index for every crate.</p>
            </div>
          </section>

          <section class="card callout">
            <div class="card-body">
              <h4>Two details that matter</h4>
              <ul>
                <li>
                  <code>sparse+</code> tells cargo the index is served over HTTP. Without it cargo tries to
                  <code>git clone</code> the URL and fails with what looks like a network error.
                </li>
                <li>
                  The trailing slash. Without it every crate 404s while <code>config.json</code> keeps working,
                  which makes it hard to spot.
                </li>
              </ul>
              <p class="field-hint" style="margin-bottom: 0">{{ config.cargo.note }}</p>
            </div>
          </section>
        </template>

        <!-- containers ----------------------------------------------------- -->
        <template v-if="tab === 'docker' && docker">
          <section class="card step-card">
            <div class="step-head"><span class="step-num">A</span><h3>Prefix image names</h3></div>
            <div class="step-body">
              <CodeBlock
                caption="shell"
                :code="[docker.examples.hub, docker.examples.hub_explicit, ...docker.examples.other].join('\n')"
              />
              <p class="field-hint">
                A name with no upstream prefix is a Docker Hub image (<code>alpine</code> means
                <code>library/alpine</code>). Other registries go under their name:
                <code v-for="u in docker.upstreams" :key="u" class="upstream-chip">{{ u }}/</code>
              </p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head"><span class="step-num">B</span><h3>Or mirror Docker Hub, with no name changes</h3></div>
            <div class="step-body">
              <p class="field-hint" style="margin-top: 0">
                A plain <code>docker pull alpine</code> then goes through this registry. Pick the runtime:
              </p>
              <div class="seg mb" role="tablist">
                <button :class="{ active: runtime === 'docker' }" @click="runtime = 'docker'">Docker</button>
                <button :class="{ active: runtime === 'containerd' }" @click="runtime = 'containerd'">containerd · Kubernetes</button>
                <button v-if="docker.podman_registries_conf" :class="{ active: runtime === 'podman' }" @click="runtime = 'podman'">Podman</button>
              </div>
              <template v-if="runtime === 'docker'">
                <CodeBlock caption="/etc/docker/daemon.json" :code="JSON.stringify(docker.daemon_json, null, 2)" :wrap="false" />
                <p class="field-hint">
                  Then restart dockerd.
                  <template v-if="docker.daemon_json['insecure-registries']">
                    <code>insecure-registries</code> is there because this registry is served over plain HTTP;
                    without it Docker skips the mirror silently.
                  </template>
                </p>
              </template>
              <template v-else-if="runtime === 'containerd'">
                <CodeBlock :caption="docker.containerd_path" note="one file per node" :code="docker.containerd_hosts_toml" :wrap="false" />
                <p class="field-hint">containerd reads it on the next pull; no restart.</p>
              </template>
              <template v-else>
                <CodeBlock caption="/etc/containers/registries.conf" :code="docker.podman_registries_conf" :wrap="false" />
              </template>
              <p v-if="docker.mirror_note" class="field-hint">{{ docker.mirror_note }}</p>
            </div>
          </section>

          <div class="grid grid-2">
            <section v-if="docker.k8s_pull_secret" class="card">
              <div class="card-head"><h3>Kubernetes pull secret</h3></div>
              <div class="card-body">
                <CodeBlock caption="shell" :code="docker.k8s_pull_secret" />
                <p class="field-hint">Only when anonymous reads are off. Use a token with the read scope.</p>
              </div>
            </section>
            <section v-if="docker.gitlab_ci" class="card">
              <div class="card-head"><h3>GitLab CI</h3></div>
              <div class="card-body">
                <CodeBlock caption=".gitlab-ci.yml" :code="docker.gitlab_ci" :wrap="false" />
              </div>
            </section>
          </div>
        </template>

        <!-- publishing ----------------------------------------------------- -->
        <template v-if="tab === 'publish'">
          <section class="card step-card">
            <div class="step-head">
              <span class="step-num mark-npm"><EcosystemIcon ecosystem="npm" :size="13" /></span>
              <h3>npm package</h3>
            </div>
            <div class="step-body">
              <CodeBlock caption="shell" :code="`${config.npm.commands[1]}\nnpm publish --registry ${config.npm.registry}`" />
              <p class="field-hint">
                A name that exists on npmjs cannot be published here, and versions are immutable: bump the
                version if you get a 409.
              </p>
            </div>
          </section>

          <section class="card step-card">
            <div class="step-head">
              <span class="step-num mark-pypi"><EcosystemIcon ecosystem="pypi" :size="13" /></span>
              <h3>Python package</h3>
            </div>
            <div class="step-body">
              <CodeBlock caption="shell" :code="config.twine.commands.join('\n')" />
              <div class="mt">
                <CodeBlock caption="~/.pypirc" :code="config.twine.pypirc" :wrap="false" />
              </div>
            </div>
          </section>

          <section v-if="docker" class="card step-card">
            <div class="step-head">
              <span class="step-num mark-docker"><EcosystemIcon ecosystem="docker" :size="13" /></span>
              <h3>Container image</h3>
            </div>
            <div class="step-body">
              <CodeBlock caption="shell" :code="docker.examples.push.join('\n')" />
              <p class="field-hint">
                Pushes go under <code>{{ docker.local_namespace }}/</code>. A token can be limited to prefixes
                such as <code>{{ docker.local_namespace }}/team-a/</code>. Pushed images are scanned before
                anyone can pull them.
              </p>
            </div>
          </section>

          <section v-if="config.cargo" class="card callout">
            <div class="card-body">
              <h4>Crates cannot be published</h4>
              <p class="field-hint" style="margin-bottom: 0">
                Cargo mirrors through source replacement, which requires the mirror to serve exactly what
                crates.io serves, so a crate published here could never resolve through it. Private crates
                need a separate registry entry and a <code>registry = "…"</code> key on each dependency.
              </p>
            </div>
          </section>
        </template>
      </div>

      <aside class="setup-rail">
        <div class="card">
          <div class="card-head"><h3>Endpoints</h3></div>
          <div class="card-body rail-body">
            <div v-for="e in endpoints" :key="e.label" class="rail-item">
              <div class="rail-label">{{ e.label }}</div>
              <code class="rail-value">{{ e.value }}</code>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><h3>Tokens</h3></div>
          <div class="card-body rail-body">
            <p class="small dim" style="margin: 0 0 0.7rem">{{ TOKEN_NOTES[tab] }}</p>
            <router-link class="btn btn-sm" :to="{ name: 'tokens' }">
              <NavIcon name="key" :size="14" /> Manage tokens
            </router-link>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><h3>More</h3></div>
          <div class="card-body rail-body rail-links">
            <router-link :to="{ name: 'help-page', params: { slug: tab === 'docker' ? 'containers' : 'usage' } }">
              {{ tab === 'docker' ? 'Container images guide' : 'Using the registry' }} →
            </router-link>
            <router-link :to="{ name: 'help-page', params: { slug: 'troubleshooting' } }">Troubleshooting →</router-link>
            <router-link :to="{ name: 'help-page', params: { slug: 'policy' } }">Why a version is blocked →</router-link>
          </div>
        </div>
      </aside>
    </div>
  </template>
</template>

<style scoped>
/* -- client picker: cards rather than thin tabs, each in its brand colour */
.client-tabs {
  display: grid;
  /* Five options: one row, or a tidy wrap -- never a single orphan. */
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.6rem;
  margin-bottom: 1.1rem;
}
.client-tab {
  --tab-color: var(--accent);
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 0.7rem 0.85rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  text-align: left;
  font: inherit;
  color: var(--text);
  transition: border-color 0.12s ease, background 0.12s ease;
}
.client-tab-npm { --tab-color: var(--npm); }
.client-tab-pypi { --tab-color: var(--pypi); }
.client-tab-cargo { --tab-color: var(--cargo); }
.client-tab-docker { --tab-color: var(--docker); }
.client-tab:hover { border-color: var(--text-faint); }
.client-tab.active {
  border-color: var(--tab-color);
  box-shadow: inset 0 0 0 1px var(--tab-color);
  background: color-mix(in srgb, var(--tab-color) 8%, var(--surface));
}
.client-tab-mark {
  display: grid;
  place-items: center;
  flex: none;
  width: 34px;
  height: 34px;
  border-radius: var(--radius-sm);
  color: var(--tab-color);
  background: color-mix(in srgb, var(--tab-color) 13%, transparent);
}
.client-tab-label { display: block; font-weight: 650; }
.client-tab-sub { display: block; font-size: 0.76rem; color: var(--text-faint); }

/* -- body + rail */
.setup-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 300px;
  gap: 1rem;
  align-items: start;
}
.setup-main > * + * { margin-top: 1rem; }

.step-card { padding: 1rem 1.1rem; }
.step-head {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  margin-bottom: 0.7rem;
}
.step-head h3 { margin: 0; font-size: 0.98rem; }
.step-num {
  --num-color: var(--accent);
  display: grid;
  place-items: center;
  flex: none;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  font-size: 0.78rem;
  font-weight: 700;
  color: #fff;
  background: var(--num-color);
}
.step-num :deep(svg) { color: #fff; }

/* segmented switch for alternatives within one step */
.seg {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.seg button {
  font: inherit;
  font-size: 0.82rem;
  padding: 0.3rem 0.75rem;
  border: none;
  background: var(--surface);
  color: var(--text-dim);
  cursor: pointer;
}
.seg button + button { border-left: 1px solid var(--border); }
.seg button.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
.step-num.mark-npm { --num-color: var(--npm); }
.step-num.mark-pypi { --num-color: var(--pypi); }
.step-num.mark-docker { --num-color: var(--docker); }
.step-body { padding-left: calc(24px + 0.65rem); }
.step-body > .field-hint:last-child { margin-bottom: 0; }

.callout { border-left: 3px solid var(--accent); }
.callout h4 { margin: 0 0 0.45rem; font-size: 0.9rem; }
.callout ul { margin: 0 0 0.6rem; padding-left: 1.1rem; color: var(--text-dim); font-size: 0.86rem; }
.callout li + li { margin-top: 0.3rem; }

.upstream-chip { margin-right: 0.3rem; }

.setup-rail {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  position: sticky;
  top: 1rem;
}
.rail-body { padding: 0.85rem 1rem; }
.rail-item + .rail-item { margin-top: 0.7rem; }
.rail-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-faint);
  margin-bottom: 0.2rem;
}
.rail-value { display: block; overflow-wrap: anywhere; font-size: 0.8rem; }
.rail-links { display: flex; flex-direction: column; gap: 0.4rem; font-size: 0.86rem; }
.setup-rail .btn { display: inline-flex; align-items: center; gap: 0.4rem; }

@media (max-width: 1250px) {
  .client-tabs { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .client-tabs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 1100px) {
  .setup-layout { grid-template-columns: 1fr; }
  .setup-rail {
    position: static;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  }
}
@media (max-width: 640px) {
  .step-body { padding-left: 0; }
}
</style>
