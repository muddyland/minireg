# Using the registry

The **Client setup** page in the UI generates every snippet below with your
real URL already filled in. This page explains what they do and when each form
is the right one.

---

## The fastest route

Install the CLI and let it configure everything:

```bash
curl -fsSL https://registry.example.com/api/cli/install.sh | sh
minireg login
minireg configure
```

See [The CLI](cli.md) for the full command set.

Everything below is what to do without it.

---

## npm

### Point everything at the registry

```bash
npm config set registry https://registry.example.com/npm/
npm config set //registry.example.com/npm/:_authToken "<token>"
```

The `_authToken` key must use the registry host **and path**, without a scheme.
Getting that wrong is the single most common npm configuration failure: npm
silently sends no credentials and you get a 401 that looks like a server fault.

### Route only one scope

Usually better. Internal packages come from your registry, everything else
straight from npmjs — no single point of failure for the whole dependency tree.

```bash
npm config set @mycompany:registry https://registry.example.com/npm/
npm config set //registry.example.com/npm/:_authToken "<token>"
```

### Commit it to the project

`.npmrc` in the project root:

```ini
registry=https://registry.example.com/npm/
//registry.example.com/npm/:_authToken=${MINIREG_TOKEN}
```

npm expands `${VAR}` from the environment, so the file is safe to commit while
the token stays in CI secrets.

### Publishing

```bash
npm publish --registry https://registry.example.com/npm/
```

Requires a token with the `publish` scope. Password authentication is refused
for publishing — `npm login` will tell you to create a token instead.

Rules that are enforced:

- A version that already exists is rejected with `409 Conflict`. Registries
  never overwrite a published version.
- Blocked packages are refused, so a blocked name cannot be squatted locally.
- If CVE policy is enforcing, a version whose score falls in the blocked range
  is refused at publish time.

### Other commands

```bash
npm dist-tag add mypkg@1.2.0 stable
npm dist-tag ls mypkg
npm deprecate mypkg@"<1.0.0" "please upgrade"
npm unpublish mypkg@1.0.0
npm audit                       # answered from this registry's CVE store
```

`npm audit` reports the CVEs *this registry* knows about, which is the same
data its blocking policy uses — so audit output and install behaviour agree.

### yarn / pnpm

Both read `.npmrc`, so the same configuration works. For yarn 2+:

```yaml
# .yarnrc.yml
npmRegistryServer: "https://registry.example.com/npm/"
npmAuthToken: "${MINIREG_TOKEN}"
```

---

## Python

### pip

```bash
pip config set global.index-url https://registry.example.com/pypi/simple/
```

Or `~/.config/pip/pip.conf`:

```ini
[global]
index-url = https://registry.example.com/pypi/simple/
```

If reads require authentication (`ALLOW_ANONYMOUS_READ=false`), pip has no
token header — credentials go in the URL:

```ini
[global]
index-url = https://__token__:<token>@registry.example.com/pypi/simple/
```

Over plain HTTP add `trusted-host = registry.example.com` to silence pip's
warning. Do this only on a trusted network; the token is in cleartext.

### uv

```bash
uv pip install --index-url https://registry.example.com/pypi/simple/ <package>
```

Or in `pyproject.toml`:

```toml
[[tool.uv.index]]
url = "https://registry.example.com/pypi/simple/"
default = true
```

### Poetry

```bash
poetry source add --priority=primary minireg https://registry.example.com/pypi/simple/
poetry config http-basic.minireg __token__ <token>
```

### Publishing with twine

```bash
twine upload \
  --repository-url https://registry.example.com/pypi/legacy/ \
  -u __token__ -p <token> \
  dist/*
```

Or `~/.pypirc`:

```ini
[distutils]
index-servers = minireg

[minireg]
repository = https://registry.example.com/pypi/legacy/
username = __token__
password = <token>
```

Then `twine upload -r minireg dist/*`.

Rules that are enforced:

- The filename must agree with the declared name and version.
- Every digest you supply must match the bytes received.
- Only one sdist per release.
- Re-uploading an existing filename is rejected. PyPI never overwrites, and
  neither does this.

---

## CI

Give CI a dedicated token — do not reuse a personal one. It shows up separately
in the audit log and can be revoked without disrupting anyone.

### GitHub Actions

```yaml
- name: Configure registries
  env:
    MINIREG_TOKEN: ${{ secrets.MINIREG_TOKEN }}
  run: |
    npm config set registry https://registry.example.com/npm/
    npm config set //registry.example.com/npm/:_authToken "$MINIREG_TOKEN"
    pip config set global.index-url \
      "https://__token__:$MINIREG_TOKEN@registry.example.com/pypi/simple/"
```

### GitLab CI

```yaml
variables:
  MINIREG_URL: https://registry.example.com

before_script:
  - curl -fsSL "$MINIREG_URL/api/cli/install.sh" | sh
  - export PATH="$HOME/.local/bin:$PATH"
  - minireg configure          # MINIREG_TOKEN comes from a masked variable

audit:
  script:
    - minireg audit --fail-on high
```

### Docker builds

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci
```

Build with `--secret id=npmrc,src=$HOME/.npmrc` so the token never lands in a
layer.

---

## Browsing

**Search** covers everything the registry has indexed. Results show the
ecosystem, latest version, whether the package was published here, and — for
admins — whether it is blocked and why.

A package page shows:

- **Install** — the exact command for that ecosystem
- **Available from** — which upstreams have it, with links to their package
  pages, in tier order
- **Versions** — publish dates, files, cache state, and known CVEs per version

Non-admins never see blocked packages in search results, because advertising
something the registry will refuse to serve is worse than not listing it.

---

## When something does not resolve

| Symptom | Cause |
|---|---|
| `404` for a package that exists upstream | No upstream configured for that ecosystem, or all upstreams are quarantined — check **Upstreams → Health** |
| `403` with a policy message | A block rule or the CVE policy. The message names the reason. Confirm with **Package policy → Test a package** |
| `401` on install | `ALLOW_ANONYMOUS_READ=false` and no token, or an `_authToken` key that does not match the registry host and path |
| `409` on publish | That version already exists. Bump the version |
| Metadata looks right but downloads fail | `PUBLIC_URL` does not match the address the client uses |
| npm ignores your registry | A `.npmrc` closer to the project is overriding it — `npm config list` shows which file won |

More in [Troubleshooting](troubleshooting.md).
