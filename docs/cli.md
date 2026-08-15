# The CLI

A single-file client that configures your package managers and audits a
project's dependencies against the CVE data this registry already holds.

It is deliberately one Python file with no third-party imports: it is fetched
from the registry it talks to, and requiring a virtualenv before you can point
npm at your own mirror would defeat the purpose. Python 3.9+ is the only
requirement.

---

## Install

```bash
curl -fsSL https://registry.example.com/api/cli/install.sh | sh
```

The installer drops one script into `~/.local/bin/minireg` and pre-fills the
registry URL, so `minireg login` needs no arguments.

Install somewhere else:

```bash
MINIREG_BIN_DIR=/usr/local/bin curl -fsSL https://registry.example.com/api/cli/install.sh | sh
```

By hand, if you would rather not pipe a script into a shell:

```bash
curl -fsSL https://registry.example.com/api/cli/download -o ~/.local/bin/minireg
chmod +x ~/.local/bin/minireg
minireg login --url https://registry.example.com
```

The **CLI tool** page in the UI has a download button and the same commands
with your URL filled in.

---

## Signing in

```bash
minireg login
```

```
  Open https://registry.example.com/cli-login?code=HP8R-S5WU
  and confirm this code:  HP8R-S5WU

  Waiting for approval… (Ctrl-C to cancel)
```

Approve it in the browser and the terminal completes on its own.

This is an OAuth device-authorization flow (RFC 8628). It means:

- **No password is typed into the terminal**, and the CLI never sees one.
- **SSO works with no extra plumbing** — approval happens under whatever
  session you already have in the browser, including Authentik.
- **No callback port** is opened on your machine, so it works over SSH and
  inside containers.

The approval screen shows the hostname, platform, and IP of the machine that
asked, so you can tell whether the request is really yours. If it is not,
deny it.

The token is stored at `~/.config/minireg/config.json` with mode `600`, and
appears in **API tokens** named after your machine. Revoke it there to sign
that machine out.

### Scopes

`login` requests `read` by default:

```bash
minireg login --scopes read,publish
```

You choose what to actually grant on the approval screen, and a token can never
exceed your own permissions — requesting `admin` as a non-admin silently drops
it rather than failing.

### No browser available

```bash
minireg login --no-browser
```

Prints the URL and code without trying to open anything. Open it from any
device — the code is what binds the session, not the browser.

---

## Configuring package managers

```bash
minireg configure           # npm and pip
minireg configure npm
minireg configure pip
minireg configure --dry-run # print what would be written
```

Writes a marked block into `~/.npmrc` and `~/.config/pip/pip.conf`:

```ini
# >>> minireg >>>
registry=https://registry.example.com/npm/
//registry.example.com/npm/:_authToken=mrg_…
# <<< minireg <<<
```

Anything else in those files is left alone, and re-running replaces the block
rather than appending a second copy. Both files are written mode `600` because
they contain a token.

---

## Auditing

```bash
minireg audit                    # this directory
minireg audit ./services/api     # elsewhere
minireg audit package-lock.json  # one file
```

```
scanning package-lock.json (4 packages, npm)

  minimist@1.2.5  CVSS 9.8  [BLOCKED BY REGISTRY]
      policy: CVE-2021-44906 - prototype pollution
      9.8  CVE-2021-44906  fixed in 1.2.6
           Prototype Pollution in minimist

  lodash@4.17.20  CVSS 8.1  [BLOCKED BY REGISTRY]
      policy: CVE-2021-23337 - command injection in template
      8.1  CVE-2021-23337  fixed in 4.17.21
           lodash vulnerable to Code Injection via `_.template`
      5.3  CVE-2020-28500  fixed in 4.17.21
           Regular Expression Denial of Service (ReDoS) in lodash

  Summary: 2 package(s) with findings, 2 blocked — these will not install
```

Two things distinguish this from `npm audit` / `pip-audit`:

- **It reports the registry's policy verdict**, not just advisories. A package
  marked `[BLOCKED BY REGISTRY]` will fail to install — that is not advisory,
  it is what will happen.
- **It uses the same CVE data the registry enforces with**, so an audit that
  passes and an install that succeeds agree with each other.

### Lockfiles

| File | Ecosystem |
|---|---|
| `package-lock.json` | npm (v1, v2, v3) |
| `npm-shrinkwrap.json` | npm |
| `poetry.lock` | PyPI |
| `uv.lock` | PyPI |
| `Pipfile.lock` | PyPI |
| `requirements.txt` | PyPI (pinned `==` entries only) |

Every lockfile found in the directory is audited, so a project with both npm
and Python dependencies is covered in one run.

Only pinned versions can be audited. A range like `django>=4.0` has no single
version to check, so it is skipped and counted in the unscanned total. This is
why lockfiles give better results than `requirements.txt`.

### Failing a build

```bash
minireg audit --fail-on high
```

| Exit | Meaning |
|---|---|
| `0` | Nothing at or above the threshold |
| `1` | The audit could not run (not logged in, registry unreachable) |
| `2` | A finding at or above the threshold, or a blocked dependency |

`--fail-on` accepts `low`, `medium`, `high`, `critical`, or `never` (the
default). Blocked dependencies always trip a non-zero exit when any threshold
is set, because they will not install.

Distinguish `1` from `2` in CI — `1` is a broken pipeline, `2` is a real
finding.

### Other flags

```bash
minireg audit --json       # machine readable
minireg audit --offline    # do not scan packages the registry has not seen
```

`--offline` is instant but blind to anything this registry has never served.
Without it, unknown packages are scanned against OSV on demand.

---

## Searching

```bash
minireg search express
minireg search requests --ecosystem pypi --limit 10

minireg info lodash
minireg info requests --ecosystem pypi
```

`info` shows versions, known CVEs per version, and which upstreams carry the
package with links to their pages.

---

## CI

There is no browser in CI, so skip `login` and pass a token from
**API tokens** through the environment:

```bash
export MINIREG_URL=https://registry.example.com
export MINIREG_TOKEN="$CI_REGISTRY_TOKEN"

minireg configure
minireg audit --fail-on high
```

Environment variables always win over the config file, so the same CLI works
for a person and a pipeline with no branching.

---

## Reference

### Commands

| Command | Purpose |
|---|---|
| `login` | Authenticate via the browser |
| `logout` | Forget the stored token (does not revoke it) |
| `whoami` | Show the current identity and scopes |
| `configure [npm\|pip\|all]` | Point package managers at the registry |
| `audit [path]` | Check dependencies for CVEs |
| `search <query>` | Search the index |
| `info <package>` | Show a package |

### Global flags

| Flag | Purpose |
|---|---|
| `--url URL` | Override the stored registry |
| `--insecure` | Skip TLS verification. Development only |
| `--version` | Print the version |

### Environment

| Variable | Purpose |
|---|---|
| `MINIREG_URL` | Registry URL; overrides the config file |
| `MINIREG_TOKEN` | API token; overrides the config file |
| `NO_COLOR` | Disable colour |
| `XDG_CONFIG_HOME` | Config location (default `~/.config`) |

### Files

| Path | Contents |
|---|---|
| `~/.config/minireg/config.json` | Registry URL, token, username. Mode `600` |
| `~/.npmrc` | Written by `configure`, in a marked block |
| `~/.config/pip/pip.conf` | Written by `configure`, in a marked block |

---

## Notes

**`logout` does not revoke.** It deletes the local token; the token stays valid
server-side. Revoke it in **API tokens** if a machine is lost.

**Approval codes expire in 10 minutes** and are single-use.

**The CLI is served from the registry**, so it is always the version that
matches your deployment. Re-run the installer after upgrading the registry.
