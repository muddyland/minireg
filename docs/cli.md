# The CLI

A single-file client that configures your package managers and container
runtime, and audits a project's dependencies and container images against the
CVE data this registry already holds.

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
  session you already have in the browser, including an SSO one.
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
minireg login --scopes read,docker:push   # for `docker push` after `configure docker`
```

| Scope | Allows |
|---|---|
| `read` | Install packages, pull images, search, audit |
| `publish` | Publish npm and Python packages |
| `docker:push` | Push container images under `local/` |
| `admin` | The administrative API |

You choose what to actually grant on the approval screen, and every scope but
`read` starts unticked there. A token can never exceed your own permissions —
requesting `admin` as a non-admin silently drops it rather than failing. The
scanner worker's `scanner` scope cannot be requested here at all; it is minted
on the **API tokens** page.

### No browser available

```bash
minireg login --no-browser
```

Prints the URL and code without trying to open anything. Open it from any
device — the code is what binds the session, not the browser.

---

## Configuring package managers

```bash
minireg configure           # npm, pip and cargo
minireg configure npm
minireg configure pip
minireg configure cargo
minireg configure --dry-run # print what would be written
```

Writes a marked block into `~/.npmrc`, `~/.config/pip/pip.conf` and
`~/.cargo/config.toml`:

```ini
# >>> minireg >>>
registry=https://registry.example.com/npm/
//registry.example.com/npm/:_authToken=mrg_…
# <<< minireg <<<
```

```toml
# >>> minireg >>>
[source.crates-io]
replace-with = "minireg"

[source.minireg]
registry = "sparse+https://registry.example.com/cargo/index/"
# <<< minireg <<<
```

Anything else in those files is left alone, and re-running replaces the block
rather than appending a second copy.

`configure` on its own covers npm, pip and cargo. Docker is opt-in (see
[Containers](#containers) below), because it stores a credential in Docker's
own config, which a plain `minireg configure` in CI should not start doing. `~/.npmrc` and `pip.conf` are written mode
`600` because they contain a token; the cargo block carries none, because
reads are anonymous and cargo only sends credentials to an index that declares
`auth-required`.

The cargo block goes at the *end* of the file on first write. That matters for
TOML in a way it does not for the other two: `[source.…]` are table headers, so
anything placed after them would be read as part of `[source.minireg]`.

### Containers

```bash
minireg configure docker                       # docker, or podman if docker is missing
minireg configure docker --container-cli podman
minireg configure npm,pip,docker               # several at once
```

```
Containers  registry.example.com
  ✓ docker login registry.example.com  (credentials stored by docker)

  Pull through it:
    docker pull registry.example.com/alpine:3.20
    docker pull registry.example.com/ghcr/<image>:<tag>
  Push under local/:
    docker push registry.example.com/local/<team>/<image>:<tag>

  Optional: make it Docker Hub's mirror, so plain `docker pull alpine` goes through it.
  Not written: it needs root and a daemon restart.

  /etc/docker/daemon.json
    { "registry-mirrors": ["https://registry.example.com"] }
```

- **It runs `docker login`** against the address you gave `minireg login`,
  with your stored token as the password. The token goes in on stdin, never on
  the command line where `ps` would show it. Docker keeps the credential in its
  own store (`~/.docker/config.json` or a credential helper).
- **It does not write the daemon config.** Mirror mode needs
  `/etc/docker/daemon.json` (or containerd's `hosts.toml`), root and a daemon
  restart, and a mistake there stops every container on the machine. The
  snippet is printed with your registry filled in.
- **Pushing needs the `docker:push` scope.** With a read-only token, login
  still succeeds (pulls work), and it tells you to sign in again with
  `--scopes read,docker:push`.
- On a plain-HTTP registry it warns that Docker will refuse it until the host
  is under `insecure-registries`; the printed `daemon.json` includes that.

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
| `Cargo.lock` | cargo (crates.io entries only) |

Every lockfile found in the directory is audited, so a project with npm, Python
and Rust dependencies is covered in one run.

`Cargo.lock` also lists the workspace's own crates and any `git` or `path`
dependencies. Those are not on crates.io, so they are skipped — asking the
registry about them would return unknown for every one, which reads as a gap in
coverage rather than as "this is your own code".

Only exactly-pinned versions can be audited. A range like `django>=4.0` has no
single version to look up, so it is reported as unpinned and excluded — the
count is always stated, never silently dropped:

```
scanning requirements.txt (1 packages, pypi, 3 unpinned)
```

If nothing in the file is pinned, the file is named and the reason given rather
than skipped in silence. This is why lockfiles give better results than a
hand-written `requirements.txt`.

### Failing a build

```bash
minireg audit --fail-on high
```

| Exit | Meaning |
|---|---|
| `0` | Nothing at or above the threshold, and everything was checked |
| `1` | The audit could not run (not logged in, registry unreachable) |
| `2` | A finding at or above the threshold, or a blocked dependency |
| `3` | Something could not be checked at all |

`--fail-on` accepts `low`, `medium`, `high`, `critical`, or `never` (the
default). Blocked dependencies always trip a non-zero exit when any threshold
is set, because they will not install.

**Exit 3 is the one worth understanding.** "We could not check" is not "we
checked and it is fine", and several ordinary situations produce zero findings:
OSV being unreachable, `--offline`, a package the registry has never seen, or a
dependency list past the server's on-demand scan cap. Exiting 0 on those turns
a CI gate into decoration, so unchecked dependencies fail by default whenever
`--fail-on` is given. Pass `--no-fail-on-unscanned` to accept them.

`--json` does not disable any of this. It prints the findings, the unscanned
count and the blocked flag, and then exits with the same code.

Distinguish the codes in CI — `1` is a broken pipeline, `2` is a real finding,
`3` means your gate did not actually cover everything.

### Fixing what it finds

```bash
minireg audit --fix              # propose upgrades, ask before writing
minireg audit --fix --dry-run    # show them and stop
minireg audit --fix --yes        # write without asking
```

```
  Remediation

    ./package.json
      lodash  ^4.17.20 -> ^4.18.0
      minimist  ~1.2.5 -> ~1.2.6

  Write these changes? [y/N]
```

What it edits:

| Audited | Edited | Why |
|---|---|---|
| `package-lock.json` | `package.json` | The lock is generated output; raising the declared floor is what stops the next `npm install` regenerating a vulnerable lock |
| `requirements.txt` | `requirements.txt` | The pins are the declaration |
| `Cargo.lock` | *nothing* | See below |

Then regenerate the lockfile — `npm install`, or `pip install -r requirements.txt` — so the change takes effect.

**Cargo is not rewritten.** `Cargo.lock` is generated output, and `Cargo.toml`
declares ranges against a workspace and feature graph that would have to be
resolved to edit safely — a floor raised in the wrong member is a build break,
not a bump. Cargo already owns this operation, so the audit prints the exact
invocations instead:

```
    Cargo.lock: run these — cargo owns the lockfile
      cargo update -p smallvec --precise 1.13.2
```

**The target version clears every CVE, not just one.** Each advisory reports
the release that fixed *it*, and an upgrade has to satisfy all of them at once,
so the chosen version is the highest of those fixes. Where OSV files the same
CVE twice with different fixes — lodash CVE-2021-23337 is recorded both as
7.2/fixed-in-4.17.21 and 8.1/fixed-in-4.18.0 — the higher bound wins. Choosing
the lower one would leave the more severe variant in place.

**It checks its own suggestion.** Before writing, the proposed versions are
audited too, and anything still affected is reported:

```
    after upgrading, these would still have findings:
      some-package@2.1.0 CVSS 7.5
```

A CVE's "fixed in" only speaks for that CVE; the release it points at can carry
others of its own.

What it will not touch:

- Declarations that are not version ranges — `workspace:*`, `git+https://…`,
  `file:…` — reported as skipped.
- A `requirements.txt` containing `--hash=` pins. Changing a version
  invalidates every recorded hash and they cannot be recomputed without
  downloading the artifacts; regenerate with pip-compile instead.
- Packages with no published fix, listed as `no fix` so they are visible rather
  than quietly absent.

Comments, environment markers, spacing, key order and indentation are all
preserved — the edit changes version tokens and nothing else.

### Container images

```bash
minireg audit --image python:3.12-slim
minireg audit --image registry.example.com/local/team/app:1.4 --fail-on critical
minireg audit --image app:1 --image worker:1 --platform linux/arm64
```

```
  registry.example.com/local/team-a/app:1
  repository : local/team-a/app  pushed here
  digest     : sha256:8ad9e43b…
  platforms  : linux/amd64
  showing    : linux/amd64  sha256:3c749d83…
  size       : 42.5 MB, 6 layer(s)
  scan       : scanned 2026-09-30 03:33
  findings   : 26 critical, 105 high, 102 medium, 34 low  (204 fixable)
  verdict    : BLOCKED — linux/amd64: push policy: image has 24 fixable findings at CRITICAL or above

  Findings  worst first
    CRIT  CVE-2021-3711        openssl 1.1.1d-0+deb10u3 -> 1.1.1d-0+deb10u7
    …

  Summary: 1 image(s), blocked — the registry will refuse these pulls
```

This reports the registry's own scan and verdict, not a second opinion: the
**verdict** line is what `docker pull` would get. Any form of the name works —
`alpine`, `alpine:3.20`, `ghcr/org/img:1`, the full
`registry.example.com/…` you would pass to `docker pull`, or `@sha256:…`.

- **An image nobody has pulled is looked up and scanned.** The registry fetches
  its manifests (not its layers) and queues a scan; the audit waits for it,
  up to `--wait` seconds (default 120).
- **Multi-platform tags** are judged on `--platform` (default `linux/amd64`;
  `linux/arm64` matches `linux/arm64/v8`). The tag's own verdict wins if
  another platform is blocked, because `docker pull` resolves the tag through
  the index and is refused for it.
- **Exit codes are the same as for lockfiles.** `2` when the registry refuses
  the pull or a finding meets `--fail-on`; `3` when the image has not been
  scanned (scanning off, platform not on the scan list, or `--wait` ran out).
  Findings on the policy's accepted-risk list do not count, because the
  registry does not count them either.
- `--fix` does not apply: rebuild on a patched base image instead.

### Other flags

```bash
minireg audit --json       # machine readable
minireg audit --offline    # do not scan packages the registry has not seen
minireg audit --refresh    # re-query OSV even for versions already scanned
```

`--offline` is instant but blind to anything this registry has never served.
Without it, anything the registry lacks CVE data for is looked up on demand —
including packages it has mirrored but not yet scanned, which is the normal
state of a new registry.

---

## Searching

```bash
minireg search express                                # packages and images
minireg search requests --ecosystem pypi --limit 10   # or: npm, cargo, docker

minireg info lodash
minireg info requests --ecosystem pypi
minireg info --ecosystem docker alpine:3.20
minireg info --ecosystem docker redis:7.4-alpine --platform linux/arm64
```

`info` shows versions, known CVEs per version, and which upstreams carry the
package with links to their pages. For an image it shows the platforms, size,
scan status, findings by severity (known-exploited first), the pull verdict
and recent tags — the same report as `audit --image`, without the exit code.

A plain `search` lists matching images after the packages. Images are found by
the name they are cached under, so `search busybox` finds both
`busybox` (Docker Hub) and `quay/prometheus/busybox`.

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

Gate the image a job is about to ship on the registry's verdict:

```bash
docker push "$IMAGE"
minireg audit --image "$IMAGE" --fail-on critical
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
| `configure [npm\|pip\|cargo\|docker\|all]` | Point package managers at the registry; `docker` logs the container client in |
| `audit [path]` | Check dependencies for CVEs |
| `audit --fix` | Rewrite declarations to versions that clear them |
| `audit --image REF` | Check a container image's scan and pull verdict |
| `search <query>` | Search packages and images |
| `info <package>` | Show a package (`--ecosystem docker` for an image) |
| `update` | Update this CLI from the registry |

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
| `CARGO_HOME` | Cargo config location (default `~/.cargo`) |

### Files

| Path | Contents |
|---|---|
| `~/.config/minireg/config.json` | Registry URL, token, username. Mode `600` |
| `~/.npmrc` | Written by `configure`, in a marked block |
| `~/.config/pip/pip.conf` | Written by `configure`, in a marked block |
| `~/.cargo/config.toml` | Written by `configure`, in a marked block. Honours `CARGO_HOME` |
| `~/.docker/config.json` | Written by `docker login` when you run `configure docker`, not by minireg |

---

## Notes

**`logout` does not revoke.** It deletes the local token; the token stays valid
server-side. Revoke it in **API tokens** if a machine is lost.

**Approval codes expire in 10 minutes** and are single-use.

**The CLI updates itself.**

```bash
minireg update           # install the version this registry ships
minireg update --check   # report only; exits 1 if an update exists
```

You will not usually need to run it unprompted. The registry stamps every API
response with the CLI version it ships, so the CLI compares against its own as
a side effect of traffic it was making anyway and says one line when it has
fallen behind:

```
  note: this registry ships CLI 1.3.0, you have 1.2.0 — run 'minireg update'
```

That costs no extra request, and it goes to stderr — piping `--json` output
stays clean.

Before overwriting itself the update checks three things: the download matches
the SHA-256 the registry advertised, it compiles as Python, and it actually
looks like this program. Any failure aborts without touching the installed
file, because a half-written script would leave nothing to recover with. The
replacement is an atomic rename within the same directory, and the executable
bit is preserved.

If the CLI lives somewhere you cannot write, it says so and suggests
`sudo minireg update` or re-running the installer.

`--check` is useful in CI to fail a pipeline that is pinned to a stale client:

```bash
minireg update --check || echo "CLI is out of date"
```
