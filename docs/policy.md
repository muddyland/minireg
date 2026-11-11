# Package policy

Everything here is enforced on **metadata requests, artifact downloads, and
publishes**. There is no path that bypasses it.

Evaluation order:

1. **Block rules** — if any matches, deny. Nothing overrides this.
2. **Allowlist mode** (optional) — when on, a package must match an allow rule.
3. **Malware** — deny versions a malicious-package advisory names. On by default.
4. **CVE score policy** — deny versions inside the configured score range. On
   by default for high and critical (7.0–10.0).
5. **New packages** — deny every version of a package that first appeared on
   a public registry less than 30 days ago. On by default.
6. **Hold on new releases** — deny releases a public registry published less
   than 3 days ago. On by default.

A fresh install protects its users without anyone opening this page: known
malware and high/critical CVEs are refused from the first install. Everything
here can be loosened, but loosening it is a decision someone makes, not the
starting point.

---

## Block rules

**Package policy → Add rule.**

| Field | Meaning |
|---|---|
| **Action** | `block` (never serve) or `allow` (permit under allowlist mode) |
| **Ecosystem** | npm, PyPI, cargo, or all |
| **Name pattern** | Glob against the normalized name |
| **Version range** | Optional. Blank covers every version |
| **Reason** | Shown to whoever gets blocked — write it for them |

Put something useful in **Reason**. It is what a developer sees when their
build breaks, and "blocked by rule" wastes everyone's afternoon where
"CVE-2021-23337, upgrade to 4.17.21" does not.

### Name patterns

Globs, matched against the *normalized* name, ignoring case (for PyPI, PEP
503 normalized so `Foo.Bar`, `foo-bar`, and `foo_bar` are one name). npm
names are case-sensitive, so `JSONStream` and `jsonstream` are different
packages, but a rule written `jsonstream` matches both: a rule can only ever
catch more spellings, never fewer.

| Pattern | Matches |
|---|---|
| `event-stream` | exactly that |
| `@evilcorp/*` | every package in the scope |
| `django-*` | every name with that prefix |
| `*` | everything — only useful with allowlist mode |

### Version ranges

npm and cargo rules take **full node-semver ranges**; PyPI rules take **PEP 440
specifier sets**.

| Ecosystem | Example | Blocks |
|---|---|---|
| npm | `4.17.20` | that exact version |
| npm | `<4.17.21` | everything before the fix |
| npm | `>=3.0.0 <3.0.2` | a compromised window |
| npm | `<2.6.9 \|\| >=3.0.0 <3.0.2` | two disjoint windows |
| npm | `^1.2.3` | `>=1.2.3 <2.0.0-0` |
| npm | `~1.2` | `>=1.2.0 <1.3.0-0` |
| npm | `1.x` | the whole 1.x line |
| npm | `1.0.0 - 2.0.0` | an inclusive span |
| PyPI | `<2.0` | everything below 2.0 |
| PyPI | `>=1.0,<2.0` | the 1.x line |
| PyPI | `~=1.4.2` | `>=1.4.2, ==1.4.*` |
| PyPI | `==1.2.3` | that exact version |

Cargo rules use the same grammar as npm — both ecosystems are semver 2.0.0 and
one engine serves both. They disagree on exactly one thing: a **bare `1.2.3`
pins that exact version here**, whereas in `Cargo.toml` it means `^1.2.3`. A
rule is read with npm's meaning, which is the stricter of the two and the safe
direction for something that decides what to block. Write `^1.2.3` explicitly
if you meant the range.

The editor previews what a range expands to as you type and lets you test a
specific version against it. Both come from the same engine that enforces the
rule, so the preview cannot drift from what actually happens.

An invalid range is rejected when you save, rather than silently matching
nothing.

**Prereleases are blocked inclusively.** This departs from npm's install-time
default, where `>=1.0.0 <2.0.0` skips `1.5.0-beta`. For a block list that would
be a hole — you would block a vulnerable line and still serve its prerelease —
so blocking errs toward blocking.

### What a blocked package looks like

| Request | Response |
|---|---|
| Package fully blocked | `403` with the reason |
| Version range blocked | Those versions vanish from the packument / index; others resolve normally |
| Blocked artifact | `403`, even if the client already has the metadata |
| Publish of a blocked name | `403` |

When `latest` pointed at a blocked version, it is repointed at the highest
surviving version rather than left dangling at something that will not install.

---

## New packages

**Package policy → New releases and packages → Block new packages.** On by
default, for 30 days.

A package that first appeared on a public registry less than 30 days ago is
refused outright, every version of it:

```
blocked as a new package: reqeusts-helper first appeared on its registry on
2026-11-05 UTC, and this registry only serves packages that are at least 30
days old, from 2026-12-05 UTC. A name that new is how typosquatted and
AI-hallucinated packages are published: check this is the package you meant.
If it is, ask an admin to exempt it
```

Attackers register the names people mistype (*typosquatting*) and the names
AI assistants invent when they hallucinate a dependency (*slopsquatting*),
then wait for someone to install them. Such a name is almost always days or
weeks old; the packages people actually mean to use have usually existed for
months or years. The message is written for whoever reads it, and that is
increasingly an AI agent: it says the name may be wrong, which is what makes
an agent go and check instead of looking for a way round the block.

"First appeared" is npm's `time.created`; elsewhere it is the package's oldest
release, when every release carries a date. A crate with releases from before
crates.io started dating them (`pubtime`, 2025) is old by definition and
never counts as new, and so is any package whose age is unknown.

The same exemptions as the hold apply: packages published to this registry,
upstreams that are not public, and **exempt** rules are never refused as new.
Packages cached before this check existed are dated from their stored
releases on the first start after upgrading.

---

## Hold on new releases

**Package policy → Hold new releases.** On by default, for 3 days.

A release that a public registry (npmjs, PyPI, crates.io) published less than
the configured number of days ago is not served: it is left out of the
packument, the simple index and the dist-tags, and a direct download is
refused with a `403` that says when it will be served:

```
held back: 1.1.0 was published 2026-11-10 09:12 UTC, and this registry serves
new releases 3 days after publication, from 2026-11-13 09:12 UTC. Use an
earlier version, or ask an admin to exempt this package
```

That window is when hijacked maintainer accounts, self-spreading npm worms and
dependency-confusion uploads do their damage: most malicious releases are
found and pulled within hours to a few days. Nobody in a home lab or a
classroom is watching advisories in real time, and an AI coding agent installs
whatever was published a minute ago, so the registry waits instead. `latest`
falls back to the newest release that is old enough, so `npm install foo`
keeps working and installs the previous release. For cargo, a held version is
served as yanked, like any blocked version.

What is never held:

- Packages published to this registry.
- Releases from an upstream that is not public. A GitLab upstream is private
  by default (it serves your own people's packages); any upstream can be
  switched with **Public registry** on its form.
- A release whose publication time the upstream does not report. npm and
  crates.io always report it; a PyPI upstream reports it only through the JSON
  simple API (PEP 700), so an HTML-only private index is never held.
- **Security fixes**, while **Serve security fixes straight away** is on (the
  default): a release that an advisory names as the fixed version for an
  older version of the same package is served at once, so the hold never
  keeps a vulnerable version in place. The advisory has to be known already;
  a fix released before its advisory reaches OSV waits like anything else, or
  until you exempt it.

### Exempt rules

An **exempt** rule (**Add exemption**) skips the hold and the new-package
check for what it matches: a pattern, optionally a version range, the same as
any rule. Use it for a package you need on release day, a new package you
have checked, or one you trust enough to take the risk.

An exemption only skips those two checks. A block rule, malware and the CVE
policy still apply: they run first.

---

## Allowlist mode

Default-deny. A package must match an **allow** rule to resolve at all.

Turn it on **after** writing the allow rules, not before — with none, nothing
resolves. The UI warns you, but it will still do what you asked.

Allow rules do not override blocks. A package matching both is blocked. Allow
rules exist to carve exceptions out of default-deny, not to override a
deliberate block.

---

## CVE policy

Blocks versions whose highest CVSS base score falls inside a range. It is on
by default, blocking 7.0–10.0 (high and critical). An install that saved its
CVE policy before this default changed keeps what it saved.

| Range | Effect |
|---|---|
| 9.0 – 10.0 | Critical only |
| 7.0 – 10.0 | High and critical |
| 0.0 – 10.0 | Anything with a CVE |
| 4.0 – 6.9 | Medium only (unusual, but supported) |

A version with no advisories at all is never blocked by the range, even one
starting at 0.0: a clean scan is recorded as a score of 0.0, but it is
recorded as clean too. A version whose advisories all score 0.0 (a CVSS
vector declaring no impact) is in a range that starts at 0.0.

It is a *range*, not a threshold, so you can block medium severity while
allowing critical. That sounds backwards but is occasionally what you want —
for example when criticals are individually reviewed and accepted while the
medium tail is not worth anyone's time.

### Unscanned versions

**Block versions that could not be scanned** is the fail-closed switch.

| Setting | Behaviour |
|---|---|
| Off (default) | An unscannable version is served. Fail open |
| On | An unscannable version is blocked. Fail closed |

"Could not be scanned" means one of two things, and neither of them is
"scanned and clean":

- OSV never answered for this version (it was down, slow, rate-limiting, or
  the version has not reached the background queue yet).
- OSV answered, the version has advisories, but none of them published a
  severity anyone could score.

That includes a version for which OSV named an advisory whose full record
could not then be fetched (a rate limit, an error or a timeout on
`/v1/vulns/{id}`, after two retries). It is left unscanned rather than
recorded as clean, whatever an earlier scan found stays in force, and the
next background pass tries again.

A version that was scanned and had no advisories records a real zero and is
never blocked by this switch. That distinction is what makes fail-closed
usable at all: an earlier release stored both cases as "no score", so turning
this on denied every package in the registry.

Inline scanning has a 4-second budget (`OSV_INLINE_TIMEOUT_SECONDS`). Exceeding
it does not stall the request — the version is marked unscanned and queued for
a background scan. With fail-closed on, a slow OSV therefore blocks installs.
That is the trade you are making: correctness over availability.

### Only block when a fix exists

Skips versions with no fixed release available upstream. Avoids blocking things
nobody can currently remediate, at the cost of serving known-vulnerable code.

It never applies to malware: see below.

### Malicious packages

A version named by a malicious-package advisory (`MAL-*`) is blocked by
**Block known malware**, which is on by default and does not depend on the CVE
score policy: turning the score range off, narrowing it, or setting **Only
block when a fix exists** never lets malware through. Such an advisory says
the release *is* malware; there is no fixed version of a backdoor, and how it
scores is not the question.

Turn **Block known malware** off only on a registry used to study malware.
Before this switch existed, malware was blocked only while the CVE policy was
enabled; existing installs have it on after upgrading whatever their CVE
policy says.

### Where scores come from

OSV.dev. `OSV_CVE_ONLY` narrows this to records carrying a `CVE-*` alias, and
now defaults to **off**.

Malicious-package advisories (`MAL-*`, from the OpenSSF malicious packages
project) are **always** kept, whatever that flag says, and are scored
critical. They are the records that say "this release is malware", and npm and
PyPI malware is almost never assigned a CVE — so filtering them out meant the
registry scanned a compromised package and recorded it as clean, which is the
opposite of the job.

Scores are computed from the CVSS vectors OSV publishes:

- **v3.x** — computed exactly from the published equations.
- **v4.0** — *approximated*. v4 scores via a 270-entry macrovector lookup table
  that cannot be reproduced from equations. When a record publishes both, v3
  wins because it is the score we can stand behind. A v4 vector that declares
  any impact never scores below 2.0, so an approximation error cannot present a
  real vulnerability as harmless.
- **v2** — computed exactly; last resort.

OSV edits its records: a score is often added or raised weeks after an
advisory is first published, and fixed releases are added as they ship. Each
scan compares the `modified` time OSV reports against the stored copy and
fetches the record again when it changed (or, when OSV reports no time, once
the copy is older than `OSV_REFRESH_INTERVAL_SECONDS`). Every stored version
linked to a refetched advisory has its highest score and fix status
recomputed at once, not when its own rescan comes round.

If you change scoring behaviour, **Vulnerabilities → Recompute scores** re-runs
the calculation over stored OSV records without re-fetching anything, and
updates the denormalized per-version maximums the policy engine reads.

---

## Where's my risk

**Risk** (admins, top of the sidebar) lists every known vulnerability in your
cached packages and images in one place, one row per vulnerability: a CVE
that is in an npm version *and* in a container image is one row with both
counted. What was served or pulled in the last 30 days (7 and 90 are a click
away) is **in use** and sorts first, then anything on CISA's known-exploited
list (KEV) or flagged as malware, then severity. That ordering is the point:
a critical CVE in a version nobody has downloaded for a year matters less than
a high one in an image every CI job pulls.

"Served" means one of the version's cached artifacts was downloaded; "pulled"
means a client fetched an affected image manifest. Expand a row to see which
versions carry it and whether policy currently blocks them, and which images
(repository, tags, platform, the package inside the image, its fixed version)
were pulled when. Suppressed advisories are left out.

---

## Testing before it bites

**Package policy → Test a package against the policy.** Enter an ecosystem,
name, and optional version, and it reports the verdict, the reason, and which
rule produced it.

Do this before adding a broad rule. `django-*` is a wider net than most people
expect.

---

## Accepting a CVE risk

**Vulnerabilities → Details → Accept risk** on a specific package/CVE pairing.

This affects `npm audit` reporting **only**. It does not lift a block — the
block list and CVE range policy are always enforced. To actually permit a
blocked version, change the rule or the range.

Every acceptance is audited with the reason you give.

---

## Recipes

**Block a specific supply-chain incident**

```
Pattern:  event-stream
Range:    >=3.3.6 <3.3.7
Reason:   2018 supply-chain incident; only 3.3.6 shipped the payload
```

**Force an upgrade past a CVE**

```
Pattern:  lodash
Range:    <4.17.21
Reason:   CVE-2021-23337 — command injection in _.template
```

**Ban a vendor's scope**

```
Pattern:  @evilcorp/*
Range:    (blank)
Reason:   Vendor not approved — see procurement ticket #1234
```

**Block criticals but allow a reviewed exception**

Set the CVE policy to 9.0–10.0, then add a version-scoped allow rule for the
package you have reviewed. Note this only helps under allowlist mode; outside
it, use **Accept risk** plus a narrower CVE range.

**Locked-down environment**

1. Add allow rules for every approved package.
2. Turn on allowlist mode.
3. Set the CVE policy to 7.0–10.0 with fail-closed on.

Expect to spend time on the allow list. That is the point.
