# Package policy

Everything here is enforced on **metadata requests, artifact downloads, and
publishes**. There is no path that bypasses it.

Evaluation order:

1. **Block rules** — if any matches, deny. Nothing overrides this.
2. **Allowlist mode** (optional) — when on, a package must match an allow rule.
3. **CVE score policy** — deny versions inside the configured score range.

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

Globs, matched against the *normalized* name (lowercase; for PyPI, PEP 503
normalized so `Foo.Bar`, `foo-bar`, and `foo_bar` are one name).

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

## Allowlist mode

Default-deny. A package must match an **allow** rule to resolve at all.

Turn it on **after** writing the allow rules, not before — with none, nothing
resolves. The UI warns you, but it will still do what you asked.

Allow rules do not override blocks. A package matching both is blocked. Allow
rules exist to carve exceptions out of default-deny, not to override a
deliberate block.

---

## CVE policy

Blocks versions whose highest CVSS base score falls inside a range.

| Range | Effect |
|---|---|
| 9.0 – 10.0 | Critical only |
| 7.0 – 10.0 | High and critical |
| 0.0 – 10.0 | Anything with a CVE |
| 4.0 – 6.9 | Medium only (unusual, but supported) |

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

Inline scanning has a 4-second budget (`OSV_INLINE_TIMEOUT_SECONDS`). Exceeding
it does not stall the request — the version is marked unscanned and queued for
a background scan. With fail-closed on, a slow OSV therefore blocks installs.
That is the trade you are making: correctness over availability.

### Only block when a fix exists

Skips versions with no fixed release available upstream. Avoids blocking things
nobody can currently remediate, at the cost of serving known-vulnerable code.

### Where scores come from

OSV.dev, restricted to records carrying a `CVE-*` alias — GHSA-only and
MAL-only records are ignored by design, per the CVE-only requirement.

Scores are computed from the CVSS vectors OSV publishes:

- **v3.x** — computed exactly from the published equations.
- **v4.0** — *approximated*. v4 scores via a 270-entry macrovector lookup table
  that cannot be reproduced from equations. When a record publishes both, v3
  wins because it is the score we can stand behind. A v4 vector that declares
  any impact never scores below 2.0, so an approximation error cannot present a
  real vulnerability as harmless.
- **v2** — computed exactly; last resort.

If you change scoring behaviour, **Vulnerabilities → Recompute scores** re-runs
the calculation over stored OSV records without re-fetching anything, and
updates the denormalized per-version maximums the policy engine reads.

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
