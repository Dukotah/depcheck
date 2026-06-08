# DepCheck

**Are your npm dependencies a liability?**

DepCheck is a client-side dependency scanner. Paste your `package.json` or
lockfile and instantly see which dependencies are risky — known
vulnerabilities, possible typosquats, abandoned or unmaintained packages,
unexpected licenses, and install-time footguns — flagged by severity.

It combines public lookups with offline heuristics:

- **OSV vulnerability lookup** — checks each package@version against the
  [OSV.dev](https://osv.dev) advisory database (GitHub Advisories, CVEs, npm
  audit data).
- **Typosquat detection** — Levenshtein edit-distance against a list of popular
  packages, to catch names one keystroke off from the real thing.
- **Registry freshness & license** — reads public npm metadata to flag stale /
  abandoned packages and risky or missing licenses.
- **Offline hygiene checks** — install scripts, git/URL deps, and wildcard /
  unpinned ranges, all evaluated locally with no network call.

A **Copper Bay Labs** product.

- **Live:** https://dukotah.github.io/depcheck/
- **100% client-side.** Your code, `.env`, and secrets are **never** uploaded.
  The only thing that ever leaves your browser is package **names and
  versions** — the same coordinates already public on npm — sent to public,
  read-only registries (OSV and npm) to look up vulnerability and metadata
  facts. There is no DepCheck backend. The offline hygiene checks make no
  network request at all.

## Part of the ship-safety suite

DepCheck is the fourth tool in the Copper Bay Labs ship-safety suite for
vibe-coded and indie apps. Each answers a different "will this ship safely?"
question:

- **[ShipSafe](https://dukotah.github.io/shipsafe/)** — will you get *sued*?
  (ADA & privacy compliance)
- **[LeakCheck](https://dukotah.github.io/leakcheck/)** — did you leak a
  *secret* in your code? (API keys & tokens)
- **[ExposureCheck](https://dukotah.github.io/exposurecheck/)** — is your *live
  site* leaking? (exposed files, headers & endpoints)
- **DepCheck** — are your *dependencies* risky? (vulns, typosquats, licenses)
  *(you are here)*

## Run it locally

No build step, no dependencies. Just open `index.html` in any modern browser:

```
git clone https://github.com/dukotah/depcheck.git
cd depcheck
# open index.html (double-click, or `start index.html` on Windows)
```

The offline hygiene checks run with no network at all; the OSV and npm lookups
need connectivity only to fetch public vulnerability and metadata facts.

## What it is (and isn't)

DepCheck is **heuristic detection**, not a security guarantee or audit. **A
clean scan is not a guarantee.** It can miss brand-new vulnerabilities and flag
harmless packages. Treat its output as a fast first pass — alongside
`npm audit`, a committed lockfile, and a real review — not proof your
dependency tree is clean. See [How it works](about.html) for the full
methodology, the check → severity table, the privacy stance, and what to do if
you find a risky dependency.

## Roadmap

- A drop-in **pre-commit / CI dependency gate** so the same OSV, typosquat, and
  hygiene checks can block dangerous deps before they ever land in a lockfile.

---

A [Copper Bay Labs](https://copperbaytech.com) product.
