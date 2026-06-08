/* DepCheck — client-side dependency-risk scanner. A Copper Bay Labs product.
 *
 * WHAT LEAVES THE BROWSER: nothing except public package LOOKUPS by name+version.
 * A package.json carries no secrets, but we still transmit only package names
 * and version strings — never the raw manifest — and only to two public,
 * CORS-enabled endpoints:
 *   - https://api.osv.dev/v1/querybatch     (known vulnerabilities)
 *   - https://registry.npmjs.org/<pkg>      (publish date + license)
 * No backend of our own, no API keys, no analytics, no cookies, no storage.
 * Every network call is best-effort with a timeout and degrades to OFFLINE
 * checks (typosquats + manifest hygiene) when the network is unavailable.
 *
 * All user/registry-derived text is inserted via textContent / el() — never
 * innerHTML — so a malicious package name or license string cannot inject
 * markup or run script.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Severity ordering / metadata (mirrors LeakCheck's stylesheet)
   * ------------------------------------------------------------------ */
  var SEVERITIES = ["critical", "high", "medium", "low"];
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  // Maps full severity -> abbreviated class suffix used by .sev-count.crit/.high/.med/.low
  var SEV_ABBR = { critical: "crit", high: "high", medium: "med", low: "low" };
  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  var NET_TIMEOUT_MS = 7000; // per-request best-effort ceiling — never hang
  var FRESHNESS_MONTHS = 24; // flag packages not published in > this many months

  /* ------------------------------------------------------------------ *
   * ~150 of the most-installed npm packages, for typosquat detection.
   * A dependency name within edit-distance 1–2 of one of these (but not an
   * exact match) is a classic typosquat / confusion risk.
   * ------------------------------------------------------------------ */
  var POPULAR = [
    "react", "react-dom", "lodash", "express", "chalk", "commander", "axios",
    "moment", "request", "debug", "async", "bluebird", "underscore", "webpack",
    "babel-core", "typescript", "eslint", "prettier", "jest", "mocha", "chai",
    "sinon", "rimraf", "glob", "minimatch", "mkdirp", "uuid", "dotenv", "yargs",
    "inquirer", "ora", "node-fetch", "cross-env", "concurrently", "nodemon",
    "ts-node", "tslib", "rxjs", "redux", "react-redux", "redux-thunk",
    "react-router", "react-router-dom", "next", "vue", "vue-router", "vuex",
    "angular", "jquery", "bootstrap", "tailwindcss", "postcss", "autoprefixer",
    "sass", "node-sass", "less", "styled-components", "emotion", "classnames",
    "prop-types", "immutable", "ramda", "date-fns", "dayjs", "luxon",
    "validator", "joi", "yup", "zod", "ajv", "cors", "helmet", "morgan",
    "body-parser", "cookie-parser", "passport", "jsonwebtoken", "bcrypt",
    "bcryptjs", "mongoose", "mongodb", "mysql", "mysql2", "pg", "sequelize",
    "knex", "redis", "ioredis", "socket.io", "ws", "graphql", "apollo-server",
    "apollo-client", "@apollo/client", "express-session", "multer", "nodemailer",
    "winston", "pino", "log4js", "fs-extra", "shelljs", "execa", "del", "tmp",
    "semver", "chokidar", "esbuild", "rollup", "vite", "parcel", "gulp", "grunt",
    "browserify", "core-js", "regenerator-runtime", "@babel/core",
    "@babel/preset-env", "@babel/runtime", "babel-loader", "css-loader",
    "style-loader", "file-loader", "url-loader", "html-webpack-plugin",
    "mini-css-extract-plugin", "terser", "uglify-js", "cheerio", "jsdom",
    "puppeteer", "playwright", "selenium-webdriver", "supertest", "nock",
    "faker", "@faker-js/faker", "nanoid", "qs", "querystring", "form-data",
    "got", "superagent", "needle", "undici", "cross-fetch", "isomorphic-fetch",
    "lodash.merge", "lodash.get", "deepmerge", "object-assign", "extend",
    "color", "colors", "kleur", "picocolors", "figlet", "boxen", "cli-table",
    "progress", "listr", "enquirer", "prompts", "minimist", "meow", "arg",
    "react-native", "expo", "electron", "three", "d3", "chart.js", "leaflet",
    "framer-motion", "swr", "react-query", "@tanstack/react-query", "formik",
    "react-hook-form", "i18next", "react-i18next", "marked", "highlight.js",
    "prismjs", "dompurify", "sanitize-html", "slugify", "pluralize",
    "humanize-duration", "ms", "pretty-bytes", "filesize", "mime", "mime-types",
    "content-type", "raw-body", "on-finished", "destroy", "etag", "fresh",
    "send", "serve-static", "type-is", "vary", "accepts", "negotiator"
  ];
  var POPULAR_SET = Object.create(null);
  for (var pi = 0; pi < POPULAR.length; pi++) POPULAR_SET[POPULAR[pi]] = true;

  /* ------------------------------------------------------------------ *
   * Damerau-Levenshtein edit distance (with transpositions), capped.
   * Returns the distance, short-circuiting once it provably exceeds `max`.
   * ------------------------------------------------------------------ */
  function editDistance(a, b, max) {
    if (a === b) return 0;
    var la = a.length, lb = b.length;
    if (Math.abs(la - lb) > max) return max + 1;
    if (la === 0) return lb;
    if (lb === 0) return la;
    var prevPrev = [];
    var prev = [];
    var cur = [];
    var i, j;
    for (j = 0; j <= lb; j++) prev[j] = j;
    for (i = 1; i <= la; i++) {
      cur[0] = i;
      var rowMin = cur[0];
      var ca = a.charCodeAt(i - 1);
      for (j = 1; j <= lb; j++) {
        var cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
        var del = prev[j] + 1;
        var ins = cur[j - 1] + 1;
        var sub = prev[j - 1] + cost;
        var v = del < ins ? del : ins;
        if (sub < v) v = sub;
        // transposition
        if (i > 1 && j > 1 &&
            a.charCodeAt(i - 1) === b.charCodeAt(j - 2) &&
            a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
          var tr = prevPrev[j - 2] + cost;
          if (tr < v) v = tr;
        }
        cur[j] = v;
        if (v < rowMin) rowMin = v;
      }
      if (rowMin > max) return max + 1;
      prevPrev = prev.slice();
      prev = cur.slice();
    }
    return prev[lb];
  }

  /* ------------------------------------------------------------------ *
   * Manifest parsing.
   * Accepts: package.json, package-lock.json (npm v1/v2/v3), yarn.lock.
   * Produces a list of { name, range, resolved, license? } entries plus
   * meta flags (hasLockfile, isLockfile, declaredCount).
   * ------------------------------------------------------------------ */
  function parseManifest(text) {
    var out = { deps: [], meta: { hasLockfile: false, isLockfile: false, source: "unknown", declaredCount: 0, parseError: null, lifecycleScripts: [] } };
    var trimmed = (text || "").replace(/^﻿/, "").trim();
    if (!trimmed) return out;

    // Try JSON first (package.json or package-lock.json).
    var json = null;
    if (trimmed.charAt(0) === "{") {
      try { json = JSON.parse(trimmed); } catch (e) { out.meta.parseError = e && e.message ? e.message : "Invalid JSON"; }
    }

    if (json && typeof json === "object") {
      // package-lock.json: has lockfileVersion or a packages/dependencies map of resolved versions.
      if (json.lockfileVersion != null || isLockShape(json)) {
        out.meta.isLockfile = true;
        out.meta.hasLockfile = true;
        out.meta.source = "package-lock.json";
        parseNpmLock(json, out);
        return out;
      }
      // package.json
      out.meta.source = "package.json";
      // Capture install/lifecycle scripts (run code at install time) for hygiene.
      if (json.scripts && typeof json.scripts === "object") {
        var LIFECYCLE = ["preinstall", "install", "postinstall", "preuninstall", "uninstall", "postuninstall", "prepare", "prepublish", "prepublishOnly"];
        for (var li = 0; li < LIFECYCLE.length; li++) {
          var hook = LIFECYCLE[li];
          var body = json.scripts[hook];
          if (typeof body === "string" && body.trim()) {
            out.meta.lifecycleScripts.push({ hook: hook, body: body.trim() });
          }
        }
      }
      var roots = {};
      mergeDeps(roots, json.dependencies);
      mergeDeps(roots, json.devDependencies);
      mergeDeps(roots, json.optionalDependencies);
      mergeDeps(roots, json.peerDependencies, true);
      var names = Object.keys(roots);
      for (var n = 0; n < names.length; n++) {
        out.deps.push({ name: names[n], range: roots[names[n]].range, resolved: null, license: null, dev: roots[names[n]].peerOnly });
      }
      out.meta.declaredCount = names.length;
      return out;
    }

    // yarn.lock (custom format).
    if (/(^|\n)\s*"?[^"\n]+@[^:\n]+"?:\s*\n/.test(trimmed) || /\n\s+version\s+"/.test(trimmed)) {
      out.meta.isLockfile = true;
      out.meta.hasLockfile = true;
      out.meta.source = "yarn.lock";
      parseYarnLock(trimmed, out);
      return out;
    }

    if (!out.meta.parseError) out.meta.parseError = "Unrecognized format — paste a package.json, package-lock.json, or yarn.lock.";
    return out;
  }

  function isLockShape(json) {
    if (json.packages && typeof json.packages === "object") return true;
    // v1 lock: top-level dependencies whose values are objects with a "version" string.
    if (json.dependencies && typeof json.dependencies === "object") {
      var keys = Object.keys(json.dependencies);
      for (var i = 0; i < keys.length; i++) {
        var v = json.dependencies[keys[i]];
        if (v && typeof v === "object" && typeof v.version === "string") return true;
        break;
      }
    }
    return false;
  }

  function mergeDeps(target, obj, peerOnly) {
    if (!obj || typeof obj !== "object") return;
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (target[k] && !target[k].peerOnly) continue; // don't let peer override a real dep
      target[k] = { range: String(obj[k]), peerOnly: !!peerOnly && !target[k] };
    }
  }

  function parseNpmLock(json, out) {
    var seen = Object.create(null);
    function add(name, version, license) {
      if (!name) return;
      var key = name;
      if (seen[key]) {
        if (version && !seen[key].resolved) seen[key].resolved = cleanVersion(version);
        if (license && !seen[key].license) seen[key].license = license;
        return;
      }
      var entry = { name: name, range: version ? "^" + cleanVersion(version) : null, resolved: version ? cleanVersion(version) : null, license: license || null, dev: false };
      seen[key] = entry;
      out.deps.push(entry);
    }

    // lockfileVersion 2/3: "packages" map keyed by "node_modules/<name>".
    if (json.packages && typeof json.packages === "object") {
      var pk = Object.keys(json.packages);
      for (var i = 0; i < pk.length; i++) {
        var path = pk[i];
        if (path === "") continue; // root project
        var info = json.packages[path] || {};
        // name is the last node_modules segment
        var idx = path.lastIndexOf("node_modules/");
        var name = idx >= 0 ? path.slice(idx + "node_modules/".length) : path;
        if (info.dev || info.devOptional) { /* still report; dev deps ship to authors */ }
        add(name, info.version, normalizeLicense(info.license || (info.licenses && info.licenses[0] && info.licenses[0].type)));
      }
    }
    // lockfileVersion 1: nested "dependencies" map.
    if (json.dependencies && typeof json.dependencies === "object") {
      walkV1(json.dependencies, add, 0);
    }
    out.meta.declaredCount = out.deps.length;
  }

  function walkV1(deps, add, depth) {
    if (depth > 8) return;
    var keys = Object.keys(deps);
    for (var i = 0; i < keys.length; i++) {
      var name = keys[i];
      var info = deps[name] || {};
      add(name, info.version, normalizeLicense(info.license));
      if (info.dependencies && typeof info.dependencies === "object") {
        walkV1(info.dependencies, add, depth + 1);
      }
    }
  }

  function parseYarnLock(text, out) {
    var seen = Object.create(null);
    var blocks = text.split(/\n(?=\S)/); // each top-level block starts at col 0
    for (var b = 0; b < blocks.length; b++) {
      var block = blocks[b];
      if (!block.trim() || block.trim().charAt(0) === "#") continue;
      // First line: one or more "name@range" specifiers, comma-separated.
      var firstLine = block.split("\n")[0].replace(/:\s*$/, "").trim();
      var specs = firstLine.split(/,\s*/);
      var name = null;
      for (var s = 0; s < specs.length; s++) {
        var spec = specs[s].replace(/^"|"$/g, "").trim();
        var at = spec.lastIndexOf("@");
        if (at > 0) { name = spec.slice(0, at); break; }
      }
      if (!name) continue;
      var vm = block.match(/\n\s+version\s+"?([^"\n]+)"?/);
      var version = vm ? cleanVersion(vm[1]) : null;
      if (seen[name]) {
        if (version && !seen[name].resolved) seen[name].resolved = version;
        continue;
      }
      var entry = { name: name, range: version ? "^" + version : null, resolved: version, license: null, dev: false };
      seen[name] = entry;
      out.deps.push(entry);
    }
    out.meta.declaredCount = out.deps.length;
  }

  function cleanVersion(v) {
    if (!v) return null;
    var m = String(v).match(/(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)/);
    return m ? m[1] : String(v).replace(/^[\^~>=<\s]+/, "").trim() || null;
  }

  function normalizeLicense(lic) {
    if (!lic) return null;
    if (typeof lic === "string") return lic;
    if (typeof lic === "object" && lic.type) return lic.type;
    return null;
  }

  /* ------------------------------------------------------------------ *
   * OFFLINE CHECK 1: Typosquats / confusion (edit-distance to popular pkgs).
   * ------------------------------------------------------------------ */
  function checkTyposquats(deps) {
    var findings = [];
    for (var i = 0; i < deps.length; i++) {
      var name = deps[i].name;
      if (!name || POPULAR_SET[name]) continue;
      // Only compare the unscoped base for scoped names against unscoped popular ones.
      var base = name.indexOf("/") >= 0 ? name.slice(name.indexOf("/") + 1) : name;
      if (base.length < 3) continue;
      var best = null, bestDist = 99;
      for (var p = 0; p < POPULAR.length; p++) {
        var pop = POPULAR[p];
        if (pop === name || pop === base) { bestDist = 0; break; }
        if (Math.abs(pop.length - base.length) > 2) continue;
        var d = editDistance(base, pop, 2);
        if (d < bestDist) { bestDist = d; best = pop; }
      }
      if (bestDist >= 1 && bestDist <= 2 && best) {
        // Suppress obviously-distinct short collisions (e.g. "del" vs "css") by
        // requiring the names share a long common prefix OR length >= 5.
        if (base.length < 5 && bestDist === 2) continue;
        var sev = bestDist === 1 ? "critical" : "high";
        findings.push(mkFinding({
          name: deps[i].name,
          version: versionOf(deps[i]),
          severity: sev,
          title: "Possible typosquat of \"" + best + "\"",
          risk: "The dependency name \"" + deps[i].name + "\" is only " + bestDist + " character" + (bestDist === 1 ? "" : "s") + " away from the very popular package \"" + best + "\". Typosquatted packages impersonate trusted names to slip malware (install scripts, credential stealers) into your build.",
          why: "Supply-chain attackers publish look-alike names hoping a typo pulls their malicious package instead of the real one.",
          fix: "Confirm you meant \"" + deps[i].name + "\". If you intended \"" + best + "\", remove the impostor (npm uninstall " + deps[i].name + "), clear node_modules + lockfile, and reinstall the correct package. If the look-alike is intentional, verify its publisher and download counts on npmjs.com first.",
          tags: ["typosquat", "offline"]
        }));
      }
    }
    return findings;
  }

  /* ------------------------------------------------------------------ *
   * OFFLINE CHECK 2: Manifest hygiene.
   * ------------------------------------------------------------------ */
  function checkHygiene(deps, meta) {
    var findings = [];
    var BLOAT_THRESHOLD = 60;

    for (var i = 0; i < deps.length; i++) {
      var d = deps[i];
      var range = d.range != null ? String(d.range) : "";
      var lower = range.toLowerCase().trim();

      // Wildcard / loose ranges.
      if (lower === "*" || lower === "latest" || lower === "x" || lower === "" ||
          /^\d+\.x$/.test(lower) || lower === "*.*.*" || /^[\^~]?\s*x/.test(lower)) {
        findings.push(mkFinding({
          name: d.name,
          version: range || "(none)",
          severity: "high",
          title: "Unpinned / wildcard version range",
          risk: "\"" + d.name + "\" is pinned to \"" + (range || "(empty)") + "\", which resolves to whatever the registry serves at install time.",
          why: "A wildcard lets a future (possibly compromised or breaking) release install silently, making builds non-reproducible and widening your attack surface.",
          fix: "Pin to a concrete caret/tilde range, e.g. \"" + d.name + "\": \"^" + (versionOf(d) !== "unknown" ? versionOf(d) : "1.2.3") + "\", and commit a lockfile so installs are deterministic.",
          tags: ["hygiene", "offline"]
        }));
        continue;
      }

      // git / url / file / link deps.
      if (/^(git\+|git:|https?:|github:|gitlab:|bitbucket:|file:|link:|portal:)/.test(lower) ||
          /^[\w.\-]+\/[\w.\-]+(#.*)?$/.test(range) && lower.indexOf("@") !== 0) {
        // the second test catches "user/repo" github shorthand
        if (/^(git\+|git:|https?:|github:|gitlab:|bitbucket:|file:|link:|portal:)/.test(lower) ||
            /^[\w.\-]+\/[\w.\-]+(#.*)?$/.test(range)) {
          var isLocal = /^(file:|link:|portal:)/.test(lower);
          findings.push(mkFinding({
            name: d.name,
            version: range,
            severity: isLocal ? "low" : "medium",
            title: isLocal ? "Local path dependency" : "Git / URL dependency",
            risk: "\"" + d.name + "\" resolves from \"" + range + "\" instead of the npm registry.",
            why: isLocal
              ? "A file:/link: path only exists on your machine, so the install breaks for teammates and CI and is not versioned."
              : "Git/URL deps bypass registry integrity checks and version pinning; the target ref can change or disappear, and there is no provenance.",
            fix: isLocal
              ? "Publish the package (private registry or workspace) and depend on a real version, or document the path requirement clearly."
              : "Prefer a published registry version. If you must use a git source, pin to a full commit SHA (not a branch/tag) so the content cannot change underneath you.",
            tags: ["hygiene", "offline"]
          }));
          continue;
        }
      }
    }

    // No lockfile present (manifest was a bare package.json).
    if (!meta.hasLockfile && meta.source === "package.json" && deps.length > 0) {
      findings.push(mkFinding({
        name: "(project)",
        version: "—",
        severity: "medium",
        title: "No lockfile detected",
        risk: "You pasted a package.json with no accompanying lockfile (package-lock.json / yarn.lock).",
        why: "Without a committed lockfile, every install can resolve transitive dependencies to different versions, so builds are not reproducible and a poisoned sub-dependency can slip in unnoticed.",
        fix: "Run npm install (or yarn) and commit the generated lockfile. Use npm ci in CI to install exactly what the lockfile pins.",
        tags: ["hygiene", "offline"]
      }));
    }

    // Install / lifecycle scripts in a pasted package.json (run code at install time).
    if (meta.lifecycleScripts && meta.lifecycleScripts.length) {
      var hooks = [];
      var snippets = [];
      for (var ls = 0; ls < meta.lifecycleScripts.length; ls++) {
        var s = meta.lifecycleScripts[ls];
        if (hooks.indexOf(s.hook) === -1) hooks.push(s.hook);
        var snip = s.body.length > 80 ? s.body.slice(0, 80) + "…" : s.body;
        snippets.push("\"" + s.hook + "\": " + snip);
      }
      var isInstallHook = false;
      for (var ih = 0; ih < hooks.length; ih++) {
        if (/^(pre|post)?install$/.test(hooks[ih])) { isInstallHook = true; break; }
      }
      findings.push(mkFinding({
        name: "(project)",
        version: hooks.join(", "),
        severity: isInstallHook ? "medium" : "low",
        title: "Install / lifecycle script declared",
        risk: "This package.json defines lifecycle " + (hooks.length === 1 ? "script" : "scripts") + " that npm runs automatically: " + snippets.join("  |  ") + ".",
        why: "preinstall/install/postinstall (and prepare) run arbitrary shell commands on every install with no prompt — the classic vector a compromised or typosquatted package uses to steal credentials or plant a backdoor on your machine and in CI.",
        fix: "Read exactly what each lifecycle script does before trusting it. Run installs with --ignore-scripts when auditing untrusted packages, and avoid depending on packages whose install hooks you can't justify.",
        tags: ["hygiene", "offline"]
      }));
    }

    // Dependency bloat.
    if (meta.declaredCount > BLOAT_THRESHOLD) {
      findings.push(mkFinding({
        name: "(project)",
        version: String(meta.declaredCount) + " deps",
        severity: "low",
        title: "High dependency count",
        risk: "This manifest declares " + meta.declaredCount + " " + (meta.isLockfile ? "resolved" : "direct") + " dependencies.",
        why: "Every dependency is attack surface and maintenance burden — more packages mean more transitive code you don't audit and a larger chance one of them is compromised or abandoned.",
        fix: "Audit for unused or redundant packages (npx depcheck), prefer the standard library or small focused utilities, and remove anything you can inline.",
        tags: ["hygiene", "offline"]
      }));
    }

    return findings;
  }

  /* ------------------------------------------------------------------ *
   * NETWORK helper: fetch with timeout. Resolves to null on any failure so
   * callers degrade gracefully and the scan never hangs.
   * ------------------------------------------------------------------ */
  function fetchJSON(url, options, timeoutMs) {
    if (typeof fetch !== "function") return Promise.resolve(null);
    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var opts = options || {};
    if (ctrl) opts.signal = ctrl.signal;
    var timer = setTimeout(function () { if (ctrl) try { ctrl.abort(); } catch (e) {} }, timeoutMs || NET_TIMEOUT_MS);
    return fetch(url, opts).then(function (resp) {
      clearTimeout(timer);
      if (!resp || !resp.ok) return null;
      return resp.json().catch(function () { return null; });
    }).catch(function () {
      clearTimeout(timer);
      return null;
    });
  }

  /* ------------------------------------------------------------------ *
   * NETWORK CHECK 1: OSV.dev known vulnerabilities (the headline check).
   * Only packages with a resolved/pinnable version are queried.
   * ------------------------------------------------------------------ */
  function checkVulnerabilities(deps, netState) {
    var queryable = [];
    for (var i = 0; i < deps.length; i++) {
      var v = exactVersion(deps[i]);
      if (v) queryable.push({ dep: deps[i], version: v });
    }
    if (!queryable.length) return Promise.resolve([]);

    var queries = queryable.map(function (q) {
      return { package: { name: q.dep.name, ecosystem: "npm" }, version: q.version };
    });

    return fetchJSON(
      "https://api.osv.dev/v1/querybatch",
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries: queries }) },
      NET_TIMEOUT_MS
    ).then(function (data) {
      if (!data || !data.results) { netState.osv = false; return []; }
      netState.osv = true;
      var findings = [];
      var detailQueue = [];
      for (var r = 0; r < data.results.length; r++) {
        var res = data.results[r];
        if (!res || !res.vulns || !res.vulns.length) continue;
        var q = queryable[r];
        detailQueue.push({ q: q, vulns: res.vulns });
      }
      if (!detailQueue.length) return findings;

      // Fetch advisory details (severity + fixed version) for each vuln id,
      // best-effort and bounded so we never hang. Cap to keep it snappy.
      var MAX_DETAILS = 40;
      var jobs = [];
      var detailCount = 0;
      for (var d = 0; d < detailQueue.length; d++) {
        var item = detailQueue[d];
        var ids = [];
        for (var vv = 0; vv < item.vulns.length && detailCount < MAX_DETAILS; vv++) {
          ids.push(item.vulns[vv].id);
          detailCount++;
        }
        jobs.push(buildVulnFinding(item.q, ids));
      }
      return Promise.all(jobs).then(function (results) {
        for (var k = 0; k < results.length; k++) if (results[k]) findings.push(results[k]);
        return findings;
      });
    });
  }

  function buildVulnFinding(q, ids) {
    // Pull details for up to a few advisories to get severity + fixed version.
    var detailJobs = ids.slice(0, 5).map(function (id) {
      return fetchJSON("https://api.osv.dev/v1/vulns/" + encodeURIComponent(id), null, NET_TIMEOUT_MS);
    });
    return Promise.all(detailJobs).then(function (details) {
      var worst = "low";
      var fixedVersions = [];
      var advisoryIds = [];
      var summary = null;
      for (var i = 0; i < details.length; i++) {
        var det = details[i];
        if (!det) {
          // Detail fetch failed for this id; still record the bare id.
          if (ids[i]) advisoryIds.push(ids[i]);
          continue;
        }
        advisoryIds.push(det.id || ids[i]);
        var lvl = osvSeverityToLevel(det);
        if (SEV_RANK[lvl] < SEV_RANK[worst]) worst = lvl;
        var fixed = extractFixedVersion(det);
        if (fixed && fixedVersions.indexOf(fixed) === -1) fixedVersions.push(fixed);
        if (!summary && det.summary) summary = String(det.summary);
      }
      // If every detail fetch failed but OSV said this package is vulnerable,
      // still emit a finding using the raw advisory ids.
      if (!advisoryIds.length && ids.length) advisoryIds = ids.slice();
      if (!advisoryIds.length) return null;
      if (advisoryIds.length && SEV_RANK[worst] === SEV_RANK.low && details.every(function (d) { return !d; })) {
        worst = "high"; // unknown severity but confirmed-vulnerable
      }

      var idList = advisoryIds.slice(0, 6).join(", ") + (advisoryIds.length > 6 ? ", …" : "");
      var count = advisoryIds.length;
      var fixStr = fixedVersions.length
        ? "Upgrade " + q.dep.name + " to " + (fixedVersions.length === 1 ? "version " + fixedVersions[0] : "a patched version (" + fixedVersions.join(" / ") + ")") + " or later, then run npm audit fix and re-test."
        : "Upgrade " + q.dep.name + " to the latest patched release (run npm audit / npm audit fix), or replace it if no fix is available. Review the linked advisories for the exact safe version.";

      return mkFinding({
        name: q.dep.name,
        version: q.version,
        severity: worst,
        title: count === 1 ? "Known vulnerability (" + idList + ")" : count + " known vulnerabilities",
        risk: q.dep.name + "@" + q.version + " matches " + count + " published " + (count === 1 ? "advisory" : "advisories") + " in the OSV.dev database (" + idList + ")." + (summary ? " " + summary : ""),
        why: "This exact installed version has a publicly disclosed security flaw, so an attacker can look up the exploit and target your app directly.",
        fix: fixStr,
        tags: ["vulnerability", "network"]
      });
    }).catch(function () { return null; });
  }

  /* ------------------------------------------------------------------ *
   * Severity mapping from OSV/CVSS data.
   * ------------------------------------------------------------------ */
  function osvSeverityToLevel(detail) {
    // Prefer database_specific.severity, then CVSS score, then ecosystem hint.
    var raw = null;
    if (detail && detail.database_specific && detail.database_specific.severity) {
      raw = String(detail.database_specific.severity).toUpperCase();
    }
    if (raw === "CRITICAL") return "critical";
    if (raw === "HIGH") return "high";
    if (raw === "MODERATE" || raw === "MEDIUM") return "medium";
    if (raw === "LOW") return "low";

    // CVSS vector/score.
    if (detail && detail.severity && detail.severity.length) {
      for (var i = 0; i < detail.severity.length; i++) {
        var score = parseCvssScore(detail.severity[i].score);
        if (score != null) {
          if (score >= 9) return "critical";
          if (score >= 7) return "high";
          if (score >= 4) return "medium";
          return "low";
        }
      }
    }
    return "high"; // unknown but present advisory: treat as high, not silent
  }

  function parseCvssScore(score) {
    if (score == null) return null;
    var s = String(score);
    // numeric base score
    var num = parseFloat(s);
    if (!isNaN(num) && s.indexOf("/") === -1) return num;
    return null; // vector strings: skip (we don't ship a CVSS calculator)
  }

  function extractFixedVersion(detail) {
    if (!detail || !detail.affected) return null;
    for (var a = 0; a < detail.affected.length; a++) {
      var aff = detail.affected[a];
      if (!aff.ranges) continue;
      for (var r = 0; r < aff.ranges.length; r++) {
        var rng = aff.ranges[r];
        if (!rng.events) continue;
        for (var e = 0; e < rng.events.length; e++) {
          if (rng.events[e].fixed) return rng.events[e].fixed;
        }
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------ *
   * NETWORK CHECK 2 + 3: npm registry — freshness + license.
   * One GET per package serves both checks. Best-effort, bounded.
   * ------------------------------------------------------------------ */
  function checkRegistry(deps, netState) {
    if (typeof fetch !== "function") { netState.registry = false; return Promise.resolve([]); }
    var MAX_PKGS = 50; // keep the burst polite + fast
    var targets = deps.slice(0, MAX_PKGS);
    var anyOk = { v: false };

    var jobs = targets.map(function (dep) {
      var name = dep.name;
      if (!name || name === "(project)") return Promise.resolve([]);
      // Scoped names must keep the scope slash percent-encoded ('@scope%2Fpkg');
      // only the leading '@' is decoded. encodeURIComponent leaves '.', '-', '_', '~' intact.
      return fetchJSON("https://registry.npmjs.org/" + encodeURIComponent(name).replace(/^%40/, "@"), null, NET_TIMEOUT_MS)
        .then(function (meta) {
          if (!meta) return [];
          anyOk.v = true;
          var found = [];
          var fresh = freshnessFinding(dep, meta);
          if (fresh) found.push(fresh);
          var lic = licenseFinding(dep, meta);
          if (lic) found.push(lic);
          return found;
        });
    });

    return Promise.all(jobs).then(function (lists) {
      netState.registry = anyOk.v;
      var all = [];
      for (var i = 0; i < lists.length; i++) all = all.concat(lists[i]);
      return all;
    });
  }

  function freshnessFinding(dep, meta) {
    var time = meta.time || {};
    var latest = (meta["dist-tags"] && meta["dist-tags"].latest) || null;
    var lastDate = time.modified || (latest && time[latest]) || null;
    // Fall back to the newest timestamp present.
    if (!lastDate) {
      var newest = 0;
      for (var k in time) {
        if (k === "created" || k === "modified") continue;
        var t = Date.parse(time[k]);
        if (!isNaN(t) && t > newest) newest = t;
      }
      if (newest) lastDate = new Date(newest).toISOString();
    }
    if (!lastDate) return null;
    var when = Date.parse(lastDate);
    if (isNaN(when)) return null;
    var months = (Date.now() - when) / (1000 * 60 * 60 * 24 * 30.44);
    if (months <= FRESHNESS_MONTHS) return null;

    var years = Math.floor(months / 12);
    var ageStr = years >= 1 ? (years + (years === 1 ? " year" : " years")) : (Math.round(months) + " months");
    var deprecated = !!meta.versions && latest && meta.versions[latest] && meta.versions[latest].deprecated;

    return mkFinding({
      name: dep.name,
      version: versionOf(dep),
      severity: months > 48 ? "medium" : "low",
      title: deprecated ? "Deprecated package" : "Abandoned / stale package",
      risk: "\"" + dep.name + "\" was last published about " + ageStr + " ago" + (deprecated ? " and is marked deprecated by its maintainer." : "."),
      why: "Unmaintained packages stop receiving security patches; a newly discovered vulnerability in stale code may never be fixed, leaving you exposed.",
      fix: deprecated
        ? "The maintainer flagged this as deprecated — follow their suggested replacement, or migrate to an actively maintained alternative."
        : "Check the repo for recent activity. If it's truly abandoned, migrate to a maintained alternative or vendor and audit the code yourself.",
      tags: ["freshness", "network"]
    });
  }

  /* ------------------------------------------------------------------ *
   * NETWORK CHECK 4: License risk.
   * ------------------------------------------------------------------ */
  function licenseFinding(dep, meta) {
    var lic = dep.license || extractLicense(meta);
    return classifyLicense(dep, lic);
  }

  function extractLicense(meta) {
    if (!meta) return null;
    var latest = (meta["dist-tags"] && meta["dist-tags"].latest) || null;
    var fromLatest = latest && meta.versions && meta.versions[latest] ? meta.versions[latest].license : null;
    var lic = fromLatest || meta.license || (meta.licenses && meta.licenses[0]);
    return normalizeLicense(lic);
  }

  function classifyLicense(dep, licRaw) {
    var lic = licRaw == null ? null : String(licRaw).trim();
    var upper = lic ? lic.toUpperCase() : "";

    // Missing / unknown.
    if (!lic || upper === "" || upper === "UNKNOWN" || upper === "SEE LICENSE IN LICENSE") {
      return mkFinding({
        name: dep.name,
        version: versionOf(dep),
        severity: "medium",
        title: "Missing or unknown license",
        risk: "\"" + dep.name + "\" declares no recognizable license" + (lic ? " (\"" + lic + "\")." : "."),
        why: "Code with no license is \"all rights reserved\" by default — you may have no legal right to use, copy, or ship it in a commercial product.",
        fix: "Confirm the license in the package's repository. If none exists, contact the author or replace the dependency with a permissively licensed (MIT/BSD/Apache-2.0) equivalent before shipping commercially.",
        tags: ["license", "network"]
      });
    }

    if (upper === "UNLICENSED" || upper === "UNLICENCED") {
      return mkFinding({
        name: dep.name,
        version: versionOf(dep),
        severity: "high",
        title: "Proprietary / UNLICENSED package",
        risk: "\"" + dep.name + "\" is published as UNLICENSED, meaning the author explicitly forbids use without permission.",
        why: "Shipping UNLICENSED code in a product is copyright infringement unless you have a separate written license from the author.",
        fix: "Remove this dependency or obtain an explicit commercial license from the author. Do not ship it otherwise.",
        tags: ["license", "network"]
      });
    }

    // Copyleft families.
    var isAGPL = /\bAGPL/.test(upper);
    var isGPL = /(^|[^L])GPL/.test(upper) || upper.indexOf("GPL-") === 0 || upper === "GPL";
    var isLGPL = /\bLGPL/.test(upper);
    var isCopyleftOther = /\b(MPL|EPL|CDDL|EUPL|CECILL|OSL|SSPL)\b/.test(upper);

    if (isAGPL) {
      return mkFinding({
        name: dep.name, version: versionOf(dep), severity: "high",
        title: "Strong copyleft license (AGPL)",
        risk: "\"" + dep.name + "\" is licensed " + lic + ". AGPL's network clause can require you to open-source your entire application — even if you only offer it as a hosted service.",
        why: "AGPL obligations are the strictest copyleft terms and routinely conflict with closed-source / SaaS commercial models.",
        fix: "Avoid AGPL deps in proprietary products. Replace it with a permissively licensed alternative, or get legal sign-off and be prepared to release your source.",
        tags: ["license", "network"]
      });
    }
    if (isGPL && !isLGPL) {
      return mkFinding({
        name: dep.name, version: versionOf(dep), severity: "high",
        title: "Strong copyleft license (GPL)",
        risk: "\"" + dep.name + "\" is licensed " + lic + ". GPL can require that anything you distribute which links this code also be released under the GPL.",
        why: "GPL's copyleft can force you to open-source proprietary code you ship, which conflicts with most commercial licensing.",
        fix: "Confirm with legal whether your usage triggers GPL distribution terms. For commercial closed-source products, prefer an MIT/BSD/Apache-2.0 alternative.",
        tags: ["license", "network"]
      });
    }
    if (isLGPL) {
      return mkFinding({
        name: dep.name, version: versionOf(dep), severity: "medium",
        title: "Weak copyleft license (LGPL)",
        risk: "\"" + dep.name + "\" is licensed " + lic + ". LGPL is lighter than GPL but still imposes relinking / modification-sharing obligations.",
        why: "Static linking or bundling LGPL code (common in JS builds) can pull you into its copyleft terms unless you allow users to swap the library.",
        fix: "Keep LGPL code as a clearly separable, replaceable module, or consult legal. A permissive alternative avoids the question entirely.",
        tags: ["license", "network"]
      });
    }
    if (isCopyleftOther) {
      return mkFinding({
        name: dep.name, version: versionOf(dep), severity: "medium",
        title: "Copyleft license (" + lic + ")",
        risk: "\"" + dep.name + "\" is licensed " + lic + ", a file-level or weak copyleft license with sharing obligations.",
        why: "These licenses require you to publish changes to the covered files and can complicate redistribution in a commercial product.",
        fix: "Review the specific terms for your distribution model, or swap for a permissively licensed (MIT/BSD/Apache-2.0) alternative.",
        tags: ["license", "network"]
      });
    }
    return null; // permissive / acceptable
  }

  /* ------------------------------------------------------------------ *
   * Finding factory + helpers.
   * ------------------------------------------------------------------ */
  function mkFinding(o) {
    return {
      name: o.name,
      version: o.version,
      severity: o.severity,
      title: o.title,
      risk: o.risk,
      why: o.why,
      fix: o.fix,
      tags: o.tags || []
    };
  }

  function versionOf(dep) {
    if (dep.resolved) return dep.resolved;
    if (dep.range) return dep.range;
    return "unknown";
  }

  // Exact, queryable version for OSV (needs a concrete semver, not a range).
  function exactVersion(dep) {
    if (dep.resolved && /^\d+\.\d+\.\d+/.test(dep.resolved)) return dep.resolved;
    if (dep.range) {
      var m = String(dep.range).match(/^\s*[\^~]?\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)\s*$/);
      if (m) return m[1];
    }
    return null;
  }

  /* ------------------------------------------------------------------ *
   * DOM rendering — reuses LeakCheck components (.summary-bar, .finding,
   * .sev-*, .sev-badge, .fix, .empty-state). All user/registry text via el().
   * ------------------------------------------------------------------ */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text; // safe: DOM-escaped
    return node;
  }

  function sortFindings(findings) {
    findings.sort(function (a, b) {
      var sa = SEV_RANK[a.severity], sb = SEV_RANK[b.severity];
      if (sa !== sb) return sa - sb;
      return String(a.name).localeCompare(String(b.name));
    });
    // de-dupe identical (name|title|severity)
    var seen = Object.create(null), out = [];
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var k = f.name + "|" + f.title + "|" + f.severity;
      if (seen[k]) continue;
      seen[k] = true;
      out.push(f);
    }
    return out;
  }

  function render(findings, meta, netState, results, liveRegion, onCopy) {
    results.textContent = "";

    var head = el("div", "results-head");
    head.appendChild(el("h2", null, "Scan results"));
    var copyBtn = el("button", "copy-button");
    copyBtn.type = "button";
    copyBtn.id = "copy-btn";
    copyBtn.textContent = "Copy report";
    copyBtn.setAttribute("data-label", "Copy report");
    if (typeof onCopy === "function") {
      copyBtn.addEventListener("click", function (e) { e.preventDefault(); onCopy(copyBtn); });
    }
    head.appendChild(copyBtn);
    results.appendChild(head);

    // Network status note (which best-effort checks ran vs degraded offline).
    var note = networkNote(netState);
    if (note) {
      var meta2 = el("p", "results-note", note);
      results.appendChild(meta2);
    }

    if (meta.parseError) {
      var errBox = el("div", "empty-state");
      errBox.style.cssText = "background:var(--fail-bg);border-color:#eccbc6";
      var icon = el("div", "es-icon", "!");
      errBox.appendChild(icon);
      var h3e = el("h3", null, "Couldn't read that manifest");
      h3e.style.color = "#8f261b";
      errBox.appendChild(h3e);
      var pe = el("p", null, meta.parseError);
      pe.style.color = "#8f261b";
      errBox.appendChild(pe);
      results.appendChild(errBox);
      results.hidden = false;
      announce(liveRegion, "Could not parse the manifest.");
      return;
    }

    if (!findings.length) {
      var empty = el("div", "empty-state");
      empty.appendChild(el("div", "es-icon", "✓"));
      empty.appendChild(el("h3", null, "No dependency risks found"));
      var msg = meta.declaredCount > 0
        ? "Scanned " + meta.declaredCount + " " + (meta.isLockfile ? "resolved" : "declared") + " " + (meta.declaredCount === 1 ? "dependency" : "dependencies") + " — no known vulnerabilities, typosquats, abandoned packages, risky licenses, or hygiene issues surfaced. A clean scan is not a guarantee; new advisories appear daily, so re-check before each release and keep a lockfile committed."
        : "No dependencies were found in what you pasted. Paste a package.json, package-lock.json, or yarn.lock to scan.";
      empty.appendChild(el("p", null, msg));
      results.appendChild(empty);
      results.hidden = false;
      announce(liveRegion, "Scan complete. No dependency risks found.");
      return;
    }

    // Summary bar.
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) counts[findings[i].severity]++;

    var bar = el("div", "summary-bar");
    var total = findings.length;
    bar.appendChild(el("p", "summary-headline",
      total + (total === 1 ? " risk found across " : " risks found across ") +
      meta.declaredCount + " " + (meta.declaredCount === 1 ? "dependency" : "dependencies")));
    var pills = el("div", "summary-counts");
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (!counts[sev]) continue;
      var pill = el("span", "sev-count " + SEV_ABBR[sev]);
      pill.appendChild(el("span", "dot"));
      pill.appendChild(el("span", "n", String(counts[sev])));
      pill.appendChild(el("span", null, SEV_LABEL[sev]));
      pills.appendChild(pill);
    }
    bar.appendChild(pills);
    results.appendChild(bar);

    // Findings grouped by severity.
    for (var g = 0; g < SEVERITIES.length; g++) {
      var groupSev = SEVERITIES[g];
      var group = findings.filter(function (f) { return f.severity === groupSev; });
      if (!group.length) continue;
      var wrap = el("div", "finding-group");
      wrap.appendChild(el("h3", "group-head", SEV_LABEL[groupSev] + " (" + group.length + ")"));
      for (var c = 0; c < group.length; c++) wrap.appendChild(buildCard(group[c]));
      results.appendChild(wrap);
    }

    results.hidden = false;
    announce(liveRegion, "Scan complete. " + total + (total === 1 ? " risk found: " : " risks found: ") + summaryPhrase(counts) + ".");
  }

  function buildCard(f) {
    var card = el("article", "finding sev-" + f.severity);

    var head = el("div", "finding-head");
    var badge = el("span", "sev-badge sev-" + f.severity);
    badge.appendChild(el("span", "dot"));
    badge.appendChild(el("span", null, SEV_LABEL[f.severity]));
    head.appendChild(badge);
    head.appendChild(el("span", "finding-title", f.title));
    card.appendChild(head);

    // package + version chip row (uses the .pkg-meta / .pkg-name / .pkg-version contract).
    var pkgMeta = el("div", "pkg-meta");
    pkgMeta.setAttribute("aria-label", "Affected package");
    var isProject = f.name === "(project)";
    var nameChip = el("span", isProject ? "pkg-name no-icon" : "pkg-name", String(f.name));
    pkgMeta.appendChild(nameChip);
    if (f.version != null && String(f.version) !== "" && String(f.version) !== "—") {
      pkgMeta.appendChild(el("span", "pkg-version no-prefix", String(f.version)));
    }
    card.appendChild(pkgMeta);

    // Risk + why.
    card.appendChild(el("p", "finding-desc", f.risk + " " + f.why));

    // Fix block.
    var fix = el("div", "fix");
    fix.appendChild(el("span", "fix-label", "How to fix"));
    fix.appendChild(el("p", "fix-body", f.fix));
    card.appendChild(fix);

    return card;
  }

  function summaryPhrase(counts) {
    var parts = [];
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (counts[sev]) parts.push(counts[sev] + " " + SEV_LABEL[sev].toLowerCase());
    }
    return parts.join(", ");
  }

  function networkNote(netState) {
    if (netState.osv && netState.registry) {
      return "Live checks ran: OSV.dev vulnerability database + npm registry (publish dates & licenses). Only package names and versions were sent — never your manifest.";
    }
    if (!netState.attempted) {
      return "Offline checks only (typosquats + manifest hygiene). No network was used.";
    }
    if (netState.osv || netState.registry) {
      return "Some live checks degraded (network unavailable). Showing what we could verify plus offline typosquat & hygiene checks.";
    }
    return "Network unavailable — vulnerability, freshness, and license lookups were skipped. Showing offline typosquat & manifest-hygiene checks only.";
  }

  function announce(liveRegion, msg) { if (liveRegion) liveRegion.textContent = msg; }

  /* ------------------------------------------------------------------ *
   * Plain-text report for the clipboard.
   * ------------------------------------------------------------------ */
  function buildReport(findings, meta, netState) {
    var lines = [];
    lines.push("DepCheck report");
    lines.push("Generated locally in the browser. Only package names + versions were ever sent (to OSV.dev / npm registry).");
    lines.push("Source: " + meta.source + "   Dependencies scanned: " + meta.declaredCount);
    lines.push(networkNote(netState));
    lines.push("");

    if (meta.parseError) {
      lines.push("Parse error: " + meta.parseError);
      return lines.join("\n");
    }
    if (!findings.length) {
      lines.push("No dependency risks found.");
      lines.push("(A clean scan is not a guarantee; new advisories appear daily.)");
      return lines.join("\n");
    }

    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) counts[findings[i].severity]++;
    lines.push(findings.length + (findings.length === 1 ? " risk found." : " risks found."));
    lines.push("Severity: " + SEVERITIES.map(function (s) { return counts[s] + " " + s; }).join(", "));
    lines.push("");
    lines.push("----------------------------------------");
    for (var f = 0; f < findings.length; f++) {
      var x = findings[f];
      var verStr = x.version != null && x.version !== "" ? (" @ " + x.version) : "";
      lines.push("");
      lines.push("[" + SEV_LABEL[x.severity].toUpperCase() + "] " + x.title);
      lines.push("  Package: " + x.name + verStr);
      lines.push("  Risk:    " + x.risk + " " + x.why);
      lines.push("  Fix:     " + x.fix);
    }
    lines.push("");
    lines.push("----------------------------------------");
    return lines.join("\n");
  }

  /* ------------------------------------------------------------------ *
   * Example manifest — a known-vuln old version, a typosquat, an abandoned
   * package, and a GPL dep, so the demo shows real findings. The typosquat
   * and hygiene findings work fully OFFLINE.
   * ------------------------------------------------------------------ */
  var EXAMPLE = JSON.stringify({
    name: "demo-app",
    version: "1.0.0",
    scripts: {
      // A lifecycle hook that runs code at install time (flagged OFFLINE).
      "postinstall": "node ./scripts/setup.js"
    },
    dependencies: {
      // Known-vulnerable old versions (OSV will flag these when online).
      "lodash": "4.17.4",
      "minimist": "1.2.0",
      "express": "4.16.0",
      // Typosquats of popular packages (flagged OFFLINE).
      "loadsh": "1.0.0",
      "expresss": "4.18.2",
      "momentjs": "2.29.1",
      // Abandoned / legacy (freshness flags when online).
      "request": "2.88.2",
      // Hygiene: wildcard + git dep.
      "left-pad": "*",
      "some-fork": "git+https://github.com/example/some-fork.git"
    },
    devDependencies: {
      "jest": "^29.0.0",
      "reactt": "18.2.0"
    }
  }, null, 2);

  /* ------------------------------------------------------------------ *
   * Orchestration: run offline checks immediately, then enrich with network.
   * ------------------------------------------------------------------ */
  function runScan(text, results, liveRegion, onReady) {
    var parsed = parseManifest(text);
    var deps = parsed.deps;
    var meta = parsed.meta;
    var netState = { osv: false, registry: false, attempted: false };

    // Offline findings render-able instantly.
    var offline = [];
    offline = offline.concat(checkTyposquats(deps));
    offline = offline.concat(checkHygiene(deps, meta));

    // First paint: offline results (so even with no network the demo works).
    var current = sortFindings(offline.slice());
    onReady(current, meta, netState);

    if (typeof fetch !== "function" || (typeof navigator !== "undefined" && navigator.onLine === false) || meta.parseError || !deps.length) {
      return; // stay offline-only
    }
    netState.attempted = true;

    var vulnP = checkVulnerabilities(deps, netState).catch(function () { netState.osv = false; return []; });
    var regP = checkRegistry(deps, netState).catch(function () { netState.registry = false; return []; });

    Promise.all([vulnP, regP]).then(function (groups) {
      var network = [].concat(groups[0] || [], groups[1] || []);
      var merged = sortFindings(offline.concat(network));
      onReady(merged, meta, netState);
    });
  }

  /* ------------------------------------------------------------------ *
   * Wire-up.
   * ------------------------------------------------------------------ */
  function init() {
    var form = document.getElementById("scan-form");
    var textarea = document.getElementById("manifest");
    var results = document.getElementById("results");
    var exampleBtn = document.getElementById("example-btn");
    var clearBtn = document.getElementById("clear-btn");
    if (!form || !textarea || !results) return;

    var liveRegion = document.getElementById("scan-status");
    if (!liveRegion) {
      liveRegion = el("div", "sr-only");
      liveRegion.id = "scan-status";
      liveRegion.setAttribute("aria-live", "polite");
      liveRegion.setAttribute("role", "status");
      results.parentNode.insertBefore(liveRegion, results);
    }

    var last = { findings: [], meta: { source: "unknown", declaredCount: 0 }, netState: { osv: false, registry: false, attempted: false } };

    function handleCopy(btn) {
      var report = buildReport(last.findings, last.meta, last.netState);
      copyReport(report, btn);
    }

    function onReady(findings, meta, netState) {
      last.findings = findings;
      last.meta = meta;
      last.netState = netState;
      render(findings, meta, netState, results, liveRegion, handleCopy);
    }

    function scan() {
      var text = textarea.value || "";
      announce(liveRegion, "Scanning dependencies…");
      runScan(text, results, liveRegion, onReady);
      if (typeof results.focus === "function") results.focus();
      if (typeof results.scrollIntoView === "function") results.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    form.addEventListener("submit", function (e) { e.preventDefault(); scan(); });

    if (exampleBtn) {
      exampleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        textarea.value = EXAMPLE;
        textarea.focus();
        scan();
      });
    }
    if (clearBtn) {
      clearBtn.addEventListener("click", function (e) {
        e.preventDefault();
        textarea.value = "";
        last.findings = [];
        results.textContent = "";
        results.hidden = true;
        announce(liveRegion, "Cleared. Paste a manifest and scan again.");
        textarea.focus();
      });
    }
  }

  /* Clipboard copy — local only. */
  function copyReport(text, btn) {
    var original = btn.getAttribute("data-label") || btn.textContent;
    function done(ok) {
      btn.textContent = ok ? "Copied ✓" : "Copy failed";
      setTimeout(function () { btn.textContent = original; }, 1800);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", "");
      ta.style.position = "fixed"; ta.style.top = "-1000px"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand && document.execCommand("copy");
      document.body.removeChild(ta);
      done(!!ok);
    } catch (err) { done(false); }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
