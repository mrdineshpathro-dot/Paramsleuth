# ParamScout

Passive-first URL **parameter discovery**, evidence-based validation and
explainable prioritisation for web targets you are **explicitly authorized** to
test.

ParamScout answers one narrow question:

> *Which URL parameters does this target accept, and which of them measurably
> change the server's response?*

It is a reconnaissance aid, **not a vulnerability scanner**. It never sends an
exploit payload, never submits a form, and never labels a parameter
"vulnerable". A parameter named `redirect` is not an open redirect and a
parameter named `id` is not an IDOR — ParamScout will tell you both exist, tell
you *how it knows*, and tell you what changed when it set them to an inert
canary. The security conclusion is yours to draw, manually, inside your
authorization.

---

## Table of contents

1. [Authorized use](#authorized-use)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [Architecture and tradeoffs](#architecture-and-tradeoffs)
5. [Scope and safety model](#scope-and-safety-model)
6. [Passive discovery](#passive-discovery)
7. [Active discovery (`--active`)](#active-discovery---active)
8. [Classification and scoring](#classification-and-scoring)
9. [Request controls and safeguards](#request-controls-and-safeguards)
10. [De-duplication, normalization and state](#de-duplication-normalization-and-state)
11. [Reports](#reports)
12. [CLI reference](#cli-reference)
13. [Limitations (read this)](#limitations-read-this)
14. [Testing](#testing)
15. [Project layout](#project-layout)

---

## Authorized use

Only run ParamScout against systems you are permitted to test:

* a signed scope document, bug-bounty programme scope, or written client
  authorization that covers the hosts you pass to `--scope-host`;
* respect the programme's rate limits and rules of engagement — ParamScout's
  defaults are conservative (2 req/s per host, 2 concurrent requests, 500
  requests per run) but they are *your* responsibility to set correctly;
* remember that **even a GET request can have side effects** (logging, cache
  entries, webhook triggers, state changes on badly designed applications).
  `--active` warns about this every run and excludes destructive-looking paths
  by default;
* data you collect may be sensitive. Reports redact credentials, but the
  endpoints, parameters and response differences they contain are still
  target-specific intelligence. Store and share them accordingly.

ParamScout deliberately contains **no** WAF bypass, rate-limit evasion,
credential guessing, stealth or exploitation features, and they will not be
added.

---

## Installation

Requires **Python 3.11+**.

```bash
git clone https://github.com/mrdineshpathro-dot/Paramsleuth.git
cd Paramsleuth
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # runtime
pip install -e ".[dev]"     # + pytest, mypy, ruff
```

Verify:

```bash
paramscout --version
paramscout wordlist --count   # -> 108 built-in parameter names
```

`python -m paramscout` works too.

---

## Quick start

```bash
# 1. Analyse a URL collection with zero network activity
paramscout extract \
  --input examples/collected_urls.txt \
  --output passive.json

# 2. Crawl an authorized scope without guessing a single parameter
paramscout scan \
  --url https://app.example.test \
  --scope-host app.example.test \
  --depth 2 --max-pages 100

# 3. Controlled active discovery (opt-in, GET only)
paramscout scan \
  --url https://app.example.test/search \
  --scope-host app.example.test \
  --active --wordlist examples/parameters.txt \
  --rate 1 --concurrency 2 --max-requests 300 \
  --output findings.json --csv findings.csv --html-report report.html

# 4. Target-specific candidates from JavaScript
paramscout scan \
  --url https://app.example.test \
  --scope-host app.example.test \
  --extract-js --output js_candidates.json

# 5. Preview a scan plan without sending anything
paramscout scan \
  --input targets.txt --scope-file examples/scope.txt \
  --active --dry-run

# 6. Resume an interrupted scan
paramscout resume --state scan.sqlite
```

**Try it locally without touching a real target:**

```bash
python examples/local_demo.py
```

That starts the bundled mock web application on `127.0.0.1`, runs a full
passive + active scan, writes JSON/CSV/HTML reports to a temporary directory,
and prints proof that the off-scope host was never contacted and that no POST
request was ever sent.

---

## Architecture and tradeoffs

```
CLI (argparse)                     paramscout/cli.py
   |
   v
ScanConfig (defaults < TOML < flags)   paramscout/config.py
   |
   v
+--------------------------- engine.py ---------------------------+
|  load inputs -> Scope gate -> crawl -> passive extraction ->     |
|  CandidateSet -> (opt-in) active validation -> scoring -> report |
+------------------------------------------------------------------+
      |             |                |                 |
      v             v                v                 v
   scope.py    crawler.py      extractors/*     discovery/*
 (allowlist,  (bounded BFS,   (html, js, json,  (baseline, control,
  path rules,  scope-checked   robots, sitemap,  probes, batching,
  private-IP   links only)     archive)          confirmation)
  guard)
      |
      v
  http_client.py  <- the ONLY component allowed to open a socket
      |            (scope, budget, rate, retry, size cap, redirects)
      v
  analysis/*  (normalization, categories, scoring, dedupe)
      |
      v
  reporting/*  (rich summary, JSON, CSV, standalone HTML)   state/store.py (SQLite)
```

Design decisions worth knowing about:

| Decision | Why | Cost |
|---|---|---|
| Passive by default, `--active` opt-in | Most parameter discovery needs no guessing at all; guessing is the part that touches the target in a way it did not ask for. | Two-step workflow. |
| Differential validation with an unrelated-parameter **control** | Many applications react to *any* unexpected query string (redirect, log, re-render). Without a control that reaction is attributed to your parameter and becomes a false positive. | Two extra requests per endpoint. |
| Repeatable evidence required | A one-off difference is usually a cache miss, a rotating ad slot or an expiring session. | 2 extra requests per promising candidate. |
| Unstable endpoints become *inconclusive*, not findings | Guessing on a noisy endpoint produces noise. Saying "I could not tell" is more useful than a wrong answer. | Some endpoints yield no verdict. |
| Separate discovery / behavioural / priority scores | Conflating "it exists" with "it changed something" with "look here first" is how tools end up printing fake severities. | Three numbers instead of one. |
| Manual redirect following | Every hop must be scope-checked *before* it is requested, and credentials must never cross an origin. | Slightly more code than `follow_redirects=True`. |
| Endpoint grouping is configurable, default `strict` | Folding paths merges endpoints that servers often treat as distinct. | More endpoints, more requests. |
| SQLite state, credentials never stored | Resume files get shared, copied and committed by accident. | Re-supply `--cookie` on resume. |

---

## Scope and safety model

**Network activity requires explicit scope configuration.** Without
`--scope-host` (or `--scope-file`, or a `[scope]` section in `--config`),
`paramscout scan` refuses to start and exits with a usage error. `extract`
never opens a socket at all.

`Scope.check(url)` is the single authorization decision point. It is called for
every seed, every discovered link, every external `<script src>`, every
`robots.txt`/`sitemap.xml` URL, every redirect hop and every probe URL. It
rejects:

* anything that is not `http://` or `https://` (`file:`, `ftp:`, `gopher:`,
  `javascript:`, `data:` …);
* URLs with credentials in the authority (`https://user:pass@host/`);
* hosts not in the allowlist;
* paths matching `--exclude-path`, and paths outside `--allow-path`;
* loopback / private / link-local / reserved addresses unless
  `--allow-private-networks` is given (needed for local test apps; add
  `--resolve-hosts` to also reject hostnames that *resolve* to private
  addresses).

**Host matching is exact or dot-boundary suffix — never substring.**

| Rule | `example.test` | `www.example.test` | `notexample.test` | `example.test.evil.test` |
|---|---|---|---|---|
| `example.test` | ✅ | ❌ | ❌ | ❌ |
| `.example.test` / `*.example.test` | ✅ | ✅ | ❌ | ❌ |
| `example.test:8443` | only on port 8443 | | | |

Subdomain coverage is never implicit: you must write `.example.test` or pass
`--include-subdomains`.

**Credentials never cross an origin.** `Authorization`, `Cookie`,
`Proxy-Authorization`, `X-API-Key` and friends are only sent to the origin you
configured. A redirect to a different origin is followed *without* them (if it
is in scope at all), and `httpx`'s cookie jar is cleared after every response
so a `Set-Cookie` from one host is never replayed to another.

**Redaction is always on and cannot be disabled.** Sensitive query values
(`token=`, `api_key=`, `session=`, `code=`, JWTs, long hex/base64 blobs,
`user:pass`) are replaced with `[REDACTED]` in logs, reports, CSV cells and the
SQLite state file. Secret headers are replaced wholesale. Reproduction requests
in reports omit credentials entirely and show the canary as `[[CANARY]]`.

---

## Passive discovery

Default mode. No parameter is guessed, nothing is submitted.

| Source | What is extracted | Confidence |
|---|---|---|
| Supplied / archived URLs | query-string names, repeated names, blank values | 0.95 / 0.85 |
| HTML links, media, `<form action>` | query strings in `href`/`src`/`action` | 0.80 |
| HTML forms | every field name **including hidden fields**, plus the form method — recorded as evidence, never submitted | 0.90 |
| `data-*` attributes | query strings embedded in widget attributes | 0.55 |
| Inline JavaScript | `URLSearchParams` construction and `.set/.append/.get`, `fetch`/`axios`/XHR URL literals, `params:`/`data:` object literals, `&name=` fragments, `getParam('x')` helpers, `req.query.x` / `$_GET['x']` / `request.GET['x']` / `params[:x]` | 0.60 |
| In-scope external JavaScript | the same, with the script URL recorded in the provenance | 0.60 |
| Embedded JSON | keys under `query`/`params`, query strings inside JSON values, endpoint strings | 0.60 |
| `robots.txt` | `Allow:`/`Disallow:` paths as endpoints (+ their parameters), `Sitemap:` links | 0.65 |
| `sitemap.xml` | every `<loc>` | 0.70 |

Every candidate keeps its provenance: source kind, the document it was found
in, the URL it *belongs* to, a redacted ±60-character context snippet and a
line number. JavaScript extraction is explicitly heuristic — that context
exists so you can confirm or discard a hit in seconds.

Crawling respects `--depth`, `--max-pages`, `--max-js-files`, `--max-js-bytes`,
the content-type filter and the client's response-size cap. Off-scope links and
scripts are counted and reported, never fetched.

---

## Active discovery (`--active`)

Opt-in, GET-only, alphanumeric canaries only.

For **each** endpoint:

1. **Baselines** — fetch the endpoint `--baselines` times *unchanged*. Whatever
   differs between those responses is ordinary variation and can never count as
   evidence.
2. **Control** — one request with an unrelated random parameter
   (`psctrlXXXXXXXX=pscXXXXXXXX`). This measures what the application does to
   *any* unexpected query string.
3. **Probe** — for each candidate, `parameter=pscXXXXXXXXXX` (existing
   occurrences of that name are *replaced*, not appended — appending would test
   nothing, because most frameworks read the first occurrence).
4. **Compare** against both the baseline noise floor and the control reaction,
   on: HTTP status, redirect `Location` (recorded, never followed off-scope),
   content type, body size, normalized-text similarity, `<title>`, DOM tag
   sequence, JSON key structure, and exact canary reflection (tracked
   separately).
5. **Confirm** — every promising candidate is re-probed `--confirmations` more
   times with fresh canaries. Only a change that reproduces is reported as
   `behavioral_change`; a change that does not reproduce is reported as
   `behavioral_change_unconfirmed`.
6. **Classify** — `behavioral_change`, `behavioral_change_unconfirmed`,
   `reflection_only`, `no_change`, `inconclusive`, `error`, `skipped`.

Ordering matters when the budget is tight: candidates with target-specific
evidence are probed first, and endpoints are processed **round-robin**, so one
endpoint's 100 wordlist guesses cannot starve every other endpoint.

**Reflection is never treated as XSS.** A reflected canary with no other
change becomes `reflection_only` with a low behavioural confidence and an
explicit note. No injection testing of any kind is performed.

**Endpoints are excluded, not just de-prioritised.** A built-in list
(`/logout`, `/delete`, `/unsubscribe`, `/cancel`, `/reset-password`, `/admin/`,
…) plus your `--exclude-endpoint` regexes are never probed at all — zero
requests. Excluded endpoints still appear in the report, marked as excluded.

**Batching (`--batch N`)** sends several parameters per request with *distinct*
canaries. Its limitations are printed every time it is used and recorded in the
report:

* a change observed in a batch **cannot be attributed** to a specific
  parameter, so every member is re-probed alone before anything is reported;
* interactions are invisible — one parameter can mask another, so a quiet batch
  does not prove that no member has an effect;
* the URL-length limit (`--max-url-length`) silently shrinks the batch, and the
  dropped names are reported.

The default is `--batch 1`.

---

## Classification and scoring

**Categories** describe likely *purpose* only: redirect/navigation, resource
identifier, file/path reference, search/filtering, remote-resource reference,
debug/configuration, pagination, authentication/session, unknown. Matching runs
exact-names-first, then patterns, in priority order (so `returnUrl` is a
redirect, not a remote resource). A category is a triage hint. It is never a
vulnerability claim and it never produces a severity.

Three independent numbers, each with the reasons that produced it:

| Score | Question | Inputs |
|---|---|---|
| `discovery_confidence` (0–1) | Does this parameter really exist here? | Provenance only: real query string, form field, archive, link, JS, JSON, robots/sitemap, wordlist |
| `behavioral_confidence` (0–1) | Does setting it measurably change the response, repeatably, beyond the control? | Repeat count, which signals fired, stability, reflection |
| `review_priority` (0–100) | Where should a human look first? | `0.28·discovery + 0.34·behavioral + 0.18·rarity + 0.12·naming + 0.08·reflection` |

Rarity = how few endpoints in the collected set use that name (rare names are
less likely to be framework noise). Naming weight is the *only* place a
parameter's name influences the priority, it is capped at 12% of the score, and
every finding's reason list ends with:

> `priority is a triage ordering only; it is not a vulnerability severity`

---

## Request controls and safeguards

| Control | Flag | Default |
|---|---|---|
| Per-host request rate | `--rate` | 2.0 req/s |
| Rate scope | `--rate-scope host\|global` | `host` |
| Per-host concurrency | `--concurrency` | 2 |
| Concurrency scope | `--concurrency-scope host\|global` | `host` |
| Aggregate rate cap (always enforced) | `--global-rate` | 5.0 req/s |
| Aggregate in-flight cap (always enforced) | `--global-concurrency` | 4 |
| Timeout | `--timeout` | 15 s (connect 8 s) |
| Retries with exponential backoff + jitter | `--retries` | 2 |
| `Retry-After` honoured | — | capped at 60 s |
| Slowdown after repeated 429/503 | — | ×2 after 2 in a row |
| Stop a host after repeated 429/503 | — | after 6 in a row |
| Response body cap (streamed) | `--max-response-bytes` | 2 MB |
| Redirect cap | `--max-redirects` | 5 |
| Global request budget | `--max-requests` | 500 |
| Per-endpoint request budget | `--max-requests-per-endpoint` | 40 |
| Probe URL length cap | `--max-url-length` | 2000 |
| Proxy for authorized inspection | `--proxy` | off |
| TLS verification | `--insecure-skip-tls-verify` to disable | **on** |
| User-Agent | `--user-agent` | `ParamScout/<version> (authorized security testing; …)` |

**`--rate` and `--concurrency` are per host** unless you set the matching
`--*-scope global`. The global caps are enforced *in addition*, so aggregate
pressure stays bounded either way.

Budget exhaustion is fail-closed: once a budget is spent, further candidates
are marked `skipped` with the reason recorded — they are never silently
dropped and never sent.

Ctrl+C is handled gracefully: the current gather unwinds cleanly, partial
results are scored and written, `stats.interrupted` is set, and the report says
so.

---

## De-duplication, normalization and state

Candidates are de-duplicated by **(endpoint, parameter name)**. Names are not
case-folded, so `?ID=1` and `?id=1` remain two candidates — plenty of stacks
treat them differently, and the report shows both.

URL handling rules:

* paths and parameter names are **never** lower-cased;
* repeated parameters and blank values are preserved, in order;
* percent-encoding is preserved verbatim (`/a%2Fb` ≠ `/a/b`);
* only the fragment is dropped for de-duplication;
* parameter order is preserved, so `?a=1&b=2` and `?b=2&a=1` are **not**
  deduplicated.

Endpoint grouping (`--endpoint-grouping`): `strict` (default),
`ignore-trailing-slash`, `case-folded-path`, `origin-only`. Folding is
convenient and lossy: it can merge endpoints the application treats as
distinct, which is why it is opt-in and documented in the report.

**Response normalization** is what makes "the page changed" mean something.
Before comparison, ParamScout strips configurable noise containers (ad and
recommendation selectors), removes comments, masks rotating values
(ISO/`HH:MM:SS` timestamps, dates, epochs, UUIDs, hex and base64 blobs, JWTs,
long numbers, `nonce=`/`csrf=`/`_token=` attributes, sensitive `<input>`
values), collapses whitespace, and hashes the visible text and the DOM tag
sequence separately. JSON responses are compared by key-path structure, not by
value.

**State** lives in one SQLite file (`--state`). It stores scope, settings,
endpoint progress, candidates, findings and aggregate counters. It does **not**
store cookies or `Authorization` headers — that is not configurable. `paramscout
resume --state scan.sqlite` continues only the endpoints that were left
unfinished, and warns that credentials must be re-supplied.

---

## Reports

* **Rich terminal summary** — scope, request counters, top findings, warnings,
  and a standing reminder that priority is not severity.
* **JSON** (`--output`) — the canonical document: scope, settings (with
  credentials replaced), stats, per-endpoint active detail (baselines, control,
  per-probe deltas), findings, limitations, warnings.
* **CSV** (`--csv`) — one row per finding, spreadsheet-ready.
* **Standalone HTML** (`--html-report`) — no external resources,
  `no-referrer`, and **every** interpolated value passed through `html.escape`.
  Findings contain attacker-influenced text (parameter names, reflected
  canaries, page titles, extraction snippets), so the renderer treats all of it
  as untrusted.

Every finding carries: endpoint, parameter, category + why, sources + evidence
(with context snippets), discovery confidence + reasons, behavioural status,
confidence and notes, observed differences, reflection status and count,
validation attempt count, manual-review priority + reasons,
inconclusive/error status where relevant, and a sanitized reproduction request.

Reports always include totals for: requests sent (by purpose and status),
retries, throttling events, off-scope URLs skipped, budget-skipped requests,
transport errors, truncated responses, elapsed time, interruption status, and
the scan's limitations.

---

## CLI reference

```
paramscout extract  --input FILE... [--url URL...] [--scope-host H...]
                    [--output F] [--csv F] [--html-report F] [--quiet]
                    Offline analysis. Makes no network requests.

paramscout scan     --url URL... | --input FILE...
                    --scope-host H... | --scope-file F
                    [--allow-path P] [--exclude-path P] [--include-subdomains]
                    [--allow-private-networks] [--resolve-hosts]
                    [--depth N] [--max-pages N] [--max-js-files N]
                    [--extract-js/--no-extract-js] [--external-js/--no-external-js]
                    [--robots/--no-robots] [--sitemap/--no-sitemap]
                    [--rate F] [--rate-scope host|global]
                    [--concurrency N] [--concurrency-scope host|global]
                    [--global-rate F] [--global-concurrency N]
                    [--timeout F] [--retries N] [--max-redirects N]
                    [--max-response-bytes N] [--max-url-length N]
                    [--max-requests N] [--max-requests-per-endpoint N]
                    [--proxy URL] [--header 'N: V'] [--cookie 'n=v']
                    [--user-agent S] [--insecure-skip-tls-verify]
                    [--active] [--wordlist F...] [--no-builtin-wordlist]
                    [--baselines N] [--confirmations N] [--batch N]
                    [--max-candidates-per-endpoint N] [--max-active-endpoints N]
                    [--exclude-endpoint REGEX...]
                    [--config F] [--state F] [--dry-run]
                    [--output F] [--csv F] [--html-report F] [--quiet]

paramscout resume   --state FILE [--cookie 'n=v'] [--header 'N: V']
                    [--max-requests N] [--output F] [--csv F] [--html-report F]

paramscout wordlist [--count]
```

Exit codes: `0` success, `1` error, `2` usage error, `130` interrupted (partial
results were still written).

Configuration file (`--config`, TOML — see `examples/config.toml`): precedence
is built-in defaults < file < CLI flags. A flag you did not pass leaves the
file's value untouched.

---

## Limitations (read this)

* **Not a vulnerability scanner.** No finding is a vulnerability and no
  severity is emitted, by design.
* **Categories come from names.** `redirect` may be a harmless internal view
  name; `id` may be a UUID you cannot enumerate.
* **JS and JSON extraction is heuristic.** Bundled/minified code produces both
  misses and junk. Every hit carries its source context so you can check it.
* **Passive discovery cannot see unreferenced parameters.** If a parameter is
  never mentioned in a URL, form, script or JSON blob, only a wordlist probe
  will find it.
* **GET only.** Parameters accepted exclusively via `POST`/`PUT`/`DELETE`
  bodies are out of reach — deliberately, because submitting forms can change
  state.
* **Differential results depend on stability.** Endpoints whose baselines
  disagree are reported `inconclusive`. That is honest, not a bug.
* **Reflection ≠ XSS.** No injection testing is performed, ever.
* **A quiet batch proves nothing** about its individual members.
* **Endpoint folding can merge distinct endpoints**; the default `strict` mode
  does not fold.
* **Differently encoded paths and reordered parameters are treated as distinct
  inputs**, so the same logical endpoint can appear twice.
* **DNS rebinding / hostnames pointing at internal addresses** are not detected
  unless you pass `--resolve-hosts`.
* **Rate limits are per host, not per account.** A shared backend behind many
  hostnames still sees aggregate traffic; use `--global-rate`.

---

## Testing

```bash
pip install -e ".[dev]"
pytest                      # 144 tests, all local, no public network access
pytest tests/test_active.py -v
mypy paramscout
ruff check paramscout tests
```

The suite runs against `tests/mockapp.py`, a threaded local web application
that implements every behaviour ParamScout has to reason about correctly:

| Route | Behaviour |
|---|---|
| `/` | links, forms (incl. hidden fields), `data-*`, inline JS, in-scope + off-scope scripts |
| `/search` | `q` and `sort` change the page content |
| `/profile` | `note` is reflected and *nothing else* changes |
| `/static-page` | ignores every parameter |
| `/dynamic` | fresh timestamp, epoch, UUID and CSRF token on every response |
| `/limited` | 429 + `Retry-After` for the first three hits |
| `/leave` | 302 to a **different host** (off scope) |
| `/redir-inscope` | 302 to an in-scope URL |
| `/checkout` | fake state-changing endpoint (excluded by scan config) |
| `/sensitive` | reacts to *any* parameter — the control-parameter false-positive trap |
| `/chaotic` | genuinely unstable: structure and text differ every time |
| `/product` | `id` changes both text and structure |
| `/echoauth` | reports *whether* credential headers arrived (never their values) |
| `/robots.txt`, `/sitemap.xml`, `/static/app.js` | discovery sources |

A second server runs on `localhost` while the primary runs on `127.0.0.1`, so
the suite can prove that off-scope redirects are never followed and that
credentials never cross an origin.

Coverage includes: query parsing (blanks, repeats, encoding), scope matching
and off-scope redirect rejection, HTML/form/JS/JSON/robots/sitemap/archive
extraction, dynamic-response normalization, the unknown-parameter control,
reflection-only handling, individually validated batch discoveries, rate
limits, retries, `Retry-After`, budget enforcement, secret redaction,
cross-origin credential handling, report escaping, and interrupted + resumed
scans.

---

## Project layout

```
paramscout/
  cli.py              argparse CLI: extract / scan / resume / wordlist
  config.py           dataclass settings, TOML loading, flag precedence
  scope.py            the single authorization gate (hosts, paths, private-IP guard)
  urls.py             URL parsing, query pairs, endpoint keys, normalization
  redaction.py        always-on credential and secret redaction
  http_client.py      the only component that touches the network
  throttle.py         rate limiters, semaphores, budgets, Retry-After, backoff
  crawler.py          bounded, scope-checked passive crawler
  engine.py           end-to-end orchestration, findings assembly, dry-run plan
  wordlists.py        conservative built-in list + wordlist loading
  models.py           Evidence, Candidate, fingerprints, findings, stats
  extractors/         html, javascript, jsonblobs, robots, sitemap, archive
  discovery/          passive assembly; baseline/control/probe/confirm pipeline
  analysis/           normalization, categories, scoring, de-duplication
  reporting/          rich summary, JSON, CSV, standalone HTML
  state/store.py      SQLite resume store (never stores credentials)
tests/                144 tests + mockapp.py (the local mock application)
examples/             wordlist, scope file, config, URL dump, local_demo.py, reports/
```

## License

MIT — see [LICENSE](LICENSE).
