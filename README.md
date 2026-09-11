# ParamScout

**URL parameter discovery and analysis for authorized bug bounty hunting.**

ParamScout finds the parameters that an application actually uses, tells you
*where* each one was discovered, and — only when you opt in — probes them with
safe, conservative requests so you can prioritize manual review. It is a
reconnaissance and triage aid, **not** a vulnerability scanner: it never sends
exploit payloads, never claims a parameter is "exploitable", and never implies
a finding is a vulnerability.

> **Authorized use only.** Run ParamScout solely against systems you own or
> where you hold explicit, written permission. Every scan requires an explicit
> scope allowlist (see [Authorized use](#authorized-use)).

---

## Contents

- [Features](#features)
- [How it decides what matters](#how-it-decides-what-matters)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Scope and safety controls](#scope-and-safety-controls)
- [Configuration file](#configuration-file)
- [Output formats](#output-formats)
- [Commands](#commands)
- [Examples](#examples)
- [Privacy](#privacy)
- [Limitations](#limitations)
- [Development](#development)
- [Author & support](#author--support)
- [Authorized use](#authorized-use)
- [License](#license)

---

## Features

- **Offline extraction** — feed it a file of collected URLs (or local
  HTML/JS/JSON files) and it reports every parameter with its source, with
  *zero* network requests.
- **Passive discovery** (default) — crawl the authorized scope and extract
  parameters from:
  - query strings of in-scope links and assets,
  - HTML forms (methods and fields are recorded; forms are **never** submitted),
  - inline and in-scope external JavaScript (`URLSearchParams`, `query-string`,
    `fetch`, `axios`, embedded JSON config),
  - `robots.txt` / `sitemap.xml` when enabled.
- **Active discovery** (opt-in, `--active`) — conservative, GET-only probing
  with safe alphanumeric canary values and a small user wordlist / built-in
  common-parameter list. One candidate per probe by default; batching is
  available but findings are always re-validated individually.
- **Stability-aware analysis** — multiple baselines per endpoint, an unrelated
  random-parameter control, and individual re-tests before a behavioral change
  is reported. Unstable endpoints are marked *inconclusive* instead of guessed.
- **Honest reporting** — discovery confidence, behavioral-change confidence,
  and a *manual-review priority* are reported separately. Reflection is tracked
  but is never labeled a vulnerability; priorities are never called severities.
- **Budget & rate discipline** — global and per-endpoint request budgets,
  per-host rate and concurrency, retries with backoff/jitter, `Retry-After`
  respect, throttling detection with automatic slowdown/stop. **Every**
  request (crawl, baseline, control, probe, retry, redirect, re-test) counts
  toward the budgets.
- **Resumable state** — optional SQLite state file; interrupted scans resume
  without re-doing completed endpoints. Credentials are never persisted.
- **Clean machine output** — JSON/CSV and a self-contained, escaped HTML
  report with a generated-by footer; no banners or ANSI in files.

## How it decides what matters

Every reported candidate carries three separate signals:

1. **Discovery confidence / score** — how strong the *source* is: an actual
   form field or in-page URL query (high) vs. a weak JS keyword heuristic
   (low). Discovery is passive unless `--active` is given.
2. **Behavioral-change confidence / score** — in `--active` mode, whether
   adding the parameter changed the response in a way that is *repeatable* and
   *distinct from an unrelated random parameter on the same endpoint*. Response
   dimensions compared: HTTP status, redirect destination (never followed
   off-scope), content type, body size, title, normalized visible text,
   DOM structure, JSON structure, and exact canary reflection.
3. **Manual-review priority** — a triage label (`low` / `medium` / `high`)
   derived only from the evidence above plus category hints. It is a
   *prioritization for a human*, not a severity rating.

Candidates whose only signal is "the page echoed my value" are reported as
reflection observations with an explicit note that reflection alone is not a
vulnerability. False positives from timestamps, session expiry, rate limiting,
or generic query handling are suppressed by the baseline/control/re-test
pipeline and flagged *inconclusive* where they cannot be ruled out.

## Installation

Requires **Python 3.11+**.

```bash
# From a clone of this repository
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# or install from the package index / a wheel:
pip install paramscout
```

Verify:

```bash
paramscout --version
paramscout --about
```

Run the local test suite (uses an in-process mock application — no network,
no external services):

```bash
python -m pytest
```

## Quick start

```bash
# 1) Offline: analyze collected URLs / local files, no network at all
paramscout extract --input collected_urls.txt --output passive.json
paramscout extract --input collected_urls.txt --output passive.csv --output-html passive.html

# 2) Passive crawl of an authorized target (no parameter guessing)
paramscout scan --url https://app.example.test/ --scope-host app.example.test \
    --depth 2 --max-pages 100

# 3) Active discovery: controlled GET-only probing with a wordlist
paramscout scan --url https://app.example.test/search --scope-host app.example.test \
    --active --wordlist examples/wordlist/common_params.txt \
    --rate 1 --concurrency 2 --max-requests 300 \
    --output findings.json --output-csv findings.csv --output-html findings.html

# 4) Dry run: print the plan and budget estimate, make no requests
paramscout scan --url https://app.example.test/search --scope-host app.example.test \
    --active --dry-run

# 5) Resume an interrupted scan (re-supply credentials; they are never stored)
paramscout resume --state scan_state.sqlite --cookie "session=abc123" \
    --output findings.json
```

Every `scan` / `resume` requires explicit scope; `extract` never touches the
network.

## Scope and safety controls

- Scope is an **allowlist**: `--scope-host host` (repeatable) and/or
  `--scope-file scope.txt`. Nothing outside it is ever requested, including
  redirect targets and crawled links.
- Scope file syntax (see `examples/scope.txt`):

  ```
  # host allowlist (optionally host:port or host/path-prefix)
  app.example.test
  *.static.example.test
  -host staging.app.example.test   # explicit deny (deny wins)
  +path /api                        # require this path prefix
  -path /api/admin                  # exclude path prefixes
  ```

- Request controls: `--rate`, `--concurrency` (both **per host**),
  `--max-requests` (global budget, including retries and redirects),
  `--max-requests-per-endpoint`, `--timeout`, `--retries`,
  `--max-redirects`, `--max-response-size`, `--proxy`, `--no-verify-tls`.
- Active mode is GET-only, never submits state-changing forms, never sends
  exploit payloads, and excludes endpoints listed via `--exclude-path`.
  If a repeated `429/503` pattern is seen, ParamScout slows down and then
  stops rather than evading rate limits.
- Credentials (`--cookie`, `--header`) are kept in memory, only sent to
  explicitly authorized credential hosts, never forwarded cross-origin, and
  never written to state files or reports.

## Configuration file

Defaults for any option can be set in a TOML file and passed with `--config`;
command-line values always win:

```toml
[paramscout]
rate = 0.1            # seconds between requests to the same host
concurrency = 2       # per-host in-flight requests
timeout = 10.0
retries = 1
baseline_requests = 3
validation_retests = 1
batch_size = 1
```

See `examples/paramsleuth.toml`.

## Output formats

All writers share one row contract: endpoint, parameter, category, source,
source context, discovery confidence/score, behavior confidence/score,
manual-review priority + reasons, observed differences, reflection status,
validation attempts, inconclusive flag/note, a sanitized reproduction request,
and limitations. Files contain **no banner text**. The HTML report is
self-contained (no remote assets), escapes all untrusted content, and its
footer identifies the generating tool, version, author, and support link.

## Commands

| Command | Purpose |
| --- | --- |
| `paramscout --version` / `--about` | version, author, contact, support, authorized-use notice |
| `paramscout extract --input ...` | offline analysis of collected URLs / local files (no network) |
| `paramscout scan --url ... --scope-host ...` | passive crawl discovery (default) |
| `paramscout scan ... --active --wordlist ...` | add controlled GET-only probing |
| `paramscout scan ... --dry-run` | print scope/plan/budget estimate, make no requests |
| `paramscout resume --state ...` | continue an interrupted scan from its state file |

Run `paramscout scan --help` for the full option list.

## Examples

The `examples/` directory contains working sample inputs and outputs:

- `examples/wordlist/common_params.txt` — a small parameter wordlist,
- `examples/collected_urls.txt` — a sample "collected URLs" input file,
- `examples/scope.txt` — a sample scope allowlist file,
- `examples/paramsleuth.toml` — a sample configuration file,
- `examples/results/` — sample JSON/CSV/HTML outputs produced by this tool
  against a local mock target (host labels normalized to
  `127.0.0.1:8000` for reproducibility).

## Privacy

ParamScout contains **no telemetry**. It never sends scan results, target
URLs, credentials, error reports, or usage statistics to the author or any
external service, and it never opens the support website automatically. The
outbound HTTP User-Agent is a static string identifying the tool and version.
The author's contact details and support link exist for voluntary, human
contact only.

## Limitations

- Reflection detection is not XSS detection; behavioral differences are not
  vulnerabilities. Priority labels are for human triage only.
- Passive extraction sees only the resources you (or the crawl) provide;
  parameters hidden behind JavaScript rendering or authenticated pages will
  not be found unless the collector sees them.
- Very dynamic endpoints may be marked inconclusive by design rather than
  producing false positives.
- This project is in early development (`0.1.0`); treat output as a starting
  point for manual review, not as ground truth.

## Development

```bash
python -m pytest                 # full local suite (mock app, no network)
python -m compileall paramscout   # byte-compile check
```

Repository layout:

```
paramscout/
  cli.py            # command-line interface (extract / scan / resume)
  config.py         # run configuration + conservative defaults
  scope.py          # scope allowlist/denylist + path rules
  http_client.py    # budgeted, rate-limited, scope-checked HTTP layer
  crawler.py        # bounded in-scope crawl
  models.py         # shared data model (endpoints, candidates, findings)
  redaction.py      # credential/sensitive-value redaction
  state.py          # optional SQLite resume state (no secrets)
  extractors/       # HTML / JS / builtin-wordlist / base collector
  discovery/        # scan engine, offline analysis, wordlists
  analysis/         # response normalization, reflection, probe decisions
  reporting/        # JSON / CSV / HTML / terminal writers
tests/              # local mock-app test suite (no network)
examples/           # sample inputs, config, wordlist, outputs
```

## Author & support

ParamScout is written and maintained by **Mrdineshpathro**
(<mrdineshpathro@gmail.com>).

If you find it useful, you can support the project at
<https://buymeacoffee.com/mrdineshpathro>.

Bugs, feature ideas, and questions are welcome — please include the version
(`paramscout --version`) and, for scan issues, the *sanitized* output and
command line (never paste cookies, headers, or target URLs you are not
allowed to share).

## Authorized use

Use of ParamScout is restricted to systems **you own** or for which you hold
**explicit, written authorization** (for example, a bug bounty program whose
rules and scope cover the target). By using this tool you agree to:

- Respect the target's scope, rate limits, terms, and applicable laws.
- Configure an explicit scope allowlist and never disable the scope checks.
- Not use ParamScout for credential guessing, exploit development,
  rate-limit evasion, or any destructive/unauthorized activity.
- Treat all findings as confidential and report them through the proper
  disclosure channels.

The author assumes no liability for misuse. You are responsible for your
actions.

## License

MIT — see [LICENSE](LICENSE).
