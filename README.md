# Camera Scanner

A Python tool for **RTSP camera security research**: it discovers cameras (via
the Shodan API or an Nmap sweep), tests whether they still use default/weak
credentials, and stores a proof frame. Outbound traffic is routed through a
residential proxy so probes leave from the proxy exit, not your own IP.

---

## ⚠️ Authorized use only

This tool logs into cameras and captures their video. Use it **only** against
devices you own or have **explicit written authorization** to test (your own
lab, or a pentest with a defined scope). Searching for, logging into, or
recording from cameras you do not control is unauthorized access / interception
and is illegal in most places. Staying in scope is your responsibility; the
authors are not liable for misuse.

The repo ships two sizes of credential wordlist under `wordlists/` (a 75-probe
`*_small.txt` set and a 70,470-probe full set). Keep them pointed at the targets
you are authorized to test; see [Step 3](#step-3--test-the-credentials) for the
file formats.

---

## Quickstart

```bash
uv sync                                # install deps into .venv (uv fetches Python 3.11 if needed)
docker compose up -d                   # Postgres on localhost:5433
cp config.yaml.example config.yaml     # then edit: shodan.api_key, proxy.token, DB creds
uv run python main.py --start_search   # populate the DB from Shodan
uv run python main.py --start_check -v # test default creds through the proxy (needs your wordlists)
```

First run only, create the table the app expects:

```bash
uv run python -c "from models.database import Database; from models.camera import Base; Base.metadata.create_all(Database().engine)"
```

Each step is explained below (Installation, Configuration, Usage).

---

## How it works

The scanner has five run modes and one storage layer. Everything is wired from
a single `config.yaml` (see Configuration).

```
                         config.yaml  (single source of settings + keys)
                              │
              ┌───────────────┼────────────────┐
   --start_search        --start_nmap        --start_check
   (ShodanTask)          (NmapTask)          (CheckTask)
        │                     │                    │
   Shodan API           nmap -p554 -sV       for each inactive camera:
   query → ip:port      over ip_range        try user/pass from wordlists
        │                (via http proxy)     via RtspProbe → grab 1 frame
        ▼                     ▼                    │ (found → creds + frame)
   ┌─────────────────────────────────────────────▼──────────┐
   │                 PostgreSQL  (cam table)                   │
   │        active cameras hold the working creds + frame      │
   └─────────────────────────────────────────────────────────┘
```

The diagram follows the discovery → check path. The other two modes work on
what already exists: `--start_face_scan` reads the active rows in the database,
and `--start_vuln_scan` reads an nmap XML file on disk.

**Modes** (`scanners/task.py`)
- **`--start_search` — `ShodanTask`**: runs the configured Shodan query and
  stores each `ip:port` in the database (marked inactive, no credentials yet).
- **`--start_nmap` — `NmapTask`**: runs `nmap -p 554 -sV` over `nmap.ip_range`,
  tunneled through an **http** proxy (nmap cannot use socks5), storing hosts that
  answer on the RTSP port. It fails loud if handed a proxy scheme nmap can't use.
- **`--start_check` — `CheckTask`**: for every inactive camera in the database,
  it tries the `user × password × rtsp-url` combinations from the wordlists,
  probing up to `checkers.concurrency` cameras in parallel. `RtspProbe` opens the
  stream and grabs one frame; on success the working credentials and the frame
  are saved and the camera is marked active.
- **`--start_face_scan` — `FaceScanTask`**: for every *active* camera, captures
  `face.frames_per_scan` frames, detects faces and stores their embeddings, so a
  later scan can tell the same person apart. Needs the database; it does not
  touch inactive cameras.
- **`--start_vuln_scan` — `VulnScanTask`** (`scanners/vuln_task.py`,
  `scanners/vuln_probe.py`): reads the XML an nmap run left behind, names each
  open service through `cpe_map.yaml`, and reports the CVEs in `vuln.feed_path`
  that cover it. **Identification only** — it opens no connection and sends no
  payload. Nothing in this mode contacts a device.

**CVE identification** (`scanners/vuln_probe.py`)
- `NvdRecordParser` reduces an NVD 2.0 record to its CPE ranges and CVSS score.
- `CveFeed` loads the feed lazily and indexes it by `(vendor, product)`.
- `CpeMap` translates the `product` string a scan reports ("OpenSSH") into a CPE
  vendor/product pair ("openbsd:openssh"). A new product is a YAML line, never a
  code change.
- `CpeMatchRange.covers` handles both an exact-version CPE and the bounded
  ranges NVD writes (`versionStartIncluding` / `versionEndExcluding`). An unknown
  version only matches a pattern that names no range at all, so a version-less
  banner does not produce a pile of false findings.

**Anonymisation** (`scanners/proxy.py`, `scanners/proxy_tunnel.py`)
- `TwoCaptchaProxy` resolves a residential proxy from the 2captcha API
  (whitelist or login mode).
- `AnonymousProxyClient` reaches a destination through the proxy without
  revealing it: it always CONNECT/tunnels (so the proxy can't inject
  `Proxy-Host`/`Via`/`X-Forwarded-For`), and — when `curl_cffi` is installed —
  impersonates a browser TLS (JA3/JA4) and HTTP/2 fingerprint; otherwise it
  falls back to a dependency-free stdlib CONNECT client.
- RTSP has no proxy option in FFmpeg, so `ProxyTunnel` exposes a local
  `127.0.0.1` endpoint that relays the RTSP TCP connection through the proxy
  (http CONNECT or a SOCKS5 handshake with DNS resolved at the exit), and the
  probe forces `rtsp_transport=tcp` so control and media share that one stream.
- The exit node's IP/TTL/TCP fingerprint is the residential exit's, not yours;
  that is by design.

**Storage** (`models/`)
- `models/camera.py` — the `cam` SQLAlchemy model.
- `models/database.py` — `Database` owns the engine and a transactional
  `session_scope` (commit on success, roll back on error).
- `models/managers.py` — `CameraRepository`, the only place that queries the
  table.

A successful check stores the working credentials and the proof frame
(`image_b64`) on the camera row, so the results live entirely in the database.

## Installation

Dependencies are managed with [uv](https://docs.astral.sh/uv/); `pyproject.toml`
is the single source and `uv.lock` pins exact versions.

```bash
git clone https://github.com/iklobato/shodan_rtsp
cd shodan_rtsp
uv sync                       # creates .venv, installs runtime + dev deps from the lock
```

`uv` provisions Python 3.11 itself if it is missing (see `.python-version`). To
install with plain pip instead, export a requirements file first:
`uv export --no-hashes --no-dev -o requirements.txt`.

A running PostgreSQL is required for anything that touches the database. The
repo ships a `docker-compose.yml` that starts one on `localhost:5433` (matching
the `database` block in `config.yaml.example`):

```bash
docker compose up -d          # starts postgres 16, data kept in a named volume
docker compose ps             # wait for "healthy"
docker compose down           # stop (keeps data); add -v to wipe the volume
```

`curl_cffi` is installed by `uv sync` and gives the HTTP client a real browser
TLS (JA3/JA4) fingerprint. The code keeps a dependency-free stdlib CONNECT
fallback for the rare case it is missing.

## Configuration

All settings and keys live in a single `config.yaml` (git-ignored). Start from
the template:

```bash
cp config.yaml.example config.yaml
# then edit config.yaml
```

```yaml
shodan:
  api_key: "<your_shodan_api_key>"
  query: "screenshot.label:webcam,cam country:BR"
checkers:
  wordlist_users: wordlists/users.txt          # you provide these
  wordlist_passwords: wordlists/passwords.txt
  wordlist_rtsp_urls: wordlists/rtsp_urls.txt
  randomize: true
  concurrency: 1                               # parallel RTSP probes (see below)
nmap:
  ip_range: 10.0.0.0/24                         # only ranges you are authorised to scan
  parallelism: 0                               # 0 = nmap defaults; > 0 tunes it (see below)
  xml_path: logs/nmap.xml                      # raw XML of the run; --start_vuln_scan reads this
vuln:
  nmap_xml: logs/nmap.xml                      # keep in step with nmap.xml_path
  feed_path: nvdcve-2.0.json                   # NVD 2.0 JSON (see "Vuln scan" below)
  cpe_map_path: cpe_map.yaml                   # product string -> CPE vendor:product
  min_cvss: 0.0                                # drop findings below this base score
  report_path: logs/vuln_report.json
proxy:
  enabled: true                                # false = direct from your IP (private ranges)
  token: "<your_2captcha_token>"
  auth_mode: whitelist                          # whitelist | login
  protocol: socks5                              # http | https | socks5
  country: us
database:
  user: "<postgres_user>"
  password: "<postgres_password>"
  host: "localhost:5433"                        # host[:port]; 5433 matches docker-compose.yml
  db: "cameras"
```

The config is validated on load (`scanners/config.py`): a missing section fails
fast with a clear error. `config.yaml` holds secrets, so it is never committed —
only `config.yaml.example` is.

Notes
- `proxy.enabled: false` sends every probe straight from your own IP. That is the
  only mode that works for a **private range** (192.168.x.x is unreachable through
  a residential exit) and for a box whose 2captcha account is down. Public scans
  must leave it `true`.
- In whitelist mode, your public IP must be added to the 2captcha dashboard
  first (there is no API for that step).
- `protocol: socks5` needs `curl_cffi` for the HTTP client; the nmap path always
  uses an http proxy regardless (nmap does not support socks5).
- `checkers.concurrency` — how many RTSP probes `--start_check` runs in parallel
  (a thread pool; probes are I/O-bound). `1` is the old sequential behaviour. The
  real ceiling is the **proxy exit**, not your CPU: too many concurrent streams
  through one residential exit get throttled or banned, so raise it gradually
  (8 → 16) and watch the error rate. All probes still leave via the proxy.
- `nmap.parallelism` — nmap parallelises hosts itself; this tunes it. `0` leaves
  nmap's defaults; `> 0` runs the sweep with `-T4 --min-parallelism <N>`.
- `nmap.xml_path` and `vuln.nmap_xml` are two settings for one file: the first
  says where a sweep writes its XML, the second says what the vuln mode reads.
  Point them at the same path unless you are feeding it a scan from elsewhere.
- `vuln.min_cvss` filters the report only; the feed is indexed the same way
  either way. `0.0` keeps everything NVD scored.

## Usage

```bash
uv run python main.py [--start_search | --start_nmap | --start_check
                      | --start_face_scan | --start_vuln_scan]
                     [--config config.yaml] [-v]
```

Exactly one mode is required. The **CLI flags are only** the mode, `--config`
and `-v`; everything else (parallelism, proxy, wordlists, DB, CVE settings) is
set in the config file. So you tune a run by editing `config.yaml` — or by
keeping several config files and choosing one with `--config`.

| Flag | Meaning |
|------|---------|
| `--start_search` | search Shodan (`shodan.query`) and populate the database |
| `--start_nmap` | Nmap sweep of `nmap.ip_range` for RTSP hosts; writes `nmap.xml_path` |
| `--start_check` | test credentials against the cameras already in the database |
| `--start_face_scan` | detect and match faces on the active cameras (needs the DB) |
| `--start_vuln_scan` | name the CVEs of the services in `vuln.nmap_xml` (no device is contacted) |
| `--config PATH` | config file to use (default `config.yaml`) |
| `-v`, `--verbose` | debug logging (shows each probe URL and the local tunnel) |

Every example below was run on this repo; the log lines are the real output,
trimmed to the informative ones.

### Examples — one full run, step by step

#### Step 1 — fill the database with cameras

Two ways in. Pick one.

**From Shodan** (`--start_search`) — runs `shodan.query`, stores each `ip:port`
it has not seen before, and skips the orgs and tags on the block list
(universities, hospitals, schools, ISPs). It spends your Shodan **query
credits**, one page per 100 results, so check the query first.

```bash
uv run python main.py --start_search
```

**From an nmap sweep of your own network** (`--start_nmap`) — stores only hosts
with port 554 **open**. A host that answers with the port closed is not a camera,
and inserting it would make `--start_check` burn a full credential run on every
live machine on your LAN. A private range is not reachable through a residential
exit, so this is the one case where the proxy goes off:

```yaml
# config.yaml
nmap:
  ip_range: 192.168.1.0/24
  xml_path: logs/nmap.xml
proxy:
  enabled: false         # direct from this machine; private ranges need this
```

```console
$ uv run python main.py --start_nmap
2026-11-02 00:44:27,752 INFO Starting nmap scanning on 192.168.1.0/24
2026-11-02 00:44:45,485 INFO Found 4 hosts using nmap scan
2026-11-02 00:44:45,486 INFO nmap XML written to logs/nmap.xml
2026-11-02 00:44:45,486 INFO Executors: finished nmap scan
```

Four hosts answered and none had 554 open, so the table stayed empty. The host
count moves between runs (6 on an earlier sweep) — Wi-Fi clients come and go.

#### Step 2 — see what you collected

```bash
psql "postgresql://scanner:scanner@localhost:5433/cameras" \
  -c "select id, ip, port, active from cam order by id desc limit 10;"
```

Rows arrive with `active = false` and no credentials. A successful check fills in
`user`, `password`, `url` and the proof frame in `image_b64`, and flips `active`
to true:

```bash
psql "postgresql://scanner:scanner@localhost:5433/cameras" \
  -c "select ip, port, user, password, url from cam where active;"
```

#### Step 3 — test the credentials

`--start_check` walks every **inactive** camera and tries every combination of
URL template × user × password. The three wordlists are plain text, one entry
per line:

```
wordlists/users.txt        one username per line
wordlists/passwords.txt    one password per line (a blank line means "no password")
wordlists/rtsp_urls.txt    one URL template per line
```

Templates take `{0}` user, `{1}` password, `{2}` host, `{3}` port:

```text
rtsp://{0}:{1}@{2}:{3}/
rtsp://{0}:{1}@{2}:{3}/live.sdp
rtsp://{0}:{1}@{2}:{3}/h264/ch1/main/av_stream
rtsp://{0}:{1}@{2}:{3}/cam/realmonitor?channel=1&subtype=0
```

The shipped lists come in two sizes, and the combination count is why. The
`*_small.txt` lists are 5 URLs × 3 users × 5 passwords = **75 probes per
camera**; the full ones are 45 × 29 × 54 = **70,470**. Start small, look at the
hit rate, then widen — and only ever against targets you are authorised to test.

```bash
uv run python main.py --start_check -v
```

With `-v` you see each probe and the anonymised path: the probe opens
`rtsp://...@127.0.0.1:<port>/` (a local tunnel) which relays to the real camera
through the proxy exit. Without `-v` you only get the summary lines. A camera
that opens is logged at INFO either way, so it shows up in both:

```text
INFO [!] rtsp://admin:admin@10.0.0.5:554/, user: admin, password: admin
```

`checkers.concurrency` decides how many probes run at once — a config value, not
a flag:

```yaml
checkers:
  concurrency: 16        # 16 RTSP probes at once (bounded by the proxy exit)
```

The real ceiling is the **proxy exit**, not your CPU: too many concurrent streams
through one residential exit get throttled or banned. Raise it gradually (8 → 16)
and watch the error rate.

#### Step 4 — name the CVEs

See [Vuln scan](#vuln-scan---start_vuln_scan) below: it reads the XML that
`--start_nmap` just wrote.

#### Step 5 — scan faces on the cameras that answered

```bash
uv run python main.py --start_face_scan
```

This reads the **active** rows only, so it does nothing until Step 3 found a
working login. `face.frames_per_scan`, `face.frame_interval` and
`face.match_threshold` tune it.

#### Choosing how the proxy authenticates

`--start_check` and `--start_nmap` always leave via the residential proxy unless
`proxy.enabled` is false — no flag needed. You only pick *how* it authenticates:

```yaml
# whitelist mode: add your public IP in the 2captcha dashboard first
proxy:
  enabled: true
  token: "<your_2captcha_token>"
  auth_mode: whitelist
  protocol: socks5       # http | https | socks5 (socks5 needs curl_cffi)
  country: us

# or login mode: gateway from the dashboard, no IP whitelisting
proxy:
  enabled: true
  token: "<your_2captcha_token>"
  auth_mode: login
  protocol: http
  gateway_host: "proxy.example.com"
  gateway_port: 8080
  gateway_password: "<gateway_password>"
```

#### Tuning the sweep, and keeping separate profiles

`nmap.parallelism` is the other config-only knob: `0` leaves nmap's defaults,
`> 0` runs the sweep with `-T4 --min-parallelism <N>`.

```yaml
nmap:
  ip_range: 10.0.0.0/24  # only ranges you are authorised to scan
  parallelism: 200        # runs nmap with -T4 --min-parallelism 200
```

Because every knob lives in the config file, you can keep several profiles and
pick one per run:

```bash
uv run python main.py --start_check --config config.fast.yaml -v
uv run python main.py --start_check --config config.quiet.yaml
```

---

### Vuln scan (`--start_vuln_scan`)

This mode is **identification only**: it reads an nmap XML file, a CVE feed and
a product map, and writes a report. It never opens a connection to a device, so
it is safe to point at any XML you already have.

**Step 1 — produce the XML.** `--start_nmap` writes it for you
(`nmap.xml_path`, default `logs/nmap.xml`). Any `nmap -sV -oX` file works too,
including one over more ports than 554:

```bash
nmap -sV -oX logs/nmap.xml 192.168.1.0/24
```

**Step 2 — build a CVE feed.** The mode reads NVD 2.0 JSON. Do **not** download
the full year files: they are hundreds of MB and the loader holds the whole file
in memory. Pull one product subset per product you mapped, then merge:

```bash
curl -sG 'https://services.nvd.nist.gov/rest/json/cves/2.0' \
  --data-urlencode 'virtualMatchString=cpe:2.3:a:openbsd:openssh' \
  --data-urlencode 'resultsPerPage=2000' -o nvdcve-openssh.json

jq -s '{format:"NVD_CVE", version:"2.0",
        vulnerabilities: [.[].vulnerabilities[]]}' \
  nvdcve-*.json > nvdcve-2.0.json
```

Use `virtualMatchString`, not `cpeName`: the `cpeName` form of the same endpoint
answers `HTTP 404`. Add `sleep 6` between calls — the NVD API rate-limits.

A ready-made subset ships in `samples/nvd_sample.json` (24 real records, trimmed
for size) if you want to try the mode before pulling your own.

**Step 3 — map your products.** `cpe_map.yaml` translates the `product` field a
scan reports into a CPE. Add a line per product, and check the name exists in the
NVD dictionary first, or the CVEs you find belong to a different product:

```console
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' \
    --data-urlencode 'cpeMatchString=cpe:2.3:a:openbsd:openssh' \
    --data-urlencode 'resultsPerPage=1' | jq .totalResults
297
```

Any `totalResults` above 0 means the name is real; `0` means you invented it and
the entry would quietly match nothing.

**Step 4 — run it.**

```console
$ uv run python main.py --start_vuln_scan
2026-11-02 00:45:04,218 INFO Read 5 services from logs/nmap.xml
2026-11-02 00:45:04,232 INFO 10.0.0.5:22 CVE-2024-6387 (CVSS 8.1)
2026-11-02 00:45:04,233 INFO 10.0.0.5:22 CVE-2023-38408 (CVSS 9.8)
2026-11-02 00:45:04,233 INFO 10.0.0.5:22 CVE-2023-48795 (CVSS 5.9)
2026-11-02 00:45:04,233 INFO 10.0.0.7:80 CVE-2021-41773 (CVSS 9.8)
2026-11-02 00:45:04,233 INFO 4 CVE matches in 5 services
```

That run read `logs/nmap.xml`, which held `samples/nmap_sample.xml` — a
hand-written three-host file that ships with the repo. Copy it into place to
reproduce the output above without scanning anything:

```bash
cp samples/nmap_sample.xml logs/nmap.xml
uv run python main.py --start_vuln_scan
```

`10.0.0.5:22` reports OpenSSH 9.2, which sits inside the ranges of three CVEs;
`10.0.0.7:80` reports Apache httpd 2.4.49, an exact-version match. The third
host's RTSP service reports no product, so it matches nothing — a version-less
banner does not get a pile of guesses.

Findings are also written to `vuln.report_path` as JSON:

```console
$ jq -r '.[] | "\(.host):\(.port) \(.cve_id) \(.cvss)"' logs/vuln_report.json
10.0.0.5:22 CVE-2024-6387 8.1
10.0.0.5:22 CVE-2023-38408 9.8
10.0.0.5:22 CVE-2023-48795 5.9
10.0.0.7:80 CVE-2021-41773 9.8
```

To keep only what matters, raise `vuln.min_cvss`:

```yaml
vuln:
  min_cvss: 7.0    # drop anything scored below 7.0
```

View results — active cameras and their working credentials live in the `cam`
table:

```bash
psql "postgresql://scanner:scanner@localhost:5433/cameras" \
  -c "select ip, port, user, password, url from cam where active;"
```

## Development

Run the tests (no external services needed; DB and network are faked):

```bash
uv run pytest -q
```

Lint with `uv run ruff check .` (config in `pyproject.toml`). Add a dependency
with `uv add <pkg>` (or `uv add --dev <pkg>` for tooling); both update
`pyproject.toml` and `uv.lock`.

The code follows an OO/SOLID structure: strategies behind `typing.Protocol`
(`Fetcher` backends, RTSP `Transport`), dependency injection at the composition
root (`main.py`), context managers over try/finally, and dispatch tables over
`if/elif`.

## Disclaimer

For education and authorized security research only. Do not use it against
systems you do not own or lack written permission to test. The authors are not
responsible for misuse or damage.

## License

MIT. See [LICENSE](LICENSE).
