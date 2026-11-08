# Camera Scanner

![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![Tests 35 passed](https://img.shields.io/badge/tests-35%20passed-brightgreen)
![Ruff clean](https://img.shields.io/badge/ruff-clean-brightgreen)

A Python tool for **RTSP camera security research**. It discovers cameras (Shodan
API or an Nmap sweep), tests default and weak credentials, and stores a proof
frame. Outbound probes leave through a residential proxy, not your own IP.

> [!WARNING]
> **Authorized use only.** This tool logs into cameras and captures video. Use it
> only against devices you own or have **explicit written authorization** to test
> (your own lab, or a pentest with a defined scope). Searching for, logging into,
> or recording from cameras you do not control is unauthorized access and
> interception, and is illegal in most places. Staying in scope is your
> responsibility; the authors are not liable for misuse.
>
> The repo ships two credential wordlist sizes under `wordlists/`: a 75-probe
> `*_small.txt` set and a 70,470-probe full set. Keep them pointed at targets you
> are authorized to test. File formats are in [Test credentials](#test-credentials).

---

## Contents

- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Mode details](#mode-details)
- [Vuln scan](#vuln-scan---start_vuln_scan)
- [Development](#development)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Quickstart

| # | Step | Command |
|---|------|---------|
| 1 | Install deps and Postgres | `uv sync` then `docker compose up -d` |
| 2 | Create config | `cp config.yaml.example config.yaml` |
| 3 | Create the table (first run only) | see command below |
| 4 | Fill the DB | `uv run python main.py --start_search` |
| 5 | Test credentials | `uv run python main.py --start_check -v` |

```bash
uv sync                                # installs into .venv; uv fetches Python 3.11 if needed
docker compose up -d                   # Postgres on localhost:5433
cp config.yaml.example config.yaml     # edit: shodan.api_key, proxy.token, DB creds
```

First run only:

```bash
uv run python -c "from models.database import Database; from models.camera import Base; Base.metadata.create_all(Database().engine)"
```

Each step is explained below.

---

## How it works

Five run modes and one storage layer. Everything reads from a single
`config.yaml`.

```mermaid
flowchart LR
    CFG[config.yaml] --> MODE{run mode}

    MODE -->|--start_search| SH[ShodanTask]
    MODE -->|--start_nmap| NM[NmapTask]
    MODE -->|--start_check| CK[CheckTask]
    MODE -->|--start_face_scan| FS[FaceScanTask]
    MODE -->|--start_vuln_scan| VS[VulnScanTask]

    SH -->|ip:port| DB[(Postgres cam)]
    NM -->|port 554 open| DB
    CK -->|working creds + frame| DB
    DB -->|active rows| FS
    NM -->|nmap XML| VS
    VS -->|report| JSON[vuln_report.json]
```

The discovery to check path fills the database. The other two modes work on
what already exists: `--start_face_scan` reads active rows, and
`--start_vuln_scan` reads an nmap XML file on disk.

### Modes

| Flag | Task | Network? | Needs DB? |
|------|------|----------|-----------|
| `--start_search` | `ShodanTask` | yes (Shodan API) | yes |
| `--start_nmap` | `NmapTask` | yes (nmap) | yes |
| `--start_check` | `CheckTask` | yes (RTSP) | yes |
| `--start_face_scan` | `FaceScanTask` | yes (RTSP) | yes |
| `--start_vuln_scan` | `VulnScanTask` | **no** | no |

### Mode summary

- **`--start_search` (`ShodanTask`)**: runs the configured Shodan query and
  stores each `ip:port` in the database, marked inactive and without credentials.
  It skips the orgs and tags on the block list (universities, hospitals, schools,
  ISPs).
- **`--start_nmap` (`NmapTask`)**: runs `nmap -p 554 -sV` over `nmap.ip_range`,
  tunneled through an **http** proxy (nmap cannot use socks5), and stores hosts
  that answer on the RTSP port. It fails loud if handed a proxy scheme nmap
  cannot use.
- **`--start_check` (`CheckTask`)**: for every inactive camera in the database,
  it tries the `user × password × rtsp-url` combinations from the wordlists,
  probing up to `checkers.concurrency` cameras in parallel. `RtspProbe` opens the
  stream and grabs one frame. On success the working credentials and the frame
  are saved and the camera is marked active.
- **`--start_face_scan` (`FaceScanTask`)**: for every active camera, captures
  `face.frames_per_scan` frames, detects faces and stores their embeddings, so a
  later scan can tell the same person apart. Needs the database. It does not
  touch inactive cameras.
- **`--start_vuln_scan` (`VulnScanTask`)**: reads the XML an nmap run left behind,
  names each open service through `cpe_map.yaml`, and reports the CVEs in
  `vuln.feed_path` that cover it. **Identification only**: it opens no connection
  and sends no payload. Nothing in this mode contacts a device.

### CVE identification (`scanners/vuln_probe.py`)

| Class | Job |
|-------|-----|
| `NvdRecordParser` | Reduces an NVD 2.0 record to its CPE ranges and CVSS score. |
| `CveFeed` | Loads the feed lazily and indexes it by `(vendor, product)`. |
| `CpeMap` | Translates the `product` string a scan reports (`OpenSSH`) into a CPE vendor/product pair (`openbsd:openssh`). A new product is a YAML line, never a code change. |
| `CpeMatchRange.covers` | Handles an exact-version CPE and the bounded ranges NVD writes (`versionStartIncluding` / `versionEndExcluding`). An unknown version only matches a pattern that names no range, so a version-less banner does not produce a pile of false findings. |

### Anonymisation (`scanners/proxy.py`, `scanners/proxy_tunnel.py`)

- `TwoCaptchaProxy` resolves a residential proxy from the 2captcha API, in
  whitelist or login mode.
- `AnonymousProxyClient` reaches a destination through the proxy without
  revealing it. It always CONNECTs and tunnels, so the proxy cannot inject
  `Proxy-Host` / `Via` / `X-Forwarded-For`. When `curl_cffi` is installed it
  impersonates a browser TLS (JA3/JA4) and HTTP/2 fingerprint; otherwise it falls
  back to a dependency-free stdlib CONNECT client.
- RTSP has no proxy option in FFmpeg. `ProxyTunnel` exposes a local `127.0.0.1`
  endpoint that relays the RTSP TCP connection through the proxy (http CONNECT or
  a SOCKS5 handshake with DNS resolved at the exit). The probe forces
  `rtsp_transport=tcp`, so control and media share one stream.
- The exit node's IP, TTL and TCP fingerprint are the residential exit's, not
  yours. That is by design.

### Storage (`models/`)

| File | Role |
|------|------|
| `models/camera.py` | The `cam` SQLAlchemy model. |
| `models/database.py` | `Database` owns the engine and a transactional `session_scope` (commit on success, roll back on error). |
| `models/managers.py` | `CameraRepository`, the only place that queries the table. |

A successful check stores the working credentials and the proof frame
(`image_b64`) on the camera row. Results live entirely in the database.

---

## Installation

Dependencies use [uv](https://docs.astral.sh/uv/). `pyproject.toml` is the single
source and `uv.lock` pins exact versions.

```bash
git clone https://github.com/iklobato/shodan_rtsp
cd shodan_rtsp
uv sync                       # creates .venv, installs runtime + dev deps from the lock
```

`uv` provisions Python 3.11 itself if missing (see `.python-version`). To install
with plain pip, export a requirements file first:
`uv export --no-hashes --no-dev -o requirements.txt`.

A running PostgreSQL is required for anything that touches the database. The repo
ships a `docker-compose.yml` that starts one on `localhost:5433`, matching the
`database` block in `config.yaml.example`.

| Command | Effect |
|---------|--------|
| `docker compose up -d` | Starts Postgres 16; data stays in a named volume. |
| `docker compose ps` | Wait for `healthy`. |
| `docker compose down` | Stops it and keeps data. |
| `docker compose down -v` | Stops it and wipes the volume. |

`curl_cffi` is installed by `uv sync` and gives the HTTP client a real browser TLS
(JA3/JA4) fingerprint. The code keeps a stdlib CONNECT fallback for the rare case
it is missing.

---

## Configuration

All settings and keys live in one `config.yaml`, which is git-ignored. Start from
the template:

```bash
cp config.yaml.example config.yaml
# then edit config.yaml
```

### Settings

| Key | Default in example | What it does |
|-----|--------------------|--------------|
| `shodan.api_key` | placeholder | Shodan API key. |
| `shodan.query` | `screenshot.label:webcam,cam country:BR` | Shodan query for `--start_search`. |
| `checkers.wordlist_users` | `wordlists/users.txt` | Usernames, one per line. |
| `checkers.wordlist_passwords` | `wordlists/passwords.txt` | Passwords, one per line. A blank line means "no password". |
| `checkers.wordlist_rtsp_urls` | `wordlists/rtsp_urls.txt` | URL templates, one per line. |
| `checkers.randomize` | `true` | Shuffle the credential combinations. |
| `checkers.concurrency` | `1` | Parallel RTSP probes. See notes below. |
| `nmap.ip_range` | `10.0.0.0/24` | Range to sweep. Only ranges you are authorized to scan. |
| `nmap.parallelism` | `0` | `0` keeps nmap defaults; `> 0` adds `-T4 --min-parallelism N`. |
| `nmap.xml_path` | `logs/nmap.xml` | Raw XML of the sweep. `--start_vuln_scan` reads this. |
| `vuln.nmap_xml` | `logs/nmap.xml` | XML the vuln mode reads. Keep in step with `nmap.xml_path`. |
| `vuln.feed_path` | `nvdcve-2.0.json` | NVD 2.0 JSON feed. |
| `vuln.cpe_map_path` | `cpe_map.yaml` | Product string to CPE vendor/product. |
| `vuln.min_cvss` | `0.0` | Drops findings below this base score from the report. |
| `vuln.report_path` | `logs/vuln_report.json` | JSON output. |
| `proxy.enabled` | `true` | `false` sends probes straight from your IP. Private ranges need `false`. |
| `proxy.token` | placeholder | 2captcha token. |
| `proxy.auth_mode` | `whitelist` | `whitelist` or `login`. |
| `proxy.protocol` | `socks5` | `http`, `https` or `socks5`. |
| `proxy.country` | `us` | Residential exit country. |
| `database.user` | placeholder | Postgres user. |
| `database.password` | placeholder | Postgres password. |
| `database.host` | `localhost:5433` | `host[:port]`; 5433 matches `docker-compose.yml`. |
| `database.db` | `cameras` | Database name. |

Minimal example:

```yaml
shodan:
  api_key: "<your_shodan_api_key>"
  query: "screenshot.label:webcam,cam country:BR"
checkers:
  wordlist_users: wordlists/users.txt
  wordlist_passwords: wordlists/passwords.txt
  wordlist_rtsp_urls: wordlists/rtsp_urls.txt
  randomize: true
  concurrency: 1
nmap:
  ip_range: 10.0.0.0/24
  parallelism: 0
  xml_path: logs/nmap.xml
vuln:
  nmap_xml: logs/nmap.xml
  feed_path: nvdcve-2.0.json
  cpe_map_path: cpe_map.yaml
  min_cvss: 0.0
  report_path: logs/vuln_report.json
proxy:
  enabled: true
  token: "<your_2captcha_token>"
  auth_mode: whitelist
  protocol: socks5
  country: us
database:
  user: "<postgres_user>"
  password: "<postgres_password>"
  host: "localhost:5433"
  db: "cameras"
```

### Config notes

| Setting | Note |
|---------|------|
| `proxy.enabled: false` | Sends every probe straight from your own IP. The only mode that works for a private range (`192.168.x.x` is unreachable through a residential exit) and for a box whose 2captcha account is down. Public scans must leave it `true`. |
| `proxy.auth_mode: whitelist` | Add your public IP in the 2captcha dashboard first. There is no API for that step. |
| `proxy.protocol: socks5` | Needs `curl_cffi` for the HTTP client. The nmap path always uses an http proxy, because nmap does not support socks5. |
| `checkers.concurrency` | How many RTSP probes `--start_check` runs in parallel. Probes are I/O-bound. `1` is sequential. The real ceiling is the proxy exit, not your CPU. Too many concurrent streams through one residential exit get throttled or banned. Raise it gradually (8 to 16) and watch the error rate. All probes still leave via the proxy. |
| `nmap.parallelism` | nmap parallelises hosts itself. `0` leaves the defaults. `> 0` runs the sweep with `-T4 --min-parallelism N`. |
| `nmap.xml_path` / `vuln.nmap_xml` | Two settings for one file. The first says where a sweep writes its XML. The second says what the vuln mode reads. Point them at the same path unless you feed a scan from elsewhere. |
| `vuln.min_cvss` | Filters the report only. The feed is indexed the same way either way. `0.0` keeps everything NVD scored. |

The config is validated on load (`scanners/config.py`): a missing section fails
fast with a clear error. `config.yaml` holds secrets and is never committed. Only
`config.yaml.example` is.

---

## Usage

```bash
uv run python main.py [--start_search | --start_nmap | --start_check
                      | --start_face_scan | --start_vuln_scan]
                     [--config config.yaml] [-v]
```

Exactly one mode is required. The CLI flags are only the mode, `--config` and
`-v`. Everything else (parallelism, proxy, wordlists, DB, CVE settings) comes from
the config file. Tune a run by editing `config.yaml`, or keep several profiles
and choose one with `--config`.

| Flag | Meaning |
|------|---------|
| `--start_search` | Search Shodan (`shodan.query`) and populate the database. |
| `--start_nmap` | Nmap sweep of `nmap.ip_range` for RTSP hosts; writes `nmap.xml_path`. |
| `--start_check` | Test credentials against cameras already in the database. |
| `--start_face_scan` | Detect and match faces on active cameras (needs the DB). |
| `--start_vuln_scan` | Name the CVEs of the services in `vuln.nmap_xml`; no device is contacted. |
| `--config PATH` | Config file to use (default `config.yaml`). |
| `-v`, `--verbose` | Debug logging: each probe URL and the local tunnel. |

Every example below was run on this repo. Log lines are real output, trimmed to
the informative ones.

---

## Mode details

### Fill the database

Two ways in. Pick one.

<details>
<summary><strong>From Shodan</strong> (<code>--start_search</code>)</summary>

Runs `shodan.query`, stores each `ip:port` it has not seen before, and skips the
orgs and tags on the block list. It spends Shodan query credits, one page per 100
results, so check the query first.

```bash
uv run python main.py --start_search
```
</details>

<details>
<summary><strong>From an nmap sweep of your own network</strong> (<code>--start_nmap</code>)</summary>

Stores only hosts with port 554 **open**. A host that answers with the port closed
is not a camera. Inserting it would make `--start_check` burn a full credential run
on every live machine on your LAN. A private range is not reachable through a
residential exit, so this is the one case where the proxy goes off.

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
count moves between runs (6 on an earlier sweep); Wi-Fi clients come and go.
</details>

### See what you collected

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

### Test credentials

`--start_check` walks every **inactive** camera and tries every combination of
URL template × user × password. The three wordlists are plain text, one entry per
line:

```text
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

The shipped lists come in two sizes. The `*_small.txt` lists are
5 URLs × 3 users × 5 passwords = **75 probes per camera**. The full ones are
45 × 29 × 54 = **70,470**. Start small, look at the hit rate, then widen. Only
against targets you are authorized to test.

```bash
uv run python main.py --start_check -v
```

With `-v` you see each probe and the anonymised path. The probe opens
`rtsp://...@127.0.0.1:<port>/` (a local tunnel), which relays to the real camera
through the proxy exit. Without `-v` you only get the summary lines. A camera that
opens is logged at INFO either way:

```text
INFO [!] rtsp://admin:admin@10.0.0.5:554/, user: admin, password: admin
```

`checkers.concurrency` decides how many probes run at once. It is a config value,
not a flag:

```yaml
checkers:
  concurrency: 16        # 16 RTSP probes at once (bounded by the proxy exit)
```

The real ceiling is the proxy exit, not your CPU. Too many concurrent streams
through one residential exit get throttled or banned. Raise it gradually (8 to 16)
and watch the error rate.

### Scan faces

```bash
uv run python main.py --start_face_scan
```

Reads the **active** rows only, so it does nothing until the check found a working
login. `face.frames_per_scan`, `face.frame_interval` and `face.match_threshold`
tune it. The face model (`buffalo_l`) downloads on first use into
`~/.insightface/models` (about 280 MB).

### Choose how the proxy authenticates

`--start_check` and `--start_nmap` always leave via the residential proxy unless
`proxy.enabled` is false. No flag needed. You only pick *how* it authenticates.

| Mode | Use when | Config |
|------|----------|--------|
| `whitelist` | Your public IP is already in the 2captcha dashboard. | `auth_mode: whitelist`, `protocol: socks5` |
| `login` | You have a gateway host, port and password from the dashboard. No IP whitelisting. | `auth_mode: login`, `protocol: http`, `gateway_host`, `gateway_port`, `gateway_password` |

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

### Tune the sweep and keep profiles

`nmap.parallelism` is the other config-only knob. `0` leaves nmap defaults. `> 0`
runs the sweep with `-T4 --min-parallelism N`.

```yaml
nmap:
  ip_range: 10.0.0.0/24  # only ranges you are authorised to scan
  parallelism: 200        # runs nmap with -T4 --min-parallelism 200
```

Every knob lives in the config file, so you can keep several profiles and pick one
per run:

```bash
uv run python main.py --start_check --config config.fast.yaml -v
uv run python main.py --start_check --config config.quiet.yaml
```

---

## Vuln scan (`--start_vuln_scan`)

Identification only. It reads an nmap XML file, a CVE feed and a product map, and
writes a report. It never opens a connection to a device, so it is safe to point at
any XML you already have.

<details>
<summary><strong>Step 1: produce the XML</strong></summary>

`--start_nmap` writes it for you (`nmap.xml_path`, default `logs/nmap.xml`). Any
`nmap -sV -oX` file works too, including one over more ports than 554.

```bash
nmap -sV -oX logs/nmap.xml 192.168.1.0/24
```
</details>

<details>
<summary><strong>Step 2: build a CVE feed</strong></summary>

The mode reads NVD 2.0 JSON. Do **not** download the full year files: they are
hundreds of MB and the loader holds the whole file in memory. Pull one product
subset per product you mapped, then merge.

```bash
curl -sG 'https://services.nvd.nist.gov/rest/json/cves/2.0' \
  --data-urlencode 'virtualMatchString=cpe:2.3:a:openbsd:openssh' \
  --data-urlencode 'resultsPerPage=2000' -o nvdcve-openssh.json

jq -s '{format:"NVD_CVE", version:"2.0",
        vulnerabilities: [.[].vulnerabilities[]]}' \
  nvdcve-*.json > nvdcve-2.0.json
```

Use `virtualMatchString`, not `cpeName`: the `cpeName` form of the same endpoint
answers `HTTP 404`. Add `sleep 6` between calls; the NVD API rate-limits.

A ready-made subset ships in `samples/nvd_sample.json` (24 real records, trimmed
for size) if you want to try the mode before pulling your own.
</details>

<details>
<summary><strong>Step 3: map your products</strong></summary>

`cpe_map.yaml` translates the `product` field a scan reports into a CPE. Add a line
per product. Check the name exists in the NVD dictionary first, or the CVEs you
find belong to a different product.

```console
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' \
    --data-urlencode 'cpeMatchString=cpe:2.3:a:openbsd:openssh' \
    --data-urlencode 'resultsPerPage=1' | jq .totalResults
297
```

Any `totalResults` above 0 means the name is real. `0` means you invented it and
the entry would quietly match nothing.
</details>

<details>
<summary><strong>Step 4: run it</strong></summary>

```console
$ uv run python main.py --start_vuln_scan
2026-11-02 00:45:04,218 INFO Read 5 services from logs/nmap.xml
2026-11-02 00:45:04,232 INFO 10.0.0.5:22 CVE-2024-6387 (CVSS 8.1)
2026-11-02 00:45:04,233 INFO 10.0.0.5:22 CVE-2023-38408 (CVSS 9.8)
2026-11-02 00:45:04,233 INFO 10.0.0.5:22 CVE-2023-48795 (CVSS 5.9)
2026-11-02 00:45:04,233 INFO 10.0.0.7:80 CVE-2021-41773 (CVSS 9.8)
2026-11-02 00:45:04,233 INFO 4 CVE matches in 5 services
```

That run read `logs/nmap.xml`, which held `samples/nmap_sample.xml`, a hand-written
three-host file that ships with the repo. Copy it into place to reproduce the
output above without scanning anything:

```bash
cp samples/nmap_sample.xml logs/nmap.xml
uv run python main.py --start_vuln_scan
```

`10.0.0.5:22` reports OpenSSH 9.2, inside the ranges of three CVEs. `10.0.0.7:80`
reports Apache httpd 2.4.49, an exact-version match. The third host's RTSP service
reports no product, so it matches nothing. A version-less banner does not get a
pile of guesses.

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
</details>

### View results

Active cameras and their working credentials live in the `cam` table:

```bash
psql "postgresql://scanner:scanner@localhost:5433/cameras" \
  -c "select ip, port, user, password, url from cam where active;"
```

---

## Development

| Task | Command |
|------|---------|
| Tests (DB and network are faked) | `uv run pytest -q` |
| Lint | `uv run ruff check .` |
| Add a dependency | `uv add <pkg>` |
| Add a dev dependency | `uv add --dev <pkg>` |

The code follows an OO/SOLID structure: strategies behind `typing.Protocol`
(`Fetcher` backends, RTSP `Transport`), dependency injection at the composition
root (`main.py`), context managers over `try/finally`, and dispatch tables over
`if/elif`.

---

## Disclaimer

For education and authorized security research only. Do not use it against systems
you do not own or lack written permission to test. The authors are not responsible
for misuse or damage.

## License

MIT. See [LICENSE](LICENSE).
