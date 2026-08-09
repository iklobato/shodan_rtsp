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

The credential wordlists that `--start_check` needs are **not** shipped with the
repo. Provide your own, restricted to the targets you are authorized to test.

---

## How it works

The scanner has three run modes, one storage layer, and one viewer. Everything
is wired from a single `config.yaml` (see Configuration).

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
   └─────────────────────────────────────────────────────────┘
                              ▲
                       serv_app.py (Streamlit)
                    reads active cameras → frames/
```

**Modes** (`scanners/task.py`)
- **`--start_search` — `ShodanTask`**: runs the configured Shodan query and
  stores each `ip:port` in the database (marked inactive, no credentials yet).
- **`--start_nmap` — `NmapTask`**: runs `nmap -p 554 -sV` over `nmap.ip_range`,
  tunneled through an **http** proxy (nmap cannot use socks5), storing hosts that
  answer on the RTSP port. It fails loud if handed a proxy scheme nmap can't use.
- **`--start_check` — `CheckTask`**: for every inactive camera in the database,
  it tries the `user × password × rtsp-url` combinations from the wordlists.
  `RtspProbe` opens the stream and grabs one frame; on success the working
  credentials and the frame are saved and the camera is marked active.

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

**Viewer** (`serv_app.py`) — a Streamlit app that reads the active cameras and
writes their frames to `frames/`.

## Installation

```bash
git clone https://github.com/iklobato/shodan_rtsp
cd shodan_rtsp
pip install -r requirements.txt
```

A running PostgreSQL is required for anything that touches the database.
`curl_cffi` is optional but recommended (browser TLS fingerprint); without it the
client uses the stdlib CONNECT fallback.

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
nmap:
  ip_range: 10.0.0.0/24                         # only ranges you are authorised to scan
proxy:
  token: "<your_2captcha_token>"
  auth_mode: whitelist                          # whitelist | login
  protocol: socks5                              # http | https | socks5
  country: us
database:
  user: "<postgres_user>"
  password: "<postgres_password>"
  host: "localhost"
  db: "cameras"
```

The config is validated on load (`scanners/config.py`): a missing section fails
fast with a clear error. `config.yaml` holds secrets, so it is never committed —
only `config.yaml.example` is.

Notes
- In whitelist mode, your public IP must be added to the 2captcha dashboard
  first (there is no API for that step).
- `protocol: socks5` needs `curl_cffi` for the HTTP client; the nmap path always
  uses an http proxy regardless (nmap does not support socks5).

## Usage

```bash
python main.py [--start_search | --start_check | --start_nmap] [--config config.yaml] [-v]
```

- `--start_search` — search Shodan and populate the database.
- `--start_nmap` — Nmap sweep of `nmap.ip_range` for RTSP hosts.
- `--start_check` — test credentials against the cameras already in the database.
- `--config` — path to the config file (default `config.yaml`).
- `-v`, `--verbose` — debug logging.

View results:

```bash
streamlit run serv_app.py
```

## Development

Run the tests (no external services needed; DB and network are faked):

```bash
python -m pytest tests/ -q
```

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
