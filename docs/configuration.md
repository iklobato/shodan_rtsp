# Configuration

Part of the [Camera Scanner](../README.md) documentation.

All settings and keys live in one `config.yaml`, which is git-ignored.

```bash
cp config.yaml.example config.yaml
```

## The settings that matter most

| Key | Example | What it does |
|-----|---------|--------------|
| `targets.allowed_cidrs` | `["192.168.1.0/24"]` | **the authorization**. Empty authorizes nothing |
| `nmap.ip_range` | `192.168.1.0/24` | default target of `scan nmap` |
| `nmap.ports` | `[554, 80, 443, 8000, 8080, 8554, 34567]` | RTSP plus the web and ONVIF ports of D15 |
| `nmap.xml_path` | `logs/nmap.xml` | raw XML of the sweep, the record of what nmap saw |
| `frames.root_path` | `logs/frames` | where frame files land |
| `face.match_threshold` | `0.5` | minimum cosine similarity. Placeholder until measured |
| `face.enabled` | `true` | `false` skips the face scan |
| `brands.signature_path` | `brands.yaml` | brand signatures and brand credentials, as data (D27) |
| `database.host` | `127.0.0.1:5440` | `host[:port]` |

<details>
<summary><b>Every key, the full table</b></summary>

| Key | Default in example | What it does |
|-----|--------------------|--------------|
| `shodan.api_key` | placeholder | Shodan API key |
| `shodan.query` | `net:203.0.113.0/24 screenshot.label:webcam,cam` | Shodan query for `scan shodan` |
| `targets.allowed_cidrs` | `["203.0.113.0/24"]` | the one list of what this scanner may reach |
| `checkers.wordlist_users` | `wordlists/users_small.txt` | usernames, one per line |
| `checkers.wordlist_passwords` | `wordlists/passwords_small.txt` | passwords, one per line; a blank line means no password |
| `checkers.wordlist_rtsp_urls` | `wordlists/rtsp_urls_small.txt` | URL templates, one per line |
| `checkers.randomize` | `true` | shuffle the credential combinations |
| `checkers.concurrency` | `1` | parallel RTSP probes |
| `nmap.ip_range` | `192.168.1.0/24` | range `scan nmap` sweeps when no target is given |
| `nmap.ports` | `[554, 80, 443, 8000, 8080, 8554, 34567]` | ports of the sweep |
| `nmap.parallelism` | `0` | `0` keeps nmap defaults, `> 0` adds `-T4 --min-parallelism N` |
| `nmap.xml_path` | `logs/nmap.xml` | raw XML of the sweep |
| `vuln.feed_path` | `nvdcve-2.0.json` | NVD 2.0 JSON feed |
| `vuln.cpe_map_path` | `cpe_map.yaml` | product string to CPE vendor:product |
| `vuln.min_cvss` | `0.0` | drops findings below this base score |
| `vuln.web_ports` | `[80, 443, 8000, 8080]` | tried after the port the camera was seen on |
| `vuln.timeout_seconds` | `8.0` | one network step; the RTSP probe uses the same bound |
| `face.enabled` | `true` | `false` skips the face scan |
| `face.frames_per_scan` | `5` | frames captured over RTSP per camera per scan |
| `face.frame_interval` | `2.0` | seconds between those frames |
| `face.match_threshold` | `0.5` | minimum cosine similarity for one person |
| `face.pairs_path` | `lab/faces` | the labelled pair set `measure threshold` reads |
| `frames.root_path` | `logs/frames` | where frame files land |
| `brands.signature_path` | `brands.yaml` | brand signatures and credentials, as data |
| `database.user` / `.password` | placeholder | Postgres credentials |
| `database.host` | `localhost:5440` | `host[:port]` |
| `database.db` | `cameras` | database name |

</details>

## Config notes

| Setting | Note |
|---------|------|
| `targets.allowed_cidrs` | The authorization, written once. It guards the Shodan query and every command that reaches a stored camera. A run narrowed with `--camera-id N` reaches the camera the operator named, which is the authorization itself, so it is not gated |
| `face.match_threshold` | A minimum cosine similarity over the L2-normalized 512-d embedding: higher means more alike, 1.0 is the same direction (D44) |
| `checkers.concurrency` | Probes are I/O-bound. Raise gradually and watch the error rate |
| `nmap.xml_path` | Where a sweep writes its XML. `scan cve` does not read it: it matches what the scan stored (D30) |

The config is validated on load (`scanners/config.py`): a missing section fails
fast with a clear error. `config.yaml` holds secrets and is never committed. Only
`config.yaml.example` is.
