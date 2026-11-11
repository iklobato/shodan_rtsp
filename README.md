# Camera Scanner

![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![Tests 141 passed](https://img.shields.io/badge/tests-141%20passed-brightgreen)
![Ruff clean](https://img.shields.io/badge/ruff-clean-brightgreen)

Find cameras on a network you own, read one frame through the path that works,
match that camera against a CVE feed, read the faces in the frame, group the faces
into people, and answer who appeared, on which camera and when.

```text
   ┌──────────────────────┐
   │     config.yaml      │   targets, wordlists, database, one file
   └──────────┬───────────┘
              │
   ┌──────────▼────────────┐
   │ targets.allowed_cidrs │   THE GATE: one packet never leaves without this
   └──────────┬────────────┘
              │
   scan nmap ─┤
   scan shodan┼──►  ┌──────────┐      ┌────────────────┐
   scan check ┤     │ Postgres │ ◄────│ report faces   │
   scan cve ──┤     └────┬─────┘      │ search         │
   scan faces ┘          │            │ measure        │
                         ▼            └────────────────┘
                 frames on disk
                 <root>/<camera_id>/<timestamp>-<source>.jpg
```

> [!WARNING]
> **Authorized use only.** This tool logs into cameras and reads frames from them.
> Run it only against devices you own or have **explicit written authorization** to
> test: your own lab, or an engagement with a defined scope. Reaching a camera you
> do not control is unauthorized access, and recording from it is interception.
> Both are illegal in most places. `targets.allowed_cidrs` is the authorization
> written down once, and it is empty by default: an empty list authorizes nothing.
>
> The CVE path is read-only by construction. It pulls at most one frame per match,
> sends no payload, and writes nothing to the device (D9, D30). Nothing in this
> repository is a weaponized exploit.
>
> Faces are read from frames the pipeline already obtained, and the people they are
> grouped into stay anonymous: a person is an id until an operator names it by hand
> (D28). Do not point this at people who did not agree to it.

---

## Contents

| | | |
|---|---|---|
| [At a glance](#at-a-glance) | [Quickstart](#quickstart) | [One run, end to end](#one-run-end-to-end) |
| [Install](#install) | [Lab target](#lab-target) | [The seven commands](#the-seven-commands) |
| [Exit codes](#exit-codes) | [The monitoring answer](#the-monitoring-answer) | [Measure the threshold](#measure-the-face-threshold) |
| [CVE matching](#cve-matching) | [Data model](#data-model) | [Configuration](#configuration) |
| [Shodan by location](#shodan-by-location) | [Run it in Docker](#run-it-in-docker) | [Troubleshooting](#troubleshooting) |
| [Development](#development) | [License](#license) | |

---

## At a glance

| | |
|---|---|
| **Input** | a CIDR you own, plus `config.yaml` |
| **Output** | Postgres rows, JPEG frames on disk, three read-only reports |
| **Reaches the network** | `scan nmap`, `scan shodan`, `scan check`, `scan cve`, `scan faces` |
| **Never reaches the network** | `report faces`, `search`, `measure threshold` |
| **Writes to a device** | never. One frame read per match, no payload, no config push |
| **Names a person** | never automatically. A person is an id until a human labels it |
| **Hard dependency** | Python 3.11, Postgres, `nmap`, `ffmpeg` for RTSP frames |
| **Soft dependency** | `mediamtx` for the lab, `~/.insightface/models/buffalo_l` for faces |

### What it does, and what it does not

| Stage | Does | Does not |
|-------|------|----------|
| `scan nmap` | sweeps 7 camera ports, stores one row per open port | guess credentials, open a stream |
| `scan check` | tries `url x user x password`, records what worked, stores one frame | retry a locked device, brute-force outside the wordlist |
| `scan cve` | matches stored banners against NVD, reads one frame per match | send an exploit, write to the device |
| `scan faces` | detects faces, clusters them into people, writes frame files | label a person, keep a face that failed detection |
| `report` / `search` | print what is stored | touch the network at all |

---

## Quickstart

| # | Step | Command |
|---|------|---------|
| 1 | Install dependencies | `uv sync` |
| 2 | Start Postgres 16 on port 5440 | `docker compose up -d postgres` |
| 3 | Create the config and edit it | `cp config.yaml.example config.yaml` |
| 4 | Create the schema | `uv run alembic upgrade head` |
| 5 | Sweep your lab | `uv run python main.py scan nmap 127.0.0.1/32` |
| 6 | Read the result | `uv run python main.py report faces` |

Real terminal, this machine, 2026-11-11:

```console
$ uv sync
$ docker compose up -d postgres
[+] Running 1/1
 ✔ Container shodan_pg  Started

$ uv run alembic current
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
0002 (head)

$ uv run python main.py --help
usage: main.py [-h] [--config CONFIG] [-v] {scan,report,search,measure} ...

Camera Scanner

positional arguments:
  {scan,report,search,measure}
    scan                Scans that write to the database
    report              Read-only reports
    search              Who appeared, where and when
    measure             Measurements that write nothing

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to the configuration file
  -v, --verbose         Verbose mode
```

The full lab runbook, with the devices to point this at, is
`specs/001-camera-monitoring-pipeline/quickstart.md`.

---

## One run, end to end

```mermaid
flowchart TD
    A[config.yaml] --> B{targets.allowed_cidrs}
    B -->|inside| C[scan nmap]
    B -->|outside| X[refused, exit 1, named addresses]
    C --> D[(camera + camera_observation)]
    D --> E[scan check]
    E --> F[(camera.url, camera.status, one frame)]
    F --> G[scan cve]
    G --> H[(cve_finding, proof frame)]
    F --> I[scan faces]
    H --> I
    I --> J[(face, person, frame files)]
    J --> K[report faces]
    J --> L[search]
```

Every stage in the order an operator runs it, with real output from one lab run:

### 1. Sweep

```console
$ uv run python main.py scan nmap 192.168.1.0/24
2026-11-11 13:47:01,729 INFO Starting nmap scanning on 192.168.1.0/24
2026-11-11 13:48:01,022 INFO Found 5 hosts using nmap scan
2026-11-11 13:48:01,024 INFO nmap XML written to logs/nmap.xml
2026-11-11 13:48:01,149 INFO Executors: finished nmap scan
```

A host that answers with the port closed is not a camera and is not stored. One
`scan_run` row records the range, so the record of what a run touched is written
even when nobody typed the range this time.

### 2. The gate, when the range is not authorized

```console
$ uv run python main.py scan check
2026-11-11 13:39:34,552 INFO Starting check task
2026-11-11 13:39:34,751 ERROR 224 of 226 addresses are outside the declared ranges
  ['127.0.0.1/32', '192.168.1.0/24']: 190.120.45.220, 189.15.27.223, ...
  and 214 more; declare them in targets.allowed_cidrs, or narrow the run with --camera-id
```

Nothing was sent. Narrow the run to the camera you named:

```console
$ uv run python main.py scan check --camera-id 232
2026-11-11 13:40:34,977 INFO Executors: finished testing cameras
```

### 3. Read one frame through a CVE class

```console
$ uv run python main.py -v scan cve --camera-id 231
2026-11-11 13:42:21,860 INFO Starting the CVE task
2026-11-11 13:42:22,175 INFO 127.0.0.1:8000 matches 1 CVE(s)
2026-11-11 13:42:22,219 INFO CVE read GET http://127.0.0.1:8000/onvif-http/snapshot?auth=...
2026-11-11 13:42:22,316 INFO Executors: finished the CVE task
$ ls -l logs/frames/231/
-rw-r--r--  22096  20261111T164222Z-cve.jpg
```

Exit 0 even when no frame comes back: a recorded absence is a successful run, not
a failure. The `cve_finding` rows carry the outcome and the reason.

### 4. Faces into people

```console
$ uv run python main.py scan faces --camera-id 231
2026-11-11 12:45:33,379 DEBUG face 1 joined person 1
2026-11-11 12:45:33,708 DEBUG face 2 joined person 1
2026-11-11 12:45:34,103 DEBUG face 3 joined person 2
2026-11-11 12:45:34,104 INFO 127.0.0.1:8000 holds 3 face(s)
```

Three faces in three frames became two people: faces 1 and 2 are the same person
in two frames of one camera, face 3 is someone else. Nothing is labelled. A face
that matches two people merges them, the older person wins, and every face and
frame of both is kept (D35).

### 5. Answer

```console
$ uv run python main.py report faces
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
person 2  faces 2   first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 2  frame cve
```

---

## Install

Dependencies use [uv](https://docs.astral.sh/uv/). `pyproject.toml` is the single
source and `uv.lock` pins exact versions.

```bash
git clone https://github.com/iklobato/shodan_rtsp
cd shodan_rtsp
uv sync                       # creates .venv, installs runtime and dev deps from the lock
```

`uv` provisions Python 3.11 itself if missing (see `.python-version`). To install
with plain pip, export a requirements file first:
`uv export --no-hashes --no-dev -o requirements.txt`.

| Piece | Why | Check |
|-------|-----|-------|
| `nmap` | the sweep, and the banner that names a brand | `nmap --version` |
| `ffmpeg` | RTSP capture and the lab stream | `ffmpeg -version` |
| Docker | Postgres 16 on port 5440 | `docker compose ps` |
| `mediamtx` | only for the lab target | `mediamtx --help` |
| `buffalo_l` | face model, about 280 MB, downloads on first face run | `ls ~/.insightface/models` |

### The database

```bash
docker compose up -d postgres
docker compose ps              # wait for healthy
uv run alembic upgrade head    # creates every table; a second run changes nothing
uv run alembic current         # 0002 (head)
```

| Command | Effect |
|---------|--------|
| `docker compose up -d postgres` | starts Postgres 16, data in a named volume |
| `docker compose down` | stops it, keeps data |
| `docker compose down -v` | stops it and wipes the volume |

Port 5432 and 5433 were taken on the machine this was built on, so the service
listens on 5440 (D40).

---

## Run it in Docker

The image is the CLI: the entrypoint is `main.py`, so every argument after the
image name is one command of the seven. Nothing is baked into it that holds a
secret or that belongs to one environment.

### Pull it, no build

The image is published, so a run needs no source tree and no build step:

```bash
export SHODAN_IMAGE=iklob1/shodan-rtsp:0.1.0
docker pull "$SHODAN_IMAGE"
docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  "$SHODAN_IMAGE" report faces
```

| Tag | Follows |
|-----|---------|
| `0.1.0` | one release, and the only tag that never moves |
| `0.1` | the patch line, so `0.1.4` replaces `0.1.3` |
| `latest` | the newest release |

Through compose, the same image without a build:

```bash
export SHODAN_IMAGE=iklob1/shodan-rtsp:0.1.0
docker compose pull scanner
docker compose run --rm scanner report faces
```

Docker Hub limits anonymous pulls to 100 per 6 hours per IP, and an authenticated
free account to 200 per 6 hours (`docs.docker.com/docker-hub/usage/`).

### Build

The rest of this section is for building from the source tree, which is what a
change to the scanner needs:

```console
$ docker build -t shodan-rtsp:0.1.0 .
#20 naming to docker.io/library/shodan-rtsp:0.1.0 done
$ docker image ls shodan-rtsp:0.1.0 --format '{{.Repository}}:{{.Tag}} {{.Size}}'
shodan-rtsp:0.1.0 1.82GB
```

### Create the schema

The entrypoint is the CLI, so a migration is one command with the entrypoint
swapped:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  --entrypoint alembic shodan-rtsp:0.1.0 upgrade head
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, initial schema
INFO  [alembic.runtime.migration] Running upgrade 0001 -> 0002, migrate the legacy cam table into camera and camera_observation
```

### `docker run`

```console
$ docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  shodan-rtsp:0.1.0 report faces
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
```

That run is real output from this machine on 2026-11-11, against the Postgres
published on the host at 5440.

| Flag | Why |
|------|-----|
| `-v "$PWD/config.yaml:/app/config.yaml:ro"` | the config holds the Shodan key and the database password, so it is mounted, never built in |
| `-e DATABASE_HOST=...` | the address the container reaches the database at (see below) |
| `-v shodan_logs:/app/logs` | the log and the frames outlive the container |
| `-v shodan_face_models:/home/scanner/.insightface` | `buffalo_l` downloads once, not once per run |
| `-v "$PWD/nvdcve-2.0.json:/app/nvdcve-2.0.json:ro"` | the NVD feed is not in the repository, so `scan cve` needs it mounted |

`DATABASE_HOST` overrides `database.host` of the config file, because that is the
one value that differs between a run on the host and a run in a container
(`scanners/config.py`). On Docker Desktop for Mac `host.docker.internal` resolves
already; on Linux add `--add-host=host.docker.internal:host-gateway`.

A command that reaches a device needs the same gate as always, and the range in
the mounted config is the one that decides:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" shodan-rtsp:0.1.0 scan shodan 'country:NL'
2026-11-11 17:22:07,553 ERROR the query names no `net:` range, so it reaches the whole index; declare the range the scan may reach in the query itself
$ echo $?
1
```

### A scan from the container

The write path works the same way, so a scan run inside the container stores its
row in the database the config names:

```console
$ docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e DATABASE_HOST=host.docker.internal:5440 \
  shodan-rtsp:0.1.0 scan nmap 127.0.0.1/32
2026-11-11 17:25:11,905 INFO Starting nmap scanning on 127.0.0.1/32
2026-11-11 17:25:12,696 INFO Found 1 hosts using nmap scan
2026-11-11 17:25:12,696 INFO nmap XML written to logs/nmap.xml
2026-11-11 17:25:12,715 INFO Executors: finished nmap scan
```

Both runs above, this one and the migration, were taken against a throwaway
database on the same Postgres, dropped afterwards, so the `cameras` database was
never touched. Only the `database` block of the mounted config differs.

### `docker compose run`

The compose file carries a `scanner` service on the same network as Postgres, so
no host address is needed:

```console
$ docker compose run --rm scanner report faces
 Container shodan_pg  Running
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
```

It sits behind the `cli` profile, so it never starts on its own and the database
command of the quickstart stays as it was:

```console
$ docker compose config --services
postgres
$ docker compose --profile cli config --services
postgres
scanner
```

### What is in the image

| In | Out |
|----|-----|
| Python 3.11 with every dependency from `uv.lock`, compiled in a builder stage | no compiler in the final image |
| `nmap`, plus the three libraries the wheels load (`libgl1`, `libglib2.0-0`, `libgomp1`) | no `ffmpeg` binary: the OpenCV wheel carries its own |
| the code, the wordlists, `brands.yaml`, `cpe_map.yaml`, the lab | no `config.yaml`, no `.env`, no API key |
| a `scanner` user, uid 1000, which is what the CLI runs as | no root, and no capability by default |

The image is 1.82 GB because `insightface` pulls `scipy`, `scikit-learn`,
`matplotlib` and both `opencv-python` wheels behind it. Dropping the face scan
would drop most of that.

One thing happens on the first run instead of at build time: `scan faces`
downloads `buffalo_l`, about 280 MB, into `$HOME/.insightface`, which the compose
file keeps in the `shodan_face_models` volume. Mount that volume, or every run
downloads the model again.

### nmap as a non-root user

The CLI runs as `scanner`, and the sweep asks nmap for `-p ... -sV` only, which
needs no privilege. A scan type that does need it quits instead of falling back:

```console
$ docker run --rm --entrypoint nmap shodan-rtsp:0.1.0 -sS -p 554 127.0.0.1
You requested a scan type which requires root privileges.
QUITTING!
```

`--cap-add NET_RAW` does not change that: nmap checks the user, not the
capability. A scan type that needs root means running the container as root,
which gives up the non-root default:

```bash
docker run --rm --user root -v "$PWD/config.yaml:/app/config.yaml:ro" \
  shodan-rtsp:0.1.0 scan nmap 192.168.1.0/24
```

The scanner itself never asks nmap for those types, so the default non-root run
is enough for the seven commands.

### Publish a release

The image goes out on a version tag, through
`.github/workflows/publish.yml`, and never from a branch:

```bash
git tag v0.1.0
git push origin v0.1.0
```

| Step | What it does |
|------|--------------|
| lint and tests | `ruff check .` and `pytest -q`, the same suite as CI |
| version check | the tag has to equal the version in `pyproject.toml`, or the run stops |
| build | `linux/amd64`, cached in the Actions cache |
| smoke test | `--help`, the imports of `cv2`, `nmap`, `onnxruntime` and `psycopg2`, and `nmap --version` |
| push | the tags `0.1.0`, `0.1` and `latest` |

Two repository secrets and one repository on Docker Hub:

| Piece | Holds |
|-------|-------|
| secret `DOCKERHUB_USERNAME` | the account, which is also the namespace |
| secret `DOCKERHUB_TOKEN` | a personal access token with **Read & Write** |
| the repository | created once in the Hub UI |

The Hub creates a token read-only by default, and a read-only token is refused at
the push, so pick Read & Write when generating it. The Hub docs describe creating
the repository in the UI and do not say a push creates it, so create it first.

A release whose tests fail never reaches the registry, and neither does one whose
tag does not match `pyproject.toml`. A failed run is re-run from the Actions tab.

---

## Lab target

Two devices, both local, both fake:

```text
                 your Mac                       the pipeline sees
   ┌────────────────────────────────┐
   │ ffmpeg  ──publish──► mediamtx  │  rtsp://127.0.0.1:8554/h264/ch1/main/av_stream
   │                      :8554     │
   │                                │
   │ lab/mock_camera.py :8000       │  http://127.0.0.1:8000/onvif-http/snapshot?auth=...
   └────────────────────────────────┘
```

```bash
# RTSP side
mediamtx lab/mediamtx.yml &
ffmpeg -loop 1 -re -i logs/faces/friends/01.jpg \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  -r 10 -c:v libx264 -pix_fmt yuv420p -g 10 -f rtsp -rtsp_transport tcp \
  rtsp://127.0.0.1:8554/h264/ch1/main/av_stream

# CVE side
uv run python lab/mock_camera.py --port 8000 --image logs/faces/friends/01.jpg \
  2> logs/mock_camera.log
```

Two details cost a run each: libx264 refuses an odd width or height (hence the
`scale`), and `-stream_loop -1` does not loop an image input (hence `-loop 1 -re`).

Verify both before scanning:

```console
$ curl -s -o /tmp/snap.jpg -w '%{http_code}\n' \
  "http://127.0.0.1:8000/onvif-http/snapshot?auth=YWRtaW46MTEK"
200
$ file -b /tmp/snap.jpg
JPEG image data, JFIF standard 1.01, 239x279, components 3

$ ffprobe -v error -rtsp_transport tcp -show_entries stream=codec_name,width,height \
    -of csv=p=0 rtsp://127.0.0.1:8554/h264/ch1/main/av_stream
h264,238,278
```

The mock is not vendor firmware. It answers the snapshot path with a JPEG, 404 to
everything else, and sends `Server: Hikvision-Webs/DS-2CD2032-I` so a real
`nmap -sV` names the brand and model. `docs/front-4-rig.md` records what that
leaves unproved.

---

## The seven commands

```bash
uv run python main.py [--config PATH] [-v] <group> <command> [options]
```

```mermaid
flowchart LR
    subgraph writes
      N[scan nmap]
      S[scan shodan]
      C[scan check]
      V[scan cve]
      F[scan faces]
    end
    subgraph reads
      R[report faces]
      Q[search]
      M[measure threshold]
    end
    N --> DB[(Postgres)]
    S --> DB
    C --> DB
    V --> DB
    F --> DB
    DB --> R
    DB --> Q
    P[(pair set on disk)] --> M
```

| Command | Reaches network | Writes | One line |
|---------|-----------------|--------|----------|
| `scan nmap [CIDR]` | nmap over the range | `scan_run`, `camera`, `camera_observation` | find cameras |
| `scan shodan [QUERY]` | Shodan API | same as nmap | find cameras without touching them ([by location](#shodan-by-location)) |
| `scan check [--camera-id N]` | RTSP port of stored cameras | `camera.url`, `user`, `password`, `status` | get in |
| `scan cve [--camera-id N]` | HTTP, ONVIF, RTSP of stored cameras | `cve_finding`, one proof frame | read one frame per match |
| `scan faces [--camera-id N]` | stored camera URL, only if no frame | `scan_run`, `face_frame`, `face`, `person` | who is in the frame |
| `report faces [--person-id N]` | none | nothing | the answer |
| `search [filters]` | none | nothing | the answer as a timeline |
| `measure threshold [--pairs P]` | none | nothing, not even the config | the one number to trust |

`--config` and `-v` come before the group: `main.py --config lab.yaml scan nmap`.

### `search` filters

| Flag | Takes | Example |
|------|-------|---------|
| `--person-id` | integer | `--person-id 1` |
| `--camera-id` | integer | `--camera-id 231` |
| `--since` | ISO 8601, read as UTC | `--since 2026-11-11T00:00:00Z` |
| `--until` | ISO 8601, read as UTC | `--until 2026-11-11T23:59:59Z` |

All four combine with AND.

---

## Shodan by location

Shodan answers where a camera is, not only that it exists. `scan shodan` stores
the place Shodan reports, so a run can be aimed at one country, one city, or one
block of a network range.

### The range always comes first

`scan shodan` refuses a query that names no `net:` range, and refuses every
`net:` range that is not inside `targets.allowed_cidrs`. Both checks run before
the API call, so a refused query spends no credit (D18).

A query that is only a location, with no range:

```console
$ uv run python main.py scan shodan 'country:NL city:"Amsterdam" has_screenshot:true'
2026-11-11 14:03:52,768 ERROR the query names no `net:` range, so it reaches the whole index; declare the range the scan may reach in the query itself
$ echo $?
1
```

A query that names a range the config does not declare:

```console
$ uv run python main.py scan shodan 'net:203.0.113.0/24 country:NL'
2026-11-11 14:03:57,580 ERROR 203.0.113.0/24 is outside the declared ranges ['127.0.0.1/32', '192.168.1.0/24']; declare it in targets.allowed_cidrs
$ echo $?
1
```

Both runs are real output from this machine on 2026-11-11, against the
`targets.allowed_cidrs` of `config.yaml` at the time.

### The shape of a query that runs

```text
net:<range you own> <location filters> <camera filters>
```

Shodan does not index private space, so the range in `net:` is a public range you
own or are authorized to test, declared in `targets.allowed_cidrs` as well (D37).
A narrower range inside a declared one is accepted: with `192.168.1.0/24`
declared, `net:192.168.1.0/28` passes the gate.

### Location filters

| Filter | Takes | Example |
|--------|-------|---------|
| `country` | 2 letter code, comma separated | `country:NL`, `country:DE,CH,FR` |
| `city` | city name, in quotes when it has a space | `city:"Amsterdam"` |
| `region` | region code | `region:NH` |
| `state` | state name | `state:"New York"` |
| `postal` | postal code | `postal:1011` |
| `geo` | radius search | listed by Shodan, syntax not on the pages reachable today |

Filter names and the quoting rule come from the Shodan docs
(`help.shodan.io/the-basics/search-query-fundamentals`,
`shodan.io/search/filters`). Only `net:` is checked by the gate: a `city:` name
and a `geo:` radius go to Shodan as written, and Shodan decides what they match.

### Filters that keep the result set on cameras

| Filter | Why |
|--------|-----|
| `has_screenshot:true` | a result with a screenshot is a device that served an image |
| `screenshot.label:webcam,cam` | Shodan labelled the image as a camera, the default of `config.yaml.example` |
| `port:554` | the RTSP port of D15 |
| `product:` / `device:` | one vendor or device string |

### Run it

Declare the range and the query in the config:

```yaml
shodan:
  api_key: "<your_shodan_api_key>"
  query: "net:203.0.113.0/24 country:NL has_screenshot:true screenshot.label:webcam,cam"
targets:
  allowed_cidrs: ["203.0.113.0/24"]
```

Then run the configured query, or type one for this run only:

```bash
uv run python main.py scan shodan
uv run python main.py scan shodan 'net:203.0.113.0/24 city:"Amsterdam" port:554'
```

The argument replaces `shodan.query` for that run and nothing else, so the same
`allowed_cidrs` still guards it. One config per country is one file per country:

```bash
uv run python main.py --config lab/nl.yaml scan shodan
```

`-v` adds one line per banner, in the formats `scanners/task.py` writes:

```text
198.51.100.7:554 added (priority=high)
Skipped 198.51.100.9:80 (blocked org/tag)
3 cameras added
```

A banner whose org, tags or hostname name an institution (school, hospital,
government, military, and the rest of the lists in `scanners/task.py`) is
skipped, so a country run does not store a hospital camera. A result that names
a residential, office or hotel tag is logged as `priority=high`; the rest are
`medium`. The `scan_run` row records the query itself, so the range a run
reached is written down even when nobody typed it.

### What gets stored

| Column | Holds |
|--------|-------|
| `camera.city` | city Shodan reports |
| `camera.country_code` | 2 letter country code |
| `camera.country_name` | country name |
| `camera.region_code` | region code |

### Read the stored cameras by place

`search` filters on person, camera and time, not on place, so a place question is
one SQL line:

```bash
docker compose exec postgres psql -U scanner -d cameras -c \
  "select country_code, city, count(*) from camera group by 1, 2 order by 3 desc"
```

A stored Shodan result is a public address, so it stays outside a private
`allowed_cidrs`: reach it with `--camera-id N`, or declare the range before
`scan check` and `scan cve` run over it.

### What was not run here

The accepted-query path has no real output in this file. The `config.yaml` of
this machine holds a live API key, so a run would spend credit and reach
`api.shodan.io`, and the ranges it declares are private, which Shodan does not
index (D37). The two refusals above are real; the accepted run is not.

---

## Exit codes

| Code | Meaning | Example |
|------|---------|---------|
| `0` | the command completed, including a run that found nothing | `scan cve` with no frame |
| `1` | a refusal the operator can fix, printed with its reason | target outside the range, unknown camera id, a timestamp that is not one |
| `2` | the command line itself is wrong | `main.py scan` with no command |

```console
$ uv run python main.py search --since nope
2026-11-11 13:52:46,290 ERROR nope is not a timestamp: Invalid isoformat string: 'nope'
$ echo $?
1
```

A finding of nothing is exit 0 with output that says so, so a caller can tell
"nothing there" apart from "it broke".

### Logging

| Stream | Carries |
|--------|---------|
| stderr | log lines, one per network step, before the call |
| stdout | results, so they pipe |

No credential value appears in any log line at any level (FR-030).

---

## The monitoring answer

### `report faces`

```console
$ uv run python main.py report faces
person 1  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
person 2  faces 2   first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 2  frame cve
```

```text
person 1  faces 22  first seen ...  last seen ...
│
├── camera 127.0.0.1:8000   frames 5    frame cve     ┐ how many frames
└── camera 127.0.0.1:8554   frames 17   frame rtsp    ┘ and which path found them
```

`--person-id N` narrows it to one person.

### `search`

```console
$ uv run python main.py search --since 2026-11-11T00:00:00Z
2026-11-11T15:45:04Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:14Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:23Z  person 2  camera 127.0.0.1:8000  frame cve
2026-11-11T15:52:06Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T16:42:22Z  person 1  camera 127.0.0.1:8000  frame cve
```

One line per appearance, oldest first. A person with no label prints as
`person <id>`, never as a name, because nothing labels a person automatically
(D28).

---

## Measure the face threshold

`face.match_threshold` ships as a placeholder of `0.5`. Do not trust it until it is
measured on a labelled pair set (D16, SC-010).

The set is one directory per identity, two or more images each:

```text
logs/faces/
├── friends/
│   ├── 01.jpg
│   └── 02.jpg
└── astronaut/
    ├── 01.jpg
    └── 02.jpg
```

```mermaid
flowchart LR
    A[friends/01.jpg] ---|same identity| B[friends/02.jpg]
    C[astronaut/01.jpg] ---|same identity| D[astronaut/02.jpg]
    A -.->|different identity| C
    B -.->|different identity| D
```

Every pair inside one directory is a same identity pair. Every pair across two
directories is a different identity pair.

```console
$ uv run python main.py measure threshold --pairs logs/faces
same identity        pairs 2   min 0.978  mean 0.986  max 0.993
different identity   pairs 4   min 0.039  mean 0.042  max 0.044
separation           0.934 between the largest different and the smallest same
```

```text
 0.0        0.1        0.5        0.9   0.978  1.0
  |----------|----------|----------|-----|---|
   different identity ..........  same identity
                              ^
                        put the threshold in this gap
```

The command reads only and writes nothing, including the config: a value that
changes itself is not a measured value. Pick a value in the gap, write it into
`face.match_threshold` by hand, and record the raw output and the pair set in the
front report. A directory with fewer than two images is refused with exit 1,
because one image cannot form a pair.

The run above used two identities of two images each, which shows the tool works
and does not settle a production value: two people say nothing about the pairs
that will actually be confused. Widen the set before relying on the number.

---

## CVE matching

`scan cve` matches what a scan already stored against an NVD feed, then reads each
match once through the read-only classes of the batch. It never opens a connection
for identification, and it sends no payload.

```mermaid
flowchart LR
    A[(camera_observation)] --> B{banner to CPE}
    B -->|cpe_map.yaml| C[NVD feed]
    C -->|match| D[read-only classes, in order]
    D -->|frame| E[(cve_finding + proof frame)]
    D -->|no frame| F[(cve_finding + reason)]
```

### Build the feed

The feed is NVD 2.0 JSON. Do **not** download the full year files: hundreds of MB,
and the loader holds the whole file in memory. Pull one product subset per product
you mapped, then merge.

```bash
curl -sG 'https://services.nvd.nist.gov/rest/json/cves/2.0' \
  --data-urlencode 'virtualMatchString=cpe:2.3:o:hikvision:ds-2cd2032-i_firmware' \
  --data-urlencode 'resultsPerPage=2000' -o nvdcve-hikvision.json

jq -s '{format:"NVD_CVE", version:"2.0",
        vulnerabilities: [.[].vulnerabilities[]]}' \
  nvdcve-*.json > nvdcve-2.0.json
```

| Gotcha | Fix |
|--------|-----|
| `cpeName` answers `HTTP 404` | use `virtualMatchString` on the same endpoint |
| the API rate-limits | `sleep 6` between calls |
| matching on the hardware CPE finds nothing | a camera CVE sits on the model firmware CPE, part `o` |

A ready-made camera subset ships in `samples/nvd_camera_sample.json`.

### Map your products

`cpe_map.yaml` translates the `product` string a scan reports into a CPE. Check the
name exists in the NVD dictionary first:

```console
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' \
    --data-urlencode 'cpeMatchString=cpe:2.3:o:hikvision:ds-2cd2032-i_firmware' \
    --data-urlencode 'resultsPerPage=1' | jq .totalResults
1
```

`totalResults` above 0 means the name is real. `0` means it was invented and the
entry would quietly match nothing. A new product is a YAML line, never a code
change.

---

## Data model

Seven entities. Frames are files, the database holds the path (D17).

```text
 ┌────────────┐        ┌─────────────────────┐
 │ scan_run   │        │ camera              │
 │ kind       ├───────►│ ip, port, vendor    │
 │ target_set │        │ url, user, status   │
 │ started_at │        └──────┬──────────────┘
 └────────────┘               │
                    ┌─────────┼──────────┐
                    ▼         ▼          ▼
        ┌────────────────┐ ┌────────┐ ┌──────────────┐
        │camera_         │ │cve_    │ │face_frame    │
        │observation     │ │finding │ │path, source  │
        └────────────────┘ └────────┘ └──────┬───────┘
                                             ▼
                                        ┌────────┐
                                        │ face   │
                                        └───┬────┘
                                            ▼
                                        ┌────────┐
                                        │ person │
                                        └────────┘
```

| File | Role |
|------|------|
| `models/camera.py`, `models/observation.py`, `models/frame.py`, `models/finding.py`, `models/face.py`, `models/person.py`, `models/scan_run.py` | the seven entities of `data-model.md` |
| `models/database.py` | `Database` owns the engine and a transactional `session_scope` (commit on success, roll back on error, always close) |
| `models/managers.py` | one repository per entity, the only place that queries a table; the reports read through `PersonReader`, which cannot write |
| `migrations/versions/` | `0001_initial_schema`, `0002_migrate_legacy_cam` |

---

## Configuration

All settings and keys live in one `config.yaml`, which is git-ignored.

```bash
cp config.yaml.example config.yaml
```

### The settings that matter most

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

### Config notes

| Setting | Note |
|---------|------|
| `targets.allowed_cidrs` | The authorization, written once. It guards the Shodan query and every command that reaches a stored camera. A run narrowed with `--camera-id N` reaches the camera the operator named, which is the authorization itself, so it is not gated |
| `face.match_threshold` | A minimum cosine similarity over the L2-normalized 512-d embedding: higher means more alike, 1.0 is the same direction (D44) |
| `checkers.concurrency` | Probes are I/O-bound. Raise gradually and watch the error rate |
| `nmap.xml_path` | Where a sweep writes its XML. `scan cve` does not read it: it matches what the scan stored (D30) |

The config is validated on load (`scanners/config.py`): a missing section fails
fast with a clear error. `config.yaml` holds secrets and is never committed. Only
`config.yaml.example` is.

---

## Troubleshooting

Every row below is a real failure seen while building this, with the real answer.

| Symptom | Cause | Fix |
|---------|-------|-----|
| sweep finds 5 hosts, zero cameras | hosts answer ICMP but no camera port is open | `nmap -Pn -p 554,80,... /24` to skip host discovery, and check the ARP table |
| devices appear in ARP but every port is `filtered` | MAC is randomized: a phone or laptop with a firewall | not a camera, ignore |
| ARP shows only the router | guest SSID or client isolation separates the clients | move the camera to the main SSID |
| camera not in ARP at all | no DHCP lease: it sits on its factory IP, or never associated | try `192.168.1.64` (Hikvision), `192.168.1.108` (Dahua) |
| `scan check` refuses 224 addresses | stored cameras from an earlier run are outside `allowed_cidrs` | `--camera-id N`, or declare the range |
| `bind: address already in use` on 5440 | another Postgres holds the port | `docker compose down`, or change `database.host` |
| `libx264` refuses the frame | odd width or height | `-vf "scale=trunc(iw/2)*2:trunc(ih/2)*2"` |
| ffmpeg publishes one frame then stops | `-stream_loop -1` does not loop an image input | `-loop 1 -re` |
| `method DESCRIBE failed: 404` | the RTSP path does not exist on that server | use the path the server publishes, not a wordlist guess |
| face scan finds nothing | the frame has no face, or the model is missing | check the JPEG by hand, then `ls ~/.insightface/models` |

Quick reachability check, no scanner involved:

```console
$ ping -c1 192.168.1.64
$ nc -vz 192.168.1.64 554 80
$ ffprobe -v error rtsp://192.168.1.64:554/Streaming/Channels/101
```

---

## Development

| Task | Command |
|------|---------|
| Tests (DB and network faked) | `uv run pytest -q` |
| Lint | `uv run ruff check .` |
| Add a dependency | `uv add <pkg>` |
| Add a dev dependency | `uv add --dev <pkg>` |

The tests run against an in-memory SQLite database and injected fakes, so the
whole suite passes with no Postgres, no camera and no network.

The code follows an OO/SOLID structure: one type per concept, strategies behind
`typing.Protocol`, dependency injection at the composition root (`main.py`),
context managers over `try/finally`, and dispatch tables over `if/elif`.

### Where the decisions live

| Document | Holds |
|----------|-------|
| `docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` | the 43 settled decisions |
| `.specify/memory/constitution.md` | the binding rules of this repository |
| `specs/001-camera-monitoring-pipeline/spec.md` | what is built and why |
| `specs/001-camera-monitoring-pipeline/research.md` | R1 to R11, the grounded findings |
| `specs/001-camera-monitoring-pipeline/data-model.md` | the seven entities |
| `specs/001-camera-monitoring-pipeline/contracts/cli.md` | the command line contract |
| `specs/001-camera-monitoring-pipeline/quickstart.md` | the lab runbook |
| `docs/front-*.md` | what each front proved, with raw output |

---

## Disclaimer

This is a security research tool. It is provided as is, with no warranty. The
author is not responsible for misuse, for damage caused by a run, or for the legal
consequences of reaching a device you do not own. Reading a frame from a camera you
do not control is unauthorized access and interception in most jurisdictions. The
gate exists to make the authorized range explicit; it does not make a wrong range
legal.

## License

MIT.
