# Quickstart: Camera Monitoring Pipeline

**Feature**: `specs/001-camera-monitoring-pipeline/spec.md`
**Created**: 2026-11-11

Every command below was checked against this machine on 2026-11-11: `ffmpeg` at
`/usr/local/bin/ffmpeg`, `mediamtx` v1.11.3 at `/usr/local/bin/mediamtx`, Docker Compose
v2.39.2, Python 3.11.7 through `uv`, and the `buffalo_l` model already cached at
`~/.insightface/models/buffalo_l`.

This quickstart is for the lab. Pointing it at anything else is out of scope (FR-001).

## 0. Lab prerequisites

| Piece | State | Note |
|-------|-------|------|
| `mediamtx` | installed, v1.11.3 | serves the RTSP stream the tool reads |
| `ffmpeg` | installed | publishes a loop into `mediamtx` |
| `buffalo_l` | cached | 280 MB, downloads on first face run when absent |
| Docker | running | the dedicated database |
| FEMU or FirmAE | to install | emulates the vulnerable camera firmware (front 6) |
| Hikvision firmware | to download | old build, no vendor login needed, from the Hikvision European portal |
| Face pairs | to supply | images of consenting people, or a public dataset whose licence allows it |

The face pairs are what the threshold measurement needs (D16): several images of the same
person and several of different people. The measurement records which set it used.

## 1. Start the database

```bash
docker compose up -d postgres
docker compose ps
```

The service is `shodan_pg` on host port 5440 (D40). Port 5433 is already taken by
`deploy-postgres-1` on this machine, which is why the port moved.

## 2. Configure

```bash
cp config.yaml.example config.yaml
```

Then, in `config.yaml`:

- remove the whole `proxy:` section (D11)
- set `targets.allowed_cidrs` to the range the scanner may reach, `["127.0.0.1/32"]` for
  this lab. An empty list authorizes nothing, so a `scan check` over stored cameras is
  refused until its addresses are here (D18, FR-001). A run narrowed with
  `scan check --camera-id N` is not gated: naming the camera is the authorization.
- set `nmap.ip_range` to the lab range
- set `database.host` to `localhost:5440`
- add `frames.root_path`, for example `logs/frames`
- add `brands.signature_path: brands.yaml`
- set `vuln.cpe_map_path` and `vuln.feed_path` as today
- add `face.pairs_path: logs/faces` (git-ignored: the set is photos of real people)
- `face.match_threshold` is a minimum cosine similarity and is a placeholder until step 7

`config.yaml` is git-ignored and holds the Shodan key. It stays out of git.

## 3. Create the schema

```bash
uv run alembic upgrade head
uv run alembic current
```

The first run creates every table. The second run changes nothing, which is SC-001.

## 4. Stand up the lab target

The RTSP side. The repository ships no video file, so the stream is published from a still
image on a loop: one with a face in it, because that is what `scan faces` reads. The path is
whatever the camera URL carries, and `lab/mediamtx.yml` accepts every path, since `mediamtx`
with no configuration file serves only paths that were declared:

```bash
mediamtx lab/mediamtx.yml &                  # RTSP on 127.0.0.1:8554
ffmpeg -loop 1 -re -i logs/faces/friends/01.jpg \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  -r 10 -c:v libx264 -pix_fmt yuv420p -g 10 -f rtsp -rtsp_transport tcp \
  rtsp://127.0.0.1:8554/h264/ch1/main/av_stream
```

Two details cost a run each: libx264 refuses an odd width or height, hence the `scale`, and
`-stream_loop -1` does not loop an image input, so the image is looped with `-loop 1 -re`.

The vulnerable side is the emulated firmware (front 6). Its acceptance is narrow: the
emulated device answers `GET /onvif-http/snapshot?auth=YWRtaW46MTEK` with a JPEG. Paste the
raw response as the front evidence. If the emulation cannot be made to answer, that is a
recorded failure and the front is blocked, not faked.

## 5. Scan

```bash
uv run python main.py scan nmap 127.0.0.1/32
uv run python main.py scan check
uv run python main.py scan cve
uv run python main.py scan faces
```

`scan cve` exits 0 even when no frame comes back. Read the `cve_finding` rows for the
outcome and the reason.

## 6. Read the result

```bash
uv run python main.py report faces
uv run python main.py search --since 2026-11-11T00:00:00Z
```

`search` prints one line per appearance, oldest first. That output is SC-006.

## 7. Measure the face threshold

Do this before trusting any threshold value (D16, SC-010).

1. Put the pairs in the lab directory: several images of one person, several of others.
2. Run `uv run python main.py measure threshold --pairs logs/faces` and record the
   similarity of the same person against the similarity of different people.
3. Pick the value that separates the two groups, and write it into
   `face.match_threshold`.
4. Record the raw output, the pair set used, and the chosen value in the front report.

Until step 4, every appearance of a threshold in the config and the docs is a placeholder
and is labelled as one.

## 8. Verify

| Check | Command | Expected |
|-------|---------|----------|
| Schema from zero | `uv run alembic upgrade head` twice | second run changes nothing |
| One row per camera per port per run | `uv run python main.py scan nmap 127.0.0.1/32` twice | two `scan_run` rows, the same `camera` rows, two observations per port |
| Read-only proof | compare the device state before and after `scan cve` | identical |
| One person, not two | `uv run python main.py scan faces` on a repeated face | one `person` row |
| No credential in the log | `uv run python main.py -v scan check 2>&1 \| grep -i <the password>` | no match |
| Gates | `uv run pytest -q` and `uv run ruff check .` | both pass |

## 9. Stop

```bash
docker compose stop postgres
kill %1 %2          # mediamtx and ffmpeg
```

Frames stay on disk under `frames.root_path` and rows stay in the database. Nothing in
this batch purges either one (D10, D13).
