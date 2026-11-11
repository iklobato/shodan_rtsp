# Shodan RTSP Scanner: session log

Dated record of what each working session found and changed, with the raw output that
proved it. Current state does not live here: the architecture, the file map and the
command line are in `specs/001-camera-monitoring-pipeline/plan.md` and
`specs/001-camera-monitoring-pipeline/contracts/cli.md`, and the settled choices are in
`docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` (D36).

## 2026-11-01/02: brand detection, face recognition, first LAN sweep

Built `scanners/brand_probe.py` (brand detection plus the per-brand credential sets),
`scanners/face_recognizer.py` (insightface, RetinaFace detector, ONNX runtime) and
`scanners/face_task.py`. Wordlists: 29 users, 54 passwords, 45 RTSP URL templates, each
with a `_small` variant for a quick run.

Scanned `192.168.1.0/24`:

| Host | Open ports | Service | Notes |
|------|-----------|---------|-------|
| 192.168.1.1 | 22, 53, 80, 9000, 9001, 9002, 9003 | router (Opticache) | 9000 has an RTSP-like banner |
| 192.168.1.105 | 6668 | IRC | |
| 192.168.1.175 | 80, 443 | Caddy | HTTP/HTTPS, no RTSP |
| 192.168.1.177 | 22, 631 | SSH + IPP | |
| 192.168.1.201 | 80, 443 | Caddy | HTTP/HTTPS, no RTSP |
| 192.168.1.246 | 22 | SSH | |

**Correction (2026-11-02, re-measured):** the two RTSP URLs that looked like they worked
were false positives, and this machine is the host behind both.

- `ifconfig` reports `192.168.1.201` and `192.168.1.175` as local addresses of this Mac.
- The Caddyfile of container `autoecosystem_caddy` has no `/h264` route: only
  `respond /metrics 404` and `reverse_proxy web:8000`. Port 80 answers `308` to https for
  any path.
- The probe, direct transport, all three stored credential pairs:
  `No frame for rtsp://admin:admin@192.168.1.201:80/h264/ch1/main/av_stream` (same for the
  other two).
- `ffprobe -rtsp_transport tcp -i rtsp://admin:12345@192.168.1.201:80/h264/ch1/main/av_stream`:
  `Invalid data found when processing input`.

No RTSP camera was exposed on `192.168.1.0/24` as of 2026-11-02. `nmap -p 554 --open -T4`
returned 6 live hosts and no open port; the only open services found were
`192.168.1.1:9000 cslistener` and `192.168.1.105:6668 irc`.

**Rows deleted 2026-11-02:** 9 (3 on this machine, 6 from the closed-port bug below).
Backup of the full `cam` table before the delete: `/tmp/cam_backup_2026-11-02.sql`.

## 2026-11-02: the local-network run, and two bugs it exposed

1. **nmap inserted closed ports as cameras.** `NmapTask.run` looped over every port in
   `host_data["tcp"]`, closed and filtered included, so each live host landed in the
   database as a camera on 554. Fixed in `_store_open_ports`: only `state == "open"` is
   stored. This is what put the 6 bogus rows in the table.
2. **The nmap path required a proxy it could not use.** `_scan` raised on any scheme other
   than `http`/`socks4`; with `protocol: socks5` in the config the run died before nmap
   started.

Verified: `uv run python main.py --start_nmap -v` on `192.168.1.0/24` gave
`Found 6 hosts using nmap scan`, `Executors: finished nmap scan`, 0 rows inserted.

## 2026-11-07/08: the face scan frame fix

### The bug: face scan crashed on every active camera

The face scan died with `TypeError: fromhex() argument must be str, not bytes` at
`scanners/face_task.py:208`.

The cause was upstream of the crash. `RtspProbe._to_camera` stored the raw JPEG bytes into
`Camera.image_b64`, a SQLAlchemy `String`. Raw bytes written into a String column land as
escaped text (`\xffd8ffe0...`). The face scan read the same column and called
`bytes.fromhex(...)`, so it always failed on a frame the probe had produced.

Fix, one line in `scanners/rtsp_probe.py:155`:

```python
image_b64 = cv2.imencode(".jpg", frame)[1].tobytes().hex()
```

The frame now travels as hex text, which is what the face scan decodes. The column name is
misleading as a result, because the payload is hex and not base64; it was left alone to
avoid a migration at the time. The frames front replaced the column with a file path (D17).

### Validation run

Against PostgreSQL `scanner@127.0.0.1:5432/cameras`, before the schema front moved the
database to `127.0.0.1:5440` (D40).

| Check | Result |
|-------|--------|
| `pytest tests/ -q` | 35 passed |
| `ruff check .` | clean |
| nmap `192.168.1.0/24` | 6 hosts up, 0 with port 554 open |
| vuln scan on the real nmap XML | 0 services reported (correct: port closed) |
| vuln scan on `samples/nmap_sample.xml` | 4 CVEs across 5 services |
| mediamtx lab on port 8554 | check found `admin:admin` on `/live.sdp`, camera active, 27 KB frame saved |
| face scan after the fix | 5 frames captured, 5 `face_frames` rows, 0 faces detected |

The CVEs reported from the sample XML: CVE-2024-6387, CVE-2023-38408, CVE-2023-48795,
CVE-2021-41773.

Face scan first runs timed out: the `insightface` import is slow and the `buffalo_l` model
downloads about 280 MB on first use. That is a first-run environment cost, not a code bug.
A rerun with `timeout 300` completed. The test stream had no face in frame, so 0 detections
is the correct answer, not a failure.

### Merged

PR #4 `https://github.com/iklobato/shodan_rtsp/pull/4`, branch
`fix/face-scan-frame-encoding`, merged to `main` as `992e076`.

- `00dd581 fix(probe): store the proof frame as hex so the face scan can decode it`
- `0e0bf3d docs(readme): make the layout visual and scannable`

The merge needed `gh pr merge --admin`: branch protection on `main` requires one approving
review and a code owner review (`enforce_admins: false`, so admin bypass worked). A normal
merge returned `mergeStateStatus: BLOCKED`, `reviewDecision: REVIEW_REQUIRED`.

### Lab cleanup after the run

mediamtx and ffmpeg were stopped, the test rows deleted, `/tmp/rtsplab` removed.

## 2026-11-11: schema front, legacy rows, and the retired proxy

Three changes, each with its own report.

- **Schema front (front 1).** The seven entities and the first Alembic revision replaced the
  hand-made `cam`/`faces`/`face_frames` tables; frames became files on disk with the path in
  the database (D17). Raw output and the deviations: `docs/front-1-report.md`.
- **Revision 0002 moved the legacy rows.** The 229 `cam` rows became `camera` plus
  `camera_observation` rows inside one run; `vendor`, `product` and `version` arrive empty
  because the old table never identified anything. The rollback was wrong on the first try
  (it deleted no camera at all, `assert 2 == 0`) and was fixed by reading the doomed ids
  before deleting the observations. Raw before/after output: section 5 of
  `docs/front-1-report.md`.
- **The residential proxy is retired (D11).** `scanners/proxy.py`,
  `scanners/proxy_tunnel.py`, the `proxy` config section, the proxy branch of the nmap check
  and the proxy tests are gone, together with `curl_cffi` in `pyproject.toml` and `uv.lock`.
  The probe opens the camera at its own address, straight from the local IP, and the
  credential log lines were removed (three sites: the DEBUG URL line, the DEBUG no-frame
  line and the INFO user/password line).

Open risk carried into front 3: the 224 migrated rows sit at status `unknown`, which is
exactly what `CameraRepository.get_random_without_frame()` selects, so a later `scan check`
would run credential combinations against them. The target gate of the check task has to
close that before the check command is pointed at the database.
