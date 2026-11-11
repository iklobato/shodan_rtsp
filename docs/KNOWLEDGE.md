# Shodan RTSP Scanner: session log

Dated record of what each working session found and changed, with the raw output that
proved it. **An agent starting here reads the newest dated section first: it carries the
current state, the open work, the traps and what needs watching.** The architecture, the file
map and the command line are in `specs/001-camera-monitoring-pipeline/plan.md` and
`specs/001-camera-monitoring-pipeline/contracts/cli.md`, the settled choices in
`docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` (D36), and the raw lab evidence of each
front in `docs/front-<n>-report.md`.

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
close that before the check command is pointed at the database. **Closed in front 3**: the
gate now refuses a wide check run and lets a narrowed one through, and the 229 legacy rows sit
outside `targets.allowed_cidrs`, so they are inert. The section below is the state after that.

## 2026-11-11: the prod-ready batch, fronts 2 to 5, and the state it left

Front 1 has its own section above. This one covers the rest of the batch: the grill rounds
that settled 45 decisions, the spec-kit artifacts, fronts 2 to 5, and where the repository
stands at the end of it.

### The batch, in one paragraph

The work started from five asks (scan a network, name the cameras, reach a frame through a
CVE, read the faces, organize the data for monitoring) and one boundary: the pipeline is
built for the own lab plus targets with written authorization (D1), because the same five
asks aimed at third-party cameras are unauthorized access plus biometric processing of people
who never agreed. The grill settled 45 decisions into
`docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md`, `spec-driven` picked the High tier,
and the spec-kit artifacts (`spec.md`, `plan.md`, `research.md`, `data-model.md`,
`contracts/`, `quickstart.md`, `tasks.md`) landed in `specs/001-camera-monitoring-pipeline/`.
The five fronts of D12 then ran in order on the branch `feat/schema-migrations`, delivered as
one PR (D32), with D24 as the definition of done: a test that fails if the logic breaks, plus
a real run in the lab with the raw output pasted into the front report.

### Front 2: dead code and bugs (`docs/front-2-report.md`)

Removed: the residential proxy (`scanners/proxy.py`, `scanners/proxy_tunnel.py`, 467 lines,
D11) with `curl_cffi` and six packages out of `uv.lock`; the `proxy` config section and the
proxy branch of the nmap check; `_sanitize_city`, which mutated its argument; the unreachable
low-priority branch of `scanners/task.py`; and `_probe_names.py`,
`docs/proxy-investigation.md`, `proxylist.txt` and `.serena/` (D23).

The discovery: the credential leak was three log sites, not the one the task named. T030
pointed at `scanners/rtsp_probe.py:146`; the test written first found two and reading the file
found the third, the DEBUG line that logged the whole URL on opening the camera and the DEBUG
line that logged it again when no frame arrived. The failing test output:

```
a credential reached the log: ['rtsp://leakeduser:leakedpassword@10.0.0.5:554/live', 'No frame for rtsp://leakeduser:leakedpassword@10.0.0.5:554/live']
```

The probe now logs address and port only. `tests/test_logging.py` keeps a positive control, so
it can fail for the right reason: the same run asserts the URL handed to the capture still
carries both credentials, because otherwise a probe that opened nothing would pass.

Tests went from 67 to 51: the proxy suite went with the proxy code, against new tests for the
credential log and for the direct transport.

Trap: five tests error in a tree extracted with `git archive HEAD`, with
`FileNotFoundError: config.yaml`. That is the artefact of the archive and not a result:
`config.yaml` is git-ignored and holds credentials. Add the errors to the passes to compare
with the in-repository number.

### Front 3: identification (`docs/front-3-report.md`)

Shipped: `brands.yaml` as a data file (D27), `scanners/brand_probe.py` rewritten to read it,
the raw banner (`data`, `http`, `cpe`) plus the interpreted identity on the camera row (D3),
the brand credential set tried ahead of the generic wordlists (D22), `TargetGate` over every
stored camera (renamed from `ShodanScope`), `scan check` on the command line, and
`targets.allowed_cidrs` in place of `shodan.allowed_cidrs`. Tests 51 to 79.

Discoveries worth keeping:

1. **The legacy rows cannot be re-identified from the database.** Measured after the front:
   232 cameras, 1 with a vendor, 3 with a raw banner, status `[(stream_obtained, 6),
   (unknown, 226)]`. The 229 rows the legacy import brought in carry no banner, so adding
   their brands to `brands.yaml` does not name them: only a fresh scan of their addresses can,
   and those addresses are outside every declared list. They are inert until someone declares
   a range that covers them, in writing.
2. **The refusal message was uncapped**, one line of 227 addresses. It now names ten and
   counts the rest, and `_NAMED_LIMIT` is the knob.
3. **A Shodan run does not refresh a row it already has.** `ShodanTask._store_banner` returns
   early when the camera exists, before writing the identity and before recording the
   observation, so a camera nmap created stays unnamed even when a later Shodan banner names
   it, and no `camera_observation` is written for it in that run (FR-006). Pre-existing, and
   untestable here without a Shodan key.
4. The four `generic_*` entries are not in `brands.yaml`: they duplicated the wordlist files,
   and the generic set is still tried through the wordlists after the brand set.
5. `ruff format` is not enforced in this repository. `ruff format --check .` flags nine files,
   four of them untouched by any front. Only `ruff check` runs, through the quality hook.
   Reformatting the repository is a separate decision.

### Front 4: the read-only CVE classes (`docs/front-4-report.md`)

Shipped: the four read-only classes of D9 under `scanners/cve/`, with `base.py` holding the
attempt contract and the transport: `HikvisionAuthBypass` (authentication bypass),
`SeleaFileRead` and `JvcFileRead` (unauthenticated file read) and `XiongmaiOnvifInfo`
(unauthenticated ONVIF). They are tried in batch order until one returns a frame, one
`cve_finding` per camera and CVE is updated in place, the frame is stored once, every network
step is bounded by `vuln.timeout_seconds`, and the ONVIF read records the model and the
firmware even when it yields no picture. Tests 79 to 107.

The read-only property (D-16): at most one frame is pulled and nothing is written to the
device. A class that yields no frame is recorded with its reason and the next class is tried
(FR-018).

Discoveries: the transport of one class never worked (D-17); the identity chain matched
nothing because the feed carries no CPE for the product string as written (D-19), fixed by
retrying the pair as its firmware CPE; two of the four classes can never be selected while the
feed carries no CPE for their CVE (D-20), and the `unauth_read` class returns a file rather
than an image, so its honest outcome is a recorded absence.

The rig is a mock, not firmware. D42 asked for FEMU or FirmAE with an old Hikvision build,
T008 was not done, and `docs/front-4-rig.md` records why: no public container reproduces a
camera CVE, and both emulators expect the operator to supply the firmware binary. The report
says exactly what the mock leaves unproved.

### Front 5: faces, people and the monitoring answer (`docs/front-5-report.md`)

Shipped: face detection (insightface `buffalo_l`, 512-d normalized embedding, cosine
similarity, D44), clustering into a `person` row with a merge when one face matches two
clusters (D35), frames as files on disk with the path in the database (D17), and the four
commands `scan faces`, `report faces`, `search` and `measure threshold`. Tests 107 to 141.

The defect the lab exposed, and the reason the front is worth reading: the frame name of R8
resolves to the second, and a run may capture several frames of one camera inside one second,
so the second row died on `UNIQUE (path)`; the run also collected every frame before storing
any, which made `captured_at` the instant of the store instead of the instant of the capture.
Both halves are fixed: each frame is written as it is captured, and a name already on disk
gains a counter suffix (D-28). The raw `IntegrityError` is in section 7 of the front report.

The RTSP half needed a stream the repository did not have, so the lab grew one: `mediamtx`
v1.11.3 serving the path `h264/ch1/main/av_stream` on `127.0.0.1:8554`, with `ffmpeg`
publishing a still image on a loop. `lab/mediamtx.yml` is the lab config (D-29),
`quickstart.md` step 4 was corrected to publish an image instead of the `lab/face.mp4` the
repository does not ship (D-30), and `lab/mock_camera.py` gained `--image` (D-24) because the
synthetic frame holds no face.

The live proof, one person across both paths, from the last run of the front:

```
person 1             faces 13  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T15:57:46Z
  camera 127.0.0.1:8000  frames 2  frame cve
  camera 127.0.0.1:8554  frames 11  frame rtsp
person 2 (lab-demo)  faces 1   first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 1  frame cve
```

One `person` row spans a camera read through a CVE class and a camera read over RTSP, which is
FR-022 and FR-027 in a single answer. `person 2` carries a label that was set by hand for the
run and set back to `NULL` afterwards: nothing in this batch writes `person.label`, so the id
stays the only name the pipeline itself gives a person (D28, D-31).

### Current state, measured 2026-11-11 after every run above

The command line, four groups and nine commands:

```
python main.py [--config PATH] [-v] <group> <command> [options]
  scan    nmap | shodan | check | cve | faces
  report  faces
  search  the monitoring answer, top level and with no subcommand
  measure threshold
```

Entities: `camera`, `scan_run`, `camera_observation`, `cve_finding`, `face_frame`, `face`,
`person` under `models/`, with the Alembic revisions `0001_initial_schema` and
`0002_migrate_legacy_cam`.

The lab database, `scanner@127.0.0.1:5440/cameras` in the container `shodan_pg` (postgres 16),
read live:

| Table | Rows |
| --- | --- |
| `camera` | 232, of which 229 outside loopback |
| `camera_observation` | 235 |
| `scan_run` | 17 (nmap 5, shodan 1, cve 6, faces 5) |
| `cve_finding` | 1 |
| `face_frame` | 10 (4 on camera 231, 6 on camera 232) |
| `face` | 14 |
| `person` | 2, both unlabelled |

Camera status: `unknown` 225, `stream_obtained` 6, `frame_by_cve` 1. No `scan_run` is left
open.

The gate is two commands, because there is no CI (D20):

**Correction (2026-11-11, later the same day): CI exists now.** `ci.yml` runs the same two
commands on every pull request and on every push to `main`, and `publish.yml` runs them again
before a release tag reaches the registry. The paragraph and the block below are the gate as
this batch was delivered. See the container section at the end of this file.

```
$ .venv/bin/python -m pytest -q
141 passed in 12.86s

$ .venv/bin/ruff check .
All checks passed!
```

Delivery: PR #6 at `https://github.com/iklobato/shodan_rtsp/pull/6`, branch
`feat/schema-migrations`, 17 commits on top of `main` at `0ca51ee`. No reviewer is named and
none was asked, by the owner choice of 2026-11-11: the repository has one collaborator, its
owner, and all six PRs carry zero reviews.

### Traps a future agent will hit

1. `UNIQUE (path)` on `face_frame` plus a file name that resolves to the second: two frames of
   one second collide unless the name gains the counter suffix (`scanners/frames.py`).
2. `captured_at` must be the instant of the capture, not of the store, or `search` answers the
   wrong time. This is why `_captured_frames` in `scanners/face_task.py` is a generator.
3. `FaceConfig` is a pydantic `BaseModel`: use `model_copy(update={...})`, never
   `dataclasses.replace`. `FaceScanDeps`, `PersonSummary` and `PersonAppearance` are frozen
   dataclasses, so `replace` is right for those.
4. `face.frames_per_scan: 0` reads no frame at all. It does not mean one frame.
5. `lab/face.mp4` does not exist in the repository.
6. The immutable-rules hook blocks a Write or an Edit that adds a module-level function, a
   fourth parameter, a method over 20 lines, a magic number, a bare `print` or a missing type
   hint. Every function of this repository lives in a class.
7. A wide `scan check` or `scan faces` is refused by the gate, because the 229 legacy rows sit
   outside `targets.allowed_cidrs`. Run narrowed with `--camera-id N`, which is the
   authorization itself.
8. `config.yaml` is git-ignored, so any tree from `git archive HEAD` fails the migration tests
   with `FileNotFoundError: config.yaml`.
9. Tests run with `.venv/bin/python -m pytest -q`. `uv run pytest -q` also works.

### What is not proved

- **No emulated firmware.** The device is the mock of `docs/front-4-rig.md`, so the CVE claim
  is proved against the request shape the advisory publishes, not against Hikvision code.
- **Only one class is proved against a device that answers.** A class runs only when its CVE
  matched the camera, and the mock matched one. Section 6 of `docs/front-4-report.md` lists
  what else the mock leaves unproved, the batch order and the timeout included.
- **The threshold is a placeholder.** `face.match_threshold` is 0.5, measured on two
  identities and six pairs, which shows the tool works and the two groups separate, not a
  production value (D45, SC-010).
- **The quickstart was never run end to end on this machine**, because the lab database holds
  the 229 legacy rows and the gate refuses a wide run. Every step ran narrowed instead.
- **The Shodan path never ran live.** No key here, and Shodan does not index private space, so
  the mode cannot serve the lab at all (D37).
- **Nothing checks that a frame file is still on disk.** Today the 10 rows and the 10 files
  match; a deleted file leaves a row pointing at nothing.

### Next steps

1. Merge PR #6 or leave it open. It carries the whole batch and nothing is pending on it.
2. Measure `face.match_threshold` over a wider pair set and replace the 0.5 placeholder.
3. Decide whether `scan_run` gains a `status` column: today a run that crashed and a run that
   finished read the same once `finished_at` is set.
4. Give each brand a model list checked against the NVD dictionary, so more than one pair in
   `brands.yaml` matches a CVE. Data work, not code.
5. Fix `ShodanTask._store_banner` so a Shodan run refreshes a row nmap created and records an
   observation for it (FR-006).
6. Larger and optional: the emulated firmware rig of D42, if the CVE claim has to be proved
   against real firmware.

### What to watch

- **A run left open.** `select id, kind, started_at from scan_run where finished_at is null;`
  Anything here is a run that died. It was one row, id 15, the crash of section 7 of the front
  5 report, until it was closed at the instant of its own frame row.
- **Camera status drift.** 225 rows sit at `unknown`, which is what a check run selects, so any
  new scan of their addresses flips them.
- **A refusal from the gate.** It means the database holds addresses outside
  `targets.allowed_cidrs`: the gate working, and the signal that someone reached a range that
  was never declared.
- **The placeholder threshold.** Any claim about face matching is unvalidated until 0.5 is
  replaced by a measured value.
- **Frames on disk against rows.** `face_frame` holds 10 paths and `logs/frames` holds the same
  10 files. Nothing enforces it.
- **The open risks of the decisions file**, section `Open risks`, still stand: no scope gate in
  code (D6), keep everything forever (D10, D13), biometric data of third parties in plain files
  with no encryption or access control, credentials stored in plaintext in `camera.password`,
  and no rotation (D39).

## 2026-11-11 (later): the container, the CI, and the first release

Second batch of the same day. Branch `feat/docker-release`, PR #8, merged at `26b7e20`. Docs
follow-up on `docs/first-release`, PR #9, merged at `6264965`. Tag `v0.1.0`, published to Docker
Hub as `iklob1/shodan-rtsp`. Before this batch the repository had no CI and no image.

### What was built

| Piece | What it is |
|-------|------------|
| `Dockerfile` | Two stages. The builder is `python:3.11-slim-bookworm` with `ghcr.io/astral-sh/uv:0.9.11`, `UV_PROJECT_ENVIRONMENT=/opt/venv`, `UV_COMPILE_BYTECODE=1` and `uv sync --frozen --no-dev`. The runtime stage installs `ca-certificates libgl1 libglib2.0-0 libgomp1 nmap`, copies `/opt/venv` only, adds user `scanner` (uid 1000) and sets `ENTRYPOINT ["/opt/venv/bin/python", "main.py"]`. No compiler ships. |
| `.dockerignore` | `config.yaml`, `.env` and `proxylist.txt` never enter a layer, plus `.git`, `.github`, `.claude`, `.venv`, `tests`, `specs`, `docs`, `logs`, `Dockerfile` and `docker-compose.yml`. |
| `docker-compose.yml` | New `scanner` service behind the `cli` profile: `image: ${SHODAN_IMAGE:-iklob1/shodan-rtsp:0.1.0}`, `DATABASE_HOST: postgres:5432`, the config mounted read-only, and two named volumes for the logs and the face model. `docker compose config --services` still prints `postgres` alone. |
| `scanners/config.py` | `load_config` reads `DATABASE_HOST` and overrides `database.host` when it is set. |
| `tests/test_config_database_host.py` | Three tests: the environment wins over the file, the file stands when the variable is unset, the rest of the file is untouched. |
| `.github/workflows/ci.yml` | `ruff check .` and `pytest -q` on a push to `main` and on every pull request. It also declares `workflow_call`, so `publish.yml` runs this job instead of a second copy. |
| `.github/workflows/publish.yml` | On a `v*` tag: runs the ci job, checks the tag against the version in `pyproject.toml`, builds `linux/amd64` with `load: true` and the gha cache, smoke tests those exact bytes, then `docker push --all-tags`. |

The override exists because the database address is the only value that differs between a run on
the host (`localhost:5440`, D40) and a run in a container (`postgres:5432` through compose,
`host.docker.internal:5440` for a single `docker run`). Everything else, the Shodan key, the
allowed ranges and the credentials, stays in `config.yaml`, which is mounted read-only and is not
in the image.

The container runs as `scanner`, uid 1000, which is enough for the seven commands: the sweep asks
nmap for `-p ... -sV` only.

### The image, as measured

```console
$ docker image ls shodan-rtsp:0.1.0 --format '{{.Repository}}:{{.Tag}} {{.Size}}'
shodan-rtsp:0.1.0 1.82GB

$ docker pull iklob1/shodan-rtsp:0.1.0
Digest: sha256:967ba68bab12bcf04e06a56cd04aa37d1426690547f4526b598377771674bdb8
Status: Downloaded newer image for iklob1/shodan-rtsp:0.1.0

$ docker run --rm --entrypoint id iklob1/shodan-rtsp:0.1.0
uid=1000(scanner) gid=1000(scanner) groups=1000(scanner)

$ docker run --rm --entrypoint /opt/venv/bin/python iklob1/shodan-rtsp:0.1.0 -c "import sys, cv2, nmap, onnxruntime, psycopg2; print(sys.version.split()[0], cv2.__version__, onnxruntime.__version__)"
3.11.18 4.11.0 1.20.1

$ docker run --rm --entrypoint nmap iklob1/shodan-rtsp:0.1.0 --version
Nmap version 7.93 ( https://nmap.org )
```

`/app` holds `config.yaml.example` and no `config.yaml`, no `.env`. The Hub reports 416 MiB per
tag, which is the compressed download; the image on disk is 1.82 GB, because `insightface` pulls
`scipy`, `scikit-learn`, `matplotlib` and both `opencv-python` wheels behind it.

### The release, as it went

```
latest sha256:967ba68bab12 2026-11-11T17:56:38Z
0.1.0  sha256:967ba68bab12 2026-11-11T17:56:36Z
0.1    sha256:967ba68bab12 2026-11-11T17:56:34Z
```

All three tags point at the same digest, and the digest on this machine after the pull is that
same one. What ran from the published image, not from the local build:

| Command | Result |
|---------|--------|
| `report faces` with `DATABASE_HOST=host.docker.internal:5440` | `person 1 faces 22 ... camera 127.0.0.1:8000 frames 5 frame cve` |
| `scan nmap 127.0.0.1/32` | `Found 1 hosts using nmap scan`, `nmap XML written to logs/nmap.xml`, and `scan_run` gained `26 \| nmap \| 127.0.0.1/32 \| 0` |
| `scan shodan 'country:NL'` | refused before any API call: `ERROR the query names no net: range, so it reaches the whole index; declare the range the scan may reach in the query itself` |
| `scan`, `report`, `search`, `measure` with `--help` | each lists its subcommands |
| `docker compose run --rm scanner --help` | the compose path uses the published image, no build |

The repository on the Hub did not exist before the tag push
(`api/v2/repositories/iklob1/shodan-rtsp/` answered 404) and the push created it as a public
repository. The Hub docs describe creating it in the UI and do not promise this, so the README
says both.

Two repository secrets drive `publish.yml`: `DOCKERHUB_USERNAME`, which is also the namespace,
and `DOCKERHUB_TOKEN`, which needs **Read & Write**. The Hub generates a token read-only by
default and a read-only one is refused at the push. On this machine both were already in the
environment and the account was already in the Docker Desktop keychain, so `docker login`
succeeded with no new credential.

PR #1, from the fork `Yaimsputnik5/shodan_rtsp` and opened on 2026-06-03, was closed as obsolete.
It conflicts with `main` in `main.py`, `models/camera.py` and `models/managers.py`
(`git merge-tree --write-tree main pr1`), it adds a `models/db_init.py` that calls
`Base.metadata.create_all` at import time, its table creation in `models/camera.py` sits after a
`return`, and it drops the cleanup of the `city` value. The schema belongs to alembic now.

### Four defects the first CI run found

Each one was green on this Mac and red on a clean runner. All four are fixed.

1. **`astral-sh/setup-uv@v10` does not exist.** The run died in seconds:
   `##[error]Unable to resolve action astral-sh/setup-uv@v10, unable to find version v10`.
   setup-uv publishes no floating major tag, so the workflow pins `v10.3.3` exactly. The other
   actions do publish their majors (`checkout@v7`, `setup-buildx-action@v4`, `login-action@v4`,
   `metadata-action@v6`, `build-push-action@v7`).
2. **`NmapTask` built its `PortScanner()` in `__init__`.** python-nmap looks for the nmap binary
   there, so the binary became a requirement of every caller, the tests that inject their own
   scanner included. Those tests failed with
   `nmap.nmap.PortScannerError: 'nmap program was not found in path'`. The scanner is built on
   the first scan now, through `_scanner()`.
3. **The migration tests read the developer config.** Without `config.yaml` they raised
   `FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'` instead of the skip
   the module docstring promises. They skip on that error now, and `ci.yml` starts a throwaway
   `postgres:16` service and writes a `config.yaml` from the example with placeholder
   credentials, so the five tests run in CI instead of skipping. Verified here by running the
   suite from a directory with no `config.yaml`: `139 passed, 5 skipped`.
4. **`test_load_config_reads_all_sections` was decided by the environment.** It asserts the dsn
   of a file it wrote itself, and the `DATABASE_HOST` that the job exports for the migration
   tests was overriding it:
   `AssertionError: assert 'postgresql:/...alhost:5432/d' == '***h/d'`. The test unsets the
   variable first. Second run with `DATABASE_HOST=localhost:5432` in the shell: `144 passed`.

### Traps a future agent will hit

1. **`astral-sh/setup-uv` has no floating major tag.** Pin an exact version or the job never
   starts. The same check applies to any new action:
   `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`.
2. **`main` requires one approving review** (`required_approving_review_count: 1`,
   `require_code_owner_reviews: true`, `enforce_admins: false`) and no reviewer exists for this
   repository. A plain `gh pr merge` answers `the base branch policy prohibits the merge` and the
   PR waits forever. Use `gh pr merge <n> --merge --admin` once the ci check is green; `--auto`
   only waits for an approval that never comes. `main` also has `lock_branch: true`.
3. **The Docker Hub API refuses a PAT as a bearer token.** `GET /v2/users/<name>/` with
   `Authorization: Bearer $DOCKERHUB_TOKEN` answers 401 with `A personal access token or
   organization access token cannot be used as a bearer`. `docker login` works. Test a token
   through `docker login`, not through that endpoint.
4. **`uv version --short` emits ANSI colour** when uv thinks it has a terminal
   (`\x1b[36m0.1.0\x1b[39m`), so a matching tag read as a mismatch. `publish.yml` reads the
   version with `sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml` for that reason.
5. **`insightface` pulls non-headless `opencv-python`.** Both wheels end up in the image
   (`opencv-python 4.11.0.86` and `opencv-python-headless 4.8.0.74`), and cv2 fails with
   `ImportError: libGL.so.1` unless `libgl1` is installed in the runtime stage.
6. **`--cap-add NET_RAW` does not give nmap a SYN scan.** As uid 1000 it prints `You requested a
   scan type which requires root privileges.` and `QUITTING!`, because nmap checks the user, not
   the capability. `--user root` is the way, and the CLI never asks for those scan types.
7. **Docker Desktop here stores images in containerd**
   (`driver-type: io.containerd.snapshotter.v1`), so `docker image inspect` prints empty
   `Architecture`, `Os`, `User` and `Entrypoint` for a pulled image. The image is fine:
   `docker image history` shows the build steps and the container behaves. Do not read those
   fields as a broken image.
8. **`.dockerignore` does not exclude itself.** The image carries `.dockerignore`, `.gitignore`
   and `.python-version`. Harmless, and worth knowing before trusting a listing of `/app`.
9. **The `SHODAN_IMAGE` default is the published image.** A change to the scanner needs
   `SHODAN_IMAGE=shodan-rtsp:dev docker compose build scanner`, or compose uses the released one
   and the change looks absent.
10. **`.claude/` is untracked in the working tree** and is not in `.gitignore`, so it shows up in
    every `git status`.

### What is not proved

- **`publish.yml` has run exactly once**, for `v0.1.0`. Its version check, its smoke test and the
  `uses: ./.github/workflows/ci.yml` call were exercised by that run and by nothing else.
- **Nothing was run on arm64.** The image is `linux/amd64` only, so an arm64 host runs it through
  emulation, which nobody measured here.
- **The face model download was never exercised from the image.** `scan faces` downloads
  `buffalo_l` (about 280 MB) into `$HOME/.insightface` on its first run; from a container that
  path is the `shodan_face_models` volume, and the published image was only used for `report`,
  `scan nmap` and the gate.
- **The image size is not bounded by anything.** 416 MiB compressed today, and no check fails if
  it doubles.
- **The compose path was proved with `--help` and with `pull`.** A full `docker compose run` of a
  scan against the compose Postgres was not run after the default flipped to the published tag.
- **The `-e DATABASE_HOST` run used `host.docker.internal`**, a Docker Desktop name. On Linux the
  same flag needs another address.
- **Nothing checks that a published tag matches a build.** The digest is recorded here by hand.

### Next steps

1. Publish the next release with the same two steps: bump the version in `pyproject.toml`, tag
   `v<version>`, push the tag. The version check refuses a tag that does not match.
2. Add a `linux/arm64` build to `publish.yml` if an arm host has to run it natively
   (`platforms: linux/amd64,linux/arm64` with `load: false` and a manifest push).
3. Run one full `docker compose run --rm scanner scan nmap ...` against the compose Postgres,
   the only path through the published default tag that was not exercised.
4. Decide whether `.claude/` enters `.gitignore`.
5. Everything still open in the section above stands: the 0.5 threshold placeholder, the
   `scan_run` status column, one CVE class proved, the Shodan path never live.

### What to watch

- **A red run on the `v*` tag.** The registry only ever sees an image whose tests passed and
  whose tag equals the version, so a failure there means the release did not happen. Re-run from
  the Actions tab.
- **Hub pull limits.** Anonymous pulls are 100 per 6 hours per IP and an authenticated free
  account is 200 per 6 hours, so a fleet of jobs pulling this image can hit the wall.
- **Image size.** Any new dependency that pulls a scientific stack adds hundreds of MiB.
- **The three tags drifting apart.** `0.1.0`, `0.1` and `latest` moved together for the first
  release; a hand-pushed tag is how they stop matching.
- **`main` against a direct push.** `enforce_admins: false` means an admin push is possible, so
  nothing but the habit of using a branch stops a commit that skips the review rule.


