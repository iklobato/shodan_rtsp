# Shodan RTSP Scanner: session log

Dated record of what each working session found and changed, with the raw output that
proved it. **An agent starting here reads the newest dated section first: it carries the
current state, the open work, the traps and what needs watching.** For the pipeline batch
the architecture, the file map and the command line are in
`specs/001-camera-monitoring-pipeline/plan.md` and
`specs/001-camera-monitoring-pipeline/contracts/cli.md`, the settled choices in
`docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` (D36), and the raw lab evidence of
each front in `docs/front-<n>-report.md`. The named person search is the batch on top of
them: `specs/002-person-search/` and `docs/decisions/2026-11-12-busca-pessoa-especifica.md`
(D47 to D67).

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

## 2026-11-12: the named person search, `search person`

Branch `002-person-search`, three commits, [PR #13](https://github.com/iklobato/shodan_rtsp/pull/13),
not merged yet. Built from six grill rounds recorded as D47 to D67 in
`docs/decisions/2026-11-12-busca-pessoa-especifica.md`. Spec, plan, research R1 to R9, data
model, contract and quickstart live in `specs/002-person-search/`.

### What was built

| Piece | What it is |
|-------|------------|
| `models/target.py` | `Target` (unique trimmed name, timestamps, `InvalidEntity` on an empty name), `TargetPhoto` (path unique, 512-value embedding, `array_length` check on Postgres only), `TargetHit` (one row per target and face, score range check, indexes on `(target_id, score)` and `face_id`) |
| `migrations/versions/0003_person_search.py` | Creates the three tables with named constraints and indexes; downgrade drops hits, then photos, then targets, and touches no other table |
| `models/managers.py` | `TargetRepository` (`resolve`, `add_photo`, `photos_of`, `all`, `remove` in one transaction), `TargetHitRepository` (`record` raises the score of an existing hit and never lowers it), `TargetReader` (`faces(filters)` over face, frame, person and camera; `matches_of(person_id)` best score per target per person), `PersonRepository.name_if_empty` and `release_label` |
| `scanners/target_search.py` | `ReferencePhotoReader` (refuses zero and more than one face, refuses an unreadable file), `TargetRegistration` (reads every photo before writing anything, then copies the file and adds the row), `TargetComparison.best_of`, `TargetSearch` (filters, compares, writes hits, names the person), `TargetRemoval` (rows, then files, then labels) |
| `scanners/frames.py` | `FrameStore.write_reference` copies a photo under `targets/<target_id>/`, `remove_reference` tolerates a file already gone |
| `scanners/reports.py` | `TargetRankingReport` (one line per appearance, best score first, target name on each line), `TargetThreshold` (prints the value with `PLACEHOLDER` while it equals the shipped default), `SearchPersonCommand` (register, then live scan, then search and print), `ForgetTargetCommand`, and the target line of `PersonReport` |
| `main.py` | `search` becomes a group with `appearance` and `person`; `TargetFactory` and `SearchParser` build both; `UsageError` and `_USAGE_EXIT = 2` carry a wrong command line that argparse cannot catch |
| `scanners/config.py`, `config.yaml.example` | `person_search.match_threshold`, default `0.5`, commented as a placeholder |

Commands, as the contract now states them:

```text
main.py search appearance [--person-id N] [--camera-id N] [--since TS] [--until TS]
main.py search person --image PATH [--image PATH ...] --name NAME [--camera-id N] [--since TS] [--until TS] [--live]
main.py search person --target-id N [--live] [filters]
main.py search person --forget N
```

### The feature, as measured on the lab

Gate at the tip of the branch:

```console
$ uv run ruff check .
All checks passed!
$ uv run pytest -q
180 passed in 12.09s
```

Migration round trip on the lab Postgres (host port 5440, database `cameras`):

```console
INFO  [alembic.runtime.migration] Running upgrade 0002 -> 0003, add target, target_photo and target_hit for the named person search
INFO  [alembic.runtime.migration] Running downgrade 0003 -> 0002, add target, target_photo and target_hit for the named person search
0                      # tables present after the downgrade
target
target_hit
target_photo          # after the second upgrade
```

Registration and search, photo taken from a stored frame:

```text
score 0.989  target maria  person 1  camera 127.0.0.1:8554  2026-11-11T15:57:31Z  frame 232/20261111T155731Z-rtsp.jpg
```

`select count(*) from target_hit` answered `22`, `22`, `22` on three consecutive runs, so the
second run neither duplicated nor dropped hits.

Photo with no face:

```text
exit=1     # and select id,name from target still listed only the earlier target
```

The label rule: person 1 had an empty label and gained `maria`; person 2 already carried
`joao` and kept it. `report faces` prints the match under the person:

```text
person 1 (maria)  faces 22  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T16:42:22Z
  camera 127.0.0.1:8000  frames 5  frame cve
  camera 127.0.0.1:8554  frames 17  frame rtsp
  target maria  score 1.000
```

The reach gate, with a copy of the config whose `allowed_cidrs` held only `192.168.1.0/24`:

```text
ERROR 7 of 7 addresses are outside the declared ranges ['192.168.1.0/24']: 201.182.98.13, 170.81.118.23, 201.182.98.4, 179.209.11.209, 187.45.113.192, 127.0.0.1, 127.0.0.1; declare them in targets.allowed_cidrs, or narrow the run with --camera-id
exit=1
```

The live pass, narrowed to camera 232:

```text
INFO Starting the face scan
INFO Executors: finished the face scan with 6 face(s)
34|faces|127.0.0.1|2026-11-12 11:06:48.526974+00      # scan_run
```

Removal:

```text
removed target 3 (maria): 1 photos, 28 hits
target=0  target_photo=0  target_hit=0  face=30       # face count unchanged
```

Threshold measurement is blocked, the pair set does not exist:

```text
ERROR the pair set lab/faces is not a directory
exit=1
```

### Two defects the lab run found, and the fix

1. **`report faces` printed no target line.** `TaskFactory._report_deps` built `ReportDeps`
   without `targets`, so the dictionary stayed empty and `PersonReport` had nothing to print.
   The builder now fills it from `TargetReader().matches_of(...)` (`main.py:141`).
2. **The name the run had just written did not show on that run.** `StoredFace.label` was read
   from the database before `name_if_empty` wrote the label, so the first search printed
   `person 1` and only the second printed `person 1 (maria)`. `TargetSearch._kept` now rebuilds
   the face with `replace(face, label=name)` when the write happened
   (`scanners/target_search.py:185`), and `tests/test_target_label.py` pins it.

### Traps a future agent will hit

1. **`search` is a group now.** `main.py search --since 2026-11-11T00:00:00Z` exits 2, because
   the option belongs to the subcommand. It is `search appearance --since ...`. Every old
   command line in the previous section keeps working only after that rename.
2. **Target ids are not reused.** The sequence keeps counting after a removal: after
   `--forget 1` and `--forget 2` the next registration got id 3, so a runbook line with
   `--target-id 1` answers `ERROR no target with id 1`. Read the id from the registration or
   from `select id, name from target`.
3. **`--forget` with any search option exits 2**, through `UsageError`, not through argparse.
   The message is `--forget removes one target and takes no search options`.
4. **The multi-face refusal is by detector count, not by database count.** A frame the
   database lists three faces for passed registration as one target, because insightface found
   one face in the whole image. Only unit tests cover the more-than-one branch.
5. **Removal leaves the empty directory.** `logs/frames/targets/<id>/` stays after the files
   go. Harmless, and it makes an `ls` look like the removal half ran.
6. **The ranking prints one line per face row.** The lab database holds the same frame twice
   from two scan runs, so the same appearance prints twice. Deduplication is a data problem,
   not a search problem.
7. **The threshold key is `person_search.match_threshold`.** Decision D51 wrote
   `target.match_threshold`; the config section, the example and the contract all say
   `person_search`. Follow the code.
8. **The task list named a file that does not exist.** T028 asked for `scanners/target_task.py`;
   the command lives in `scanners/reports.py` as `SearchPersonCommand`, and `tasks.md` was
   updated to say so.
9. **`config.yaml` holds a live Shodan key and is gitignored.** Never stage it. `.claude/`
   is still untracked and still not in `.gitignore`.

### What is not proved

- **The threshold has never been measured.** `measure threshold --pairs lab/faces` failed
  because the pair set is not there, so `0.5` ships as a declared placeholder (D60) and every
  line about it says `PLACEHOLDER`.
- **The more-than-one-face refusal was never exercised on a real photo**, for the reason in
  trap 4.
- **Scale.** The comparison is a linear scan over every stored face, once per target photo,
  marked with a `ponytail:` comment naming pgvector as the upgrade path. The lab holds 30
  faces; nothing here proves behaviour at thousands.
- **Image formats.** Only the jpg the lab stores was read. Another format depends on what
  opencv reads.
- **A second real person.** The lab holds two person rows, and both targets registered during
  this session matched person 1 only, so nothing here separates one target from an unrelated
  face in production data.

### Next steps

1. Merge [PR #13](https://github.com/iklobato/shodan_rtsp/pull/13). `main` requires one
   approving review and no reviewer exists, so it is `gh pr merge 13 --merge --admin` once the
   ci check is green (see the trap in the previous section).
2. Build a labelled pair set (one folder per identity, two or more photos each), run
   `measure threshold`, and write the measured value into `person_search.match_threshold` so
   the output stops saying `PLACEHOLDER`.
3. Register a target from a real group photo to prove the more-than-one-face refusal through
   the command line, not only through the test.
4. Decide what to do with the duplicate face rows the lab database carries, since they double
   every ranking line.
5. Add `.claude/` to `.gitignore`, or drop the directory from the working tree.

### What to watch

- **Hit table growth.** One row per target and face, so a target matched by many faces grows
  with the face table. `select count(*), target_id from target_hit group by 2` is the check.
- **A silent threshold change.** Anyone who edits `person_search.match_threshold` to the
  shipped `0.5` by accident turns the `PLACEHOLDER` warning back on, and a value near 1.0
  hides every hit. Both look like an empty search.
- **The target ids drifting.** They never reset, so scripts and runbooks that hardcode an id
  rot on the first removal.
- **The `search` rename reaching old runbooks.** Any document still printing `main.py search
  --since` now exits 2 instead of answering.





## 2026-11-12 (later): the command surface, cut in six grill rounds

Six grill rounds on the same day turned the developer experience of this repository into
D68 to D83 (`docs/decisions/2026-11-12-simplificacao-cli.md`). Three things changed and
nothing else: the command surface, the setup text, and the shape of `main.py`. No pipeline
behaviour moved, no table changed, no migration was added. The work sits on branch
`002-person-search`, on top of the named person search, because
[PR #13](https://github.com/iklobato/shodan_rtsp/pull/13) is still open, and D83 ships the
whole batch as one pull request.

### What the surface was, and what it is now

Measured before the edits and after them:

| Fact | Before | After |
|------|--------|-------|
| Groups | 4: `scan`, `report`, `search`, `measure` | 6: `find`, `scan`, `report`, `search`, `target`, `measure` |
| Leaf commands | 9 | 12 |
| Discovery commands | `scan nmap`, `scan shodan` | `find nmap`, `find shodan` |
| Credential and CVE commands | `scan check`, `scan cve` | `scan credentials`, `scan vulns` |
| `search person` flags | 8 (`--image`, `--name`, `--target-id`, `--forget`, `--live`, `--camera-id`, `--since`, `--until`) | 7, `--forget` gone (D76) |
| Seeing the registered targets | no command at all | `target list` |
| `--config` and `-v` | read on the root only, before the group | read anywhere on the line (D71) |
| `main.py` | 578 lines, 4 wiring and argparse classes | 732 lines, 17 classes, 7 of them parsers |

The tree, as the root help prints it:

```console
$ uv run python main.py --help
usage: main.py [-h] [--config CONFIG] [-v]
               {find,scan,report,search,target,measure} ...

Camera Scanner

positional arguments:
  {find,scan,report,search,target,measure}
    find                Discovery that stores cameras
    scan                Scans of the cameras already stored
    report              Read-only reports
    search              Searches that only read
    target              The named people this build looks for
    measure             Measurements that write nothing

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to the configuration file
  -v, --verbose         Verbose mode
```

### Where the change lives

| File | What changed |
|------|--------------|
| `main.py` | The tree of D72, one thin parser class per group (`FindParser`, `ScanParser`, `ReportParser`, `SearchParser`, `TargetParser`, `MeasureParser`) over a shared `CommandParser`; `CommonOptions.parent()` builds the parent parser that carries `--config` and `-v` with `default=argparse.SUPPRESS`, so a subparser no longer overwrites the root default; `CommandLine._commands()` maps the 12 command keys and `_REFUSALS` also answers an unknown target; `RegistrationBuilder`, `ReportDepsBuilder.of(filters)`, `ScanFactory`, `ReportFactory`, `SearchFactory` and `TargetFactory` build the commands |
| `models/managers.py` | `TargetListing` (frozen, the four columns of D80) and `TargetListReader` (`rows()`, one grouped `count(*)` query per table through `_grouped_in`) |
| `scanners/target_search.py` | `TargetSelection.id_of`: an exact name wins, a digits only argument is the id when no target carries that name |
| `scanners/reports.py` | `ForgetTargetCommand` deleted; `AddTargetCommand`, `RemoveTargetCommand` and `TargetListingReport` added, each carrying `run = render` so the command line calls the one entry point it knows |
| `tests/test_cli_surface.py` (new) | 16 accepted command lines, the 5 old ones that must be refused, the dispatch set, `--config` after the command and `-v` before the group both read, the root default surviving |
| `tests/test_target_listing.py` (new) | Two targets with different counts, so a count that leaks into the other line fails the test |
| `tests/test_target_selection.py` (new) | A target named `1` beats the id it looks like, an unknown number and an unknown word both refused |
| `tests/test_cli_exit.py` | `--forget` on the person search is refused, and a `--config` after the command is read |
| `README.md` | Command names, the regenerated help block, the mermaid graph, the `target` rows, and one copy-paste setup block (D81) |
| `specs/001-camera-monitoring-pipeline/contracts/cli.md`, `specs/002-person-search/contracts/cli.md`, `specs/002-person-search/quickstart.md` | The renamed headers, the `target` group, and the note that `--forget` stops at argparse now |
| `docs/configuration.md`, `docs/docker.md`, `docs/cve-matching.md`, `docs/shodan-by-location.md`, `specs/001-camera-monitoring-pipeline/quickstart.md` | The command names in these runbooks, which the rename had left printing commands that exit 2 |

The dated records (`docs/front-*-report.md`, the dated sections of this file,
`specs/001/.../{plan,tasks,research}.md`, `specs/002/.../{plan,tasks,data-model}.md` and the
decision files) keep the names of their day on purpose.

### The lab run, raw

Postgres container `shodan_pg` up and healthy, ids from the previous session already burnt
(the new target got id 5, not 1). The whole round trip, in one run on 2026-11-12:

```console
$ uv run python main.py target list
no target registered
$ uv run python main.py target add --name maria --image logs/frames/231/20261111T154504Z-cve.jpg
target 5 (maria): 1 reference photos
$ uv run python main.py target list
target 5  maria  1 reference photos  0 hits
$ uv run python main.py search person --name maria
score 1.000  target maria  person 1 (maria)  camera 127.0.0.1:8000  2026-11-11T15:45:04Z  frame 231/20261111T154504Z-cve.jpg
score 1.000  target maria  person 1  camera 127.0.0.1:8000  2026-11-11T15:45:04Z  frame 231/20261111T154504Z-cve.jpg
score 1.000  target maria  person 1  camera 127.0.0.1:8000  2026-11-11T16:42:22Z  frame 231/20261111T164222Z-cve.jpg
score 0.995  target maria  person 1  camera 127.0.0.1:8000  2026-11-11T15:45:14Z  frame 231/20261111T154514Z-cve.jpg
...
score 0.988  target maria  person 1  camera 127.0.0.1:8554  2026-11-11T15:57:46Z  frame 232/20261111T155746Z-rtsp.jpg
$ uv run python main.py target add --name maria --image logs/frames/231/20261111T145832Z-cve.jpg
2026-11-12 08:41:25,995 ERROR no face found in the reference photo: logs/frames/231/20261111T145832Z-cve.jpg
$ uv run python main.py target list
target 5  maria  1 reference photos  28 hits
$ uv run python main.py target remove maria
removed target 5 (maria): 1 photos, 28 hits
$ uv run python main.py target list
no target registered
```

Three things in that block are worth keeping:

- The first line of the search carries `person 1 (maria)` and the 27 lines after it carry
  `person 1` alone, in one single run. The label row was empty before this run, so the first
  line is reading the name the run itself wrote. Why the lines after it do not is not
  investigated here, and the person row was left labelled `maria` until the removal cleared
  it.
- A reference photo with no face is refused at `target add` with exit 1 and the target is
  left holding the one photo it had, so a bad photo cannot damage a good target.
- The 28 hits are the duplicate face rows the lab database carries, counted once per target
  photo: the same four timestamps repeat inside the ranking. That is the known duplication of
  the previous section, not a new one.

The argument positions of D71, and the two refusals, on the same lab:

```console
$ uv run python main.py -v target list
2026-11-12 08:39:06,243 INFO Verbose mode enabled
no target registered
$ uv run python main.py target list -v
2026-11-12 08:39:06,243 INFO Verbose mode enabled
no target registered
$ uv run python main.py target list --config config.yaml
no target registered
$ uv run python main.py target remove maria
2026-11-12 08:39:09,137 ERROR no target named or numbered maria
$ uv run python main.py scan check
usage: main.py scan [-h] [--config CONFIG] [-v] {credentials,vulns,faces} ...
main.py scan: error: argument command: invalid choice: 'check' (choose from 'credentials', 'vulns', 'faces')
$ uv run python main.py search person --forget 1
main.py: error: unrecognized arguments: --forget 1
```

Both refusals exit 2, which is the wrong command line and not a failure, as the contracts
state. Twelve leaf commands were checked one by one with `--help` and every one exits 0.

Gate at the tip of the branch:

```console
$ uv run ruff check .
All checks passed!
$ uv run pytest -q
199 passed in 11.86s
```

### Traps found while doing it

1. **`parents=` on a subparser overwrites the root default unless the default is
   `SUPPRESS`.** Adding the parent parser the obvious way made `main.py target list` read a
   `config` of `None` and a `verbose` of `False`, because the subparser wrote its own values
   into the shared namespace after the root had parsed. `default=argparse.SUPPRESS` on every
   parent option, with the real defaults left on the root parser alone, is what keeps the
   root value when the option is not typed. Checked on Python 3.11.
2. **`target remove` leaves the empty directory behind.** The reference file goes, the row
   goes, and `logs/frames/targets/<id>/` stays as an empty directory, so
   `logs/frames/targets/` survives the last removal. Harmless, and visible in the working
   tree after every run.
3. **A report that only defines `render` crashes the command line.** `TargetListingReport`
   was written without `run = render` and the first real `target list` died with
   `AttributeError: 'TargetListingReport' object has no attribute 'run'`. The class of bug is
   now caught by the test calling `.run()`, which is how the CLI calls it.
4. **A test that seeds two photo rows needs a path unique across the whole table.**
   `target_photo.path` is unique, so the second target seeded with the same path raised
   `IntegrityError: UNIQUE constraint failed: target_photo.path`. The seeding helper builds
   `targets/<id>/<name>-<index>.jpg`.
5. **The old names fail late, not early.** `scan check` and `search person --forget 1` are
   refused by argparse with exit 2 and a message that names the wrong argument, so a shell
   history entry fails fast with a clear line rather than doing something surprising. That is
   the intended behaviour of D69 with no aliases, and it is the reason the runbooks in
   `docs/` had to be renamed in the same change.

### What is not proved

- **The five runbook files were renamed by string, not by running them.** `docs/docker.md`
  and `docs/shodan-by-location.md` are `docker run` examples and Shodan queries; their new
  command names were checked with `--help` only. No query was sent and no container was
  rebuilt.
- **Nothing about the interactive setup.** The README block of D81 was written and read, not
  executed from a clean checkout.
- **`target list` at scale.** Two queries, one per table, but nothing proves it on thousands
  of targets.
- **The digit only target name.** `target remove 1` reaches the id when no target is named
  `1`, which is what D79 chose; a target actually named `1` is untested on the lab, only in
  `tests/test_target_selection.py`.

### Next steps

1. Merge [PR #13](https://github.com/iklobato/shodan_rtsp/pull/13) and
   [PR #14](https://github.com/iklobato/shodan_rtsp/pull/14), which carries this change and is
   based on the branch of #13. `main` requires one approving review and no reviewer exists in
   the history, so both are `gh pr merge <n> --merge --admin` once the ci check is green.
2. Close the empty `logs/frames/targets/<id>/` directory in `FrameStore.remove_reference`, or
   state that it is deliberate.
3. Add `.claude/` to `.gitignore`, or drop the directory from the working tree.

## 2026-11-12 (later still): the CVE batch, widened by what NVD actually says

The request was to add at least 100 CVEs that allow a frame to be read. This
section records the measurement that set the real number, the reads that were
added, and the ones that were left out on purpose.

### How the number was measured

65 NVD 2.0 `keywordSearch` queries, pulled into three sweeps in `/tmp` (camera
brands, snapshot and stream phrases, CGI endpoint phrases), gave 1067 unique
CVEs. Two filters were then applied, both on the English description:

1. the text says the access needs no login, and
2. the text names a picture or a stream, and
3. the text or the CPE names a camera, DVR, NVR, webcam, encoder or ONVIF.

```console
$ python3 /tmp/nvd_camera_frame.py
unique CVEs pulled: 1067
camera + open access + media: 41
```

Of those 41, 11 are what this batch claims: 10 read a picture over HTTP and one
reads an ONVIF description. Another 9 need an RTSP session, 1 named a path that
was not taken (CVE-2026-50245, `/ONVIF`), and the remaining 20 are another
mechanism entirely: Bluetooth, a Wiegand bus, a physical presence, a password
reset, an RCE. The batch speaks HTTP only, so 11 was the honest ceiling for this
change, not 100.

```console
$ python3 /tmp/nvd_batch_overlap.py
of 41, in batch: 11
of 41, batch read a picture over HTTP: 10
of 41, batch read an ONVIF description: 1
named path, not taken: ['CVE-2026-50245']
need an RTSP session: 9
another mechanism: 20
```

### What was added

`scanners/cve/snapshot_read.py`, three classes over one shared base:

| Class | Paths | CVEs |
|-------|-------|------|
| `StaticSnapshotRead` | `/snapshot`, `/snapshot.jpg`, `/jpg/image.jpg`, `/video.mjpg` | CVE-2021-31793, CVE-2021-4469, CVE-2021-47796, CVE-2018-18428, CVE-2018-17559 |
| `StreamPathRead` | `/live.mjpeg`, `/snapshot.jpg`, `/FC/PT/D` | CVE-2018-25141, CVE-2017-20213 |
| `CgiImageRead` | `/cgi-bin/get_jpeg?channel=1`, `/cgi-bin/animate.cgi?channel=1` | CVE-2019-25236, CVE-2019-25240, CVE-2017-17101 |

`CVE_BATCH` went from 4 to 7 classes, all of the picture family first, then the
two file reads, then the ONVIF description.

`brands.yaml` gained the model pairs those CVEs hang on, each one the product an
NVD record carried: `apexis:apm-h803-mpc`, `nightowlsp:wdb-20`,
`abus:tvip_10000`, `flir:flir_ax8`, `tp-link:tl-sc3130` (hyphen, not the
`tplink` the brand entry uses), plus a generic `apexis`, `nightowl`, `abus` and
`flir` entry for the other models of the same brand.

```console
$ uv run python -c "... Identifier(BrandBook.load('brands.yaml')) ..."
APM-H803-MPC camera -> apexis | apm-h803-mpc
NightOwl WDB-20 doorbell -> nightowlsp | wdb-20
FLIR AX8 thermal camera -> flir | flir_ax8
ABUS TVIP 10000 -> abus | tvip_10000
TL-SC3130 -> tp-link | tl-sc3130
Apexis camera -> apexis | ip_camera
```

### Traps

1. **A CVE without a path cannot be covered.** CVE-2024-42531 (Ezviz), the FLIR
   and Beward RTSP records and the Xiongmai ONVIF record say the stream is
   open, but the mechanism is an RTSP session, and the batch has no RTSP class.
   Adding their ids to an HTTP class would claim a proof the class does not
   produce.
2. **A class is one attempt for every CVE it covers.** `_try_classes` calls the
   class once and writes the same outcome onto every finding it opened, so a
   family of paths and a family of CVEs have to agree. That is why the paths
   are grouped by family and not by brand.
3. **Denver answers on a second port.** CVE-2021-4469 and CVE-2021-47796 name
   port 8001, which only reaches the class when `web_ports` lists it.
4. **`tp-link` is not `tplink`.** The CPE vendor field is hyphenated, so the
   brand entry could never reach the model CVEs; a separate model entry is the
   only way in.

### What is not proved

- **No device was read for any of the 11 CVEs.** The classes were exercised
  against the loopback stub server, which proves the request shape and the
  decode, not that a real Apexis or FLIR answers these paths.
- **The 41 CVE inventory is a keyword search, not an enumeration.** A CVE whose
  description does not use the words the query used is not in the 1067, so 41
  is a floor, not a total. No NVD CPE dictionary walk was run for the whole
  camera space.
- **The `/ONVIF` path of CVE-2026-50245 (Brickcom) was not added.** It names no
  readable path and the record carries no CPE, so nothing would match it.

### Next steps

1. An RTSP class would widen the batch from 11 to 20 of the measured 41, because
   9 of the remaining ones are unauthenticated RTSP sessions. It needs the
   capture code `scanners/rtsp_probe.py` already has. Only 2 of those 9 records
   carry a CPE (`rubetek:rv-3406_firmware`, `flir:flir_ax8_firmware`), so the
   feed would reach 2 of the 9.
2. A CPE dictionary walk over the camera vendors would replace the keyword
   floor with a total, at one request per product.
