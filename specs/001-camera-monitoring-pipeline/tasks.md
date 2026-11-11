---
description: "Task list for the camera monitoring pipeline feature"
---

# Tasks: Camera Monitoring Pipeline

**Input**: `specs/001-camera-monitoring-pipeline/`
**Prerequisites**: plan.md, spec.md, research.md (R1 to R11), data-model.md, contracts/cli.md, contracts/brand-signatures.md, quickstart.md

**Tests**: included, because the specification requires them (FR-033) and the constitution
makes a test that can fail a non-negotiable. Tests are written first and must fail before
the implementation lands.

**Organization**: phases follow the execution order of decision D12, which is not the
priority order of the spec. The spec priorities say what is worth most; D12 says what has
to land first so that later fronts do not fight over the same files. The cleanup of US5
therefore runs before identification, because it touches `scanners/task.py`,
`scanners/rtsp_probe.py` and `scanners/config.py`, which US2, US3 and US4 also touch.

**Delivery**: one branch and one reviewed PR per front (D32). Each phase below is one front.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel: different files, no dependency on an incomplete task
- **[Story]**: US1 to US5, mapped to the user stories of spec.md
- Every task names the exact file it touches

## Path Conventions

Single project at the repository root: `main.py`, `models/`, `scanners/`, `tests/`,
`alembic/`, and the data files `brands.yaml` and `cpe_map.yaml`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: the dependency, the config sections and the database target, before any front starts.

- [ ] T001 Add the `alembic` dependency with `uv add alembic` in `pyproject.toml` and `uv.lock` (authorized by D4)
- [ ] T002 [P] Add the `frames` and `brands` sections to the config models and remove the `proxy` section in `scanners/config.py`
- [ ] T003 [P] Update `config.yaml.example`: drop the proxy section, add `frames.root_path` and `brands.signature_path`, set the database host to `localhost:5440`
- [ ] T004 [P] Move the postgres host port from 5433 to 5440 in `docker-compose.yml` (D40)
- [ ] T005 [operator] Update the local `config.yaml` by hand: database host `localhost:5440`, proxy section removed. The file is git-ignored and holds credentials, so no tool and no agent edits it

**Checkpoint**: `docker compose up -d postgres` starts, and `uv run python -c "import alembic"` succeeds.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the lab rig. Every front is done only with a real run and raw output (D24), so the
target has to exist before the fronts that are verified against it.

- [ ] T006 Start `mediamtx` and publish a looped stream: `ffmpeg -re -stream_loop -1 -i lab/face.mp4 -c copy -f rtsp rtsp://127.0.0.1:8554/cam1`. Blocks US1, US4
- [ ] T007 [P] Supply the face pair set for the threshold measurement: several images of one person and several of others, with consenting people or a public dataset whose licence allows it. Blocks US4
- [ ] T008 Install FEMU or FirmAE and emulate an old Hikvision build. Blocks US3 only, so it can run in parallel with US1 and US5
- [ ] T009 Write the rig document under `docs/` with the raw output of `GET /onvif-http/snapshot?auth=YWRtaW46MTEK` against the emulated device, or the recorded reason it could not be made to answer (D42). If the fallback mock is used, the document must say so in the first line

**Checkpoint**: the RTSP stream answers, the face pairs are on disk, and the rig document states the state of the emulation.

---

## Phase 3: User Story 1 - A database that remembers history (Priority: P1) 🎯 MVP

**Goal**: the seven entities of data-model.md, created by the first Alembic revision, plus the
subcommand skeleton with `scan nmap` and `scan shodan`.

**Independent Test**: on an empty database, `uv run alembic upgrade head` twice, then one scan of one lab camera on one port, then read the camera, the scan and the observation rows back.

### Tests for User Story 1

- [ ] T010 [P] [US1] Test that the migration from zero creates every table, that a second run changes nothing, and that `alembic downgrade base` returns the database to zero tables, in `tests/test_migrations.py`
- [ ] T011 [P] [US1] Test the camera validation and the status enum, including the failure path for a bad port and an unparsable address, in `tests/test_camera_model.py`
- [ ] T012 [P] [US1] Test that one scan writes exactly one observation per camera per port and that a repeated scan does not duplicate the camera, in `tests/test_observation.py`
- [ ] T013 [P] [US1] Test that a scan run records the target set it reached, in `tests/test_scan_run.py`

### Implementation for User Story 1

- [ ] T014 [US1] Create the declarative base with the constraint naming convention of R2 in `models/base.py`
- [ ] T015 [US1] Create the `camera`, `scan_run` and `camera_observation` entities in `models/camera.py`, `models/scan_run.py` and `models/observation.py`
- [ ] T016 [US1] Create the `cve_finding`, `face_frame`, `face` and `person` entities in `models/finding.py`, `models/frame.py`, `models/face.py` and `models/person.py`
- [ ] T017 [US1] Wire the existing engine and session handling to the new base in `models/database.py`
- [ ] T018 [US1] Initialise Alembic: `alembic init alembic`, then wire `target_metadata` and `transaction_per_migration=True` in `alembic/env.py` and `alembic.ini`
- [ ] T019 [US1] Write the first revision creating the whole schema in `alembic/versions/0001_initial_schema.py`
- [ ] T020 [US1] Replace the repositories with one per entity in `models/managers.py`
- [ ] T021 [US1] Restructure `main.py` into subcommands with a dispatch table, registering `scan nmap` and `scan shodan` (D34, D38, R7)
- [ ] T022 [US1] Record the target set on the scan run in `scanners/task.py`
- [ ] T078 [US1] Configure the service scan port list of D15 (554, 80, 443, 8000, 8080, 8554, 34567) as `nmap.ports` in `scanners/config.py` and `config.yaml.example`, and use it in the nmap task in `scanners/task.py` (FR-011)
- [ ] T023 [US1] Validate the Shodan query against the declared CIDR list before the API call in `scanners/task.py` (D18)
- [ ] T024 [US1] Lab run: `alembic upgrade head` twice and `scan nmap 127.0.0.1/32` against the lab, with the raw output pasted into the front report

**Checkpoint**: the schema exists from zero, and one scan produces the rows of acceptance scenario 2.

---

## Phase 4: User Story 5 - A code base the other fronts can be trusted on (Priority: P5)

**Goal**: remove the retired proxy path, the dead code, the credential log line and the stale
docs, so the fronts that follow touch a smaller tree.

**Independent Test**: `uv run pytest -q` and `uv run ruff check .` before and after, with the retired tests gone and the direct path still covered.

### Tests for User Story 5

- [ ] T025 [P] [US5] Test that no credential value reaches any log line, at any level, in `tests/test_logging.py`
- [ ] T026 [P] [US5] Test that the direct RTSP transport still works after the proxy removal, in `tests/test_rtsp_direct.py`

### Implementation for User Story 5

- [ ] T027 [US5] Delete `scanners/proxy.py` and `scanners/proxy_tunnel.py` (D11)
- [ ] T028 [US5] Remove the proxy branch of the nmap check and the proxy config wiring in `scanners/task.py` and `scanners/config.py`
- [ ] T029 [US5] Delete the proxy tests and remove `curl_cffi` from `pyproject.toml` and `uv.lock`
- [ ] T030 [US5] Remove the credential log line at `scanners/rtsp_probe.py:146`
- [ ] T031 [US5] Delete the unused `_sanitize_city` helper that mutates its input in `models/managers.py`
- [ ] T032 [US5] Remove the unreachable low-priority branch and the dead `_LOW_PRIORITY_COUNT` class state in `scanners/task.py`
- [ ] T033 [US5] Delete `_probe_names.py`, `docs/proxy-investigation.md`, `proxylist.txt` and `.serena/` (D23)
- [ ] T034 [US5] Trim `docs/KNOWLEDGE.md` to a dated session log, moving current state to the README and to `docs/decisions/` (D36)
- [ ] T035 [US5] Lab run: `uv run pytest -q` and `uv run ruff check .` before and after, with both outputs pasted into the front report

**Checkpoint**: the suite passes with the retired tests gone, and no credential appears in a log.

---

## Phase 5: User Story 2 - Identify the camera make and model (Priority: P2)

**Goal**: keep the raw banner as evidence, drive brand detection and the brand credential set
from `brands.yaml`, and attach the vulnerable version range from the CVE map.

**Independent Test**: a stored banner of a known camera yields vendor, product and version with its raw evidence kept; a device matching no signature is stored as unknown with its banner kept; a brand added only to `brands.yaml` is detected with no code change.

### Tests for User Story 2

- [ ] T036 [P] [US2] Test brand detection from a banner through `brands.yaml`, including a brand added only to the file, in `tests/test_brand_detection.py`
- [ ] T037 [P] [US2] Test that an unmatched device is stored as unknown with its raw banner kept, in `tests/test_brand_unknown.py`
- [ ] T038 [P] [US2] Test that a product in the CVE map attaches its version range to the camera, in `tests/test_version_range.py`
- [ ] T039 [P] [US2] Test that a malformed `brands.yaml` fails at load with the offending line named, in `tests/test_brands_file.py`

### Implementation for User Story 2

- [ ] T040 [US2] Write `brands.yaml` with the brand entries of the data contract, starting with the brands the current code already knows
- [ ] T041 [US2] Rewrite `scanners/brand_probe.py` to load `brands.yaml`, dropping the hardcoded pattern table and the duplicated `_generic_nginx`
- [ ] T042 [US2] Store the raw banner fields on the camera instead of discarding them at `scanners/task.py:42`
- [ ] T043 [US2] Write the interpreted vendor, product and version to the camera in `scanners/task.py`
- [ ] T044 [US2] Try the brand credential set before the generic wordlists in the check task (D22)
- [ ] T045 [US2] Register `scan check` in `main.py`
- [ ] T046 [US2] Lab run: identify the lab camera and a device that matches no signature, with both raw outputs pasted into the front report

**Checkpoint**: acceptance scenarios 1 to 4 of US2 hold against the lab.

---

## Phase 6: User Story 3 - Obtain a frame through a known CVE, read only (Priority: P3)

**Goal**: three CVE classes, one module each, tried in order until one yields a frame, with the
outcome and the reason recorded either way.

**Independent Test**: against the emulated firmware the bypass returns a JPEG with the device state unchanged; against a device that does not answer, a recorded reason and no crash.

### Tests for User Story 3

- [ ] T047 [P] [US3] Test the finding invariants: a frame is recorded exactly when one was obtained, and a candidate without a frame always carries a reason, in `tests/test_cve_finding.py`
- [ ] T048 [P] [US3] Test that a class yielding no frame falls through to the next class, in `tests/test_cve_class_order.py`
- [ ] T049 [P] [US3] Test the read-only property: a fake transport records every request and the test asserts GET-only, no body, and at most one frame, in `tests/test_cve_read_only.py`
- [ ] T050 [P] [US3] Test that a timeout on one step is recorded and does not hang the run, in `tests/test_cve_timeout.py`
- [ ] T079 [P] [US3] Test that a successful ONVIF read records the model and the firmware on the camera, in `tests/test_onvif_info.py`

### Implementation for User Story 3

- [ ] T051 [US3] Define the class interface, the attempt result and the outcome enum in `scanners/cve/base.py`
- [ ] T052 [P] [US3] Implement the authentication bypass module for CVE-2017-7921 in `scanners/cve/auth_bypass.py`
- [ ] T053 [P] [US3] Implement the unauthenticated read module for CVE-2025-34022 and CVE-2016-15055 in `scanners/cve/unauth_read.py`
- [ ] T054 [P] [US3] Implement the unauthenticated ONVIF module in `scanners/cve/unauth_onvif.py`, returning the model and the firmware alongside the frame (FR-019)
- [ ] T055 [US3] Implement the on-disk frame layout of R8 in `scanners/frames.py`
- [ ] T056 [US3] Make the CVE task read observations from the database, record findings, and write the model and the firmware of an ONVIF success onto the camera in `scanners/vuln_task.py` (D30, FR-019)
- [ ] T057 [US3] Set every network step of an attempt to time out rather than hang in `scanners/cve/`
- [ ] T058 [US3] Register `scan cve` in `main.py`, exiting 0 when the run completed without a frame
- [ ] T059 [US3] Lab run: capture the device state, run `scan cve`, capture the device state again, and paste both plus the raw response into the front report

**Checkpoint**: SC-004 holds: a frame is obtained and the device state before and after is identical.

---

## Phase 7: User Story 4 - Faces grouped into people, and the monitoring answer (Priority: P4)

**Goal**: fix the metric to cosine over the 512-d normed embedding, cluster faces into people
with the merge rule, and answer who appeared where and when.

**Independent Test**: a face seen twice is one person; a face matching two people merges them; `search` prints one line per appearance.

### Tests for User Story 4

- [ ] T060 [P] [US4] Test that matching uses cosine similarity over the normalized vector and rejects the Euclidean comparison, in `tests/test_face_metric.py`
- [ ] T061 [P] [US4] Test that a new face creates a person and a repeat does not, in `tests/test_person_cluster.py`
- [ ] T062 [P] [US4] Test the merge: a face matching two people leaves one person and re-points every face, in `tests/test_person_merge.py`
- [ ] T063 [P] [US4] Test the output shape of `report faces` and `search`, in `tests/test_report_output.py`
- [ ] T064 [P] [US4] Test that a person with no label prints as an id and never as a name, in `tests/test_person_anonymous.py`

### Implementation for User Story 4

- [ ] T065 [US4] Fix the dimension and the metric in `scanners/face_recognizer.py`: 512-d, `normed_embedding`, cosine similarity (D44)
- [ ] T066 [US4] Define `face.match_threshold` as a minimum cosine similarity and mark the current value a placeholder in `scanners/config.py` and `config.yaml.example` (D45)
- [ ] T067 [US4] Implement the person entity, its repository and the merge in `models/person.py` and `models/managers.py`
- [ ] T068 [US4] Cluster detected faces into people in `scanners/face_task.py`, with the `ponytail:` ceiling comment naming the pgvector upgrade path (R9)
- [ ] T069 [US4] Store the frame as a file and its path in the database in `scanners/face_task.py` and `scanners/frames.py`
- [ ] T070 [US4] Register `scan faces`, `report faces` and `search` in `main.py`
- [ ] T071 [US4] Implement the monitoring query in `models/managers.py`, using the indexes of data-model.md and no SQL built from strings
- [ ] T072 [US4] Implement `measure threshold` over the labelled pair set in `scanners/face_recognizer.py` and register it in `main.py` (D16)
- [ ] T080 [P] [US4] Test the measurement: same identity pairs score above different identity pairs on a fixed set of embeddings, and an identity directory with one image exits 1, in `tests/test_threshold_measure.py`
- [ ] T073 [US4] Lab run: the same face in two frames yields one person, and the `search` output is pasted into the front report

**Checkpoint**: SC-005 and SC-006 hold against the lab.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: the documentation and the gates that cover every front.

- [ ] T074 [P] Rewrite `README.md` for the subcommands of `contracts/cli.md`, removing the proxy section (D34, D38)
- [ ] T075 [P] Update `.specify/memory/constitution.md` and `docs/decisions/` if any front contradicted a recorded decision
- [ ] T076 Run the whole gate: `uv run pytest -q`, `uv run ruff check .`, and the quickstart end to end, with the raw output pasted
- [ ] T077 Confirm every front report carries a raw lab output, and that any unmeasured value is still labelled a placeholder (SC-009, SC-010)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies
- **Foundational (Phase 2)**: depends on Setup. T006 blocks US1 and US4, T007 blocks US4, T008 blocks US3. T008 and T009 can run in parallel with Phase 3 and Phase 4
- **US1 (Phase 3)**: depends on Setup and T006
- **US5 (Phase 4)**: depends on US1, because the cleanup removes tests that reference the new repositories. Runs before US2, US3 and US4 so they touch a smaller tree (D12)
- **US2 (Phase 5)**: depends on US1 and US5
- **US3 (Phase 6)**: depends on US2, which supplies the identification the match needs, and on T008
- **US4 (Phase 7)**: depends on US3, which supplies the frames, and on T006 and T007
- **Polish (Phase 8)**: depends on every front

### Within Each Phase

- Tests first, and they must fail before the implementation lands (constitution principle II)
- Models before repositories, repositories before services, services before the CLI command
- Each front ends with its lab run and its pasted raw output (D24)

### Parallel Opportunities

- Phase 1: T002, T003 and T004 touch different files
- Phase 3: T010 to T013 are four test files; T015 and T016 are separate entity files
- Phase 5: T036 to T039 are four test files
- Phase 6: T052, T053 and T054 are three separate CVE modules
- Phase 7: T060 to T064 are five test files
- The firmware emulation (T008) is the long pole and can be started on day one

---

## Parallel Example: User Story 3

```bash
# The three CVE class modules touch different files and can be written together:
Task: "Implement the authentication bypass module for CVE-2017-7921 in scanners/cve/auth_bypass.py"
Task: "Implement the unauthenticated read module for CVE-2025-34022 and CVE-2016-15055 in scanners/cve/unauth_read.py"
Task: "Implement the unauthenticated ONVIF module in scanners/cve/unauth_onvif.py"
```

---

## Implementation Strategy

### MVP first

Phase 1, Phase 2 (T006 only), Phase 3. That delivers a database that remembers history and a
scan that fills it, which is user story 1 and the foundation every other front writes to.
Stop and validate with the quickstart before continuing.

### Incremental delivery

One front per branch and per reviewed PR (D32), in this order: US1, US5, US2, US3, US4, then
Polish. Each front is independently testable and leaves the tree passing its own gates.

### What is not in this list

The mock fallback for the lab (only if T008 fails), any purge of stored frames or embeddings
(contradicts D10), any automatic labelling of a person (contradicts D28), and the deploy,
scheduling, metrics and alerting work that D2 put out of scope.

---

## Notes

- [P] means different files and no dependency on an incomplete task
- A front is not done until its test fails when the logic breaks and its lab output is pasted
- A number that has not been measured is labelled a placeholder, in the config and in the docs
- The gates are `uv run pytest -q` and `uv run ruff check .`, run by hand before every commit (D20)
