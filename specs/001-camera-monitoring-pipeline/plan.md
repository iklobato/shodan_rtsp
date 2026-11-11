# Implementation Plan: Camera Monitoring Pipeline

**Branch**: `001-camera-monitoring-pipeline` | **Date**: 2026-11-11 | **Spec**: `specs/001-camera-monitoring-pipeline/spec.md`
**Input**: Feature specification from `/specs/001-camera-monitoring-pipeline/spec.md`
**Decisions**: `docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` (D1 to D41)

## Summary

Turn the current scanner into a pipeline that finds cameras on an authorized network,
identifies their make and model, uses a known CVE to pull a single proof frame, groups the
faces in those frames into people, and answers who appeared where and when from stored
data.

The work is delivered as six fronts. Five come from D12: the schema with migrations, the
cleanup of dead code and bugs, identification, the read-only CVE proof, and the face and
monitoring front. The sixth is the lab rig, which the operator chose during planning so
that the CVE proof runs against emulated vendor firmware rather than a mock.

Technical approach: a normalized PostgreSQL 16 schema created by Alembic on a dedicated
instance, the raw banner kept as evidence for identification, brand signatures moved from
code into a YAML data file, one module per CVE class with a read-only proof, cosine
matching over the 512-d `buffalo_l` embedding, and a subcommand CLI whose `search` command
is the monitoring answer.

## Technical Context

**Language/Version**: Python 3.11.7 (`requires-python = ">=3.11,<3.12"`), managed by `uv`

**Primary Dependencies**: kept: SQLAlchemy 2.0.19, psycopg2-binary, pydantic 2.11.10,
pyyaml, opencv-python-headless 4.8.0.74, numpy 1.x, insightface 0.7.3, onnxruntime 1.20.1,
python-nmap 0.7.1, shodan 1.28.0. Added: `alembic`, authorized by D4. Removed: `curl_cffi`,
which exists only for the proxy path retired by D11.

**Storage**: PostgreSQL 16, the compose service `shodan_pg`, host port 5440 (D40). Frames
are files on disk under `frames.root_path`, with the path in the database (D17). The
Homebrew Postgres at 5432 that the tool points at today is shared with `mercur` and
`suleiman` and is left untouched.

**Testing**: `pytest` 8.4.1 through `uv run pytest -q`, plus `uv run ruff check .`. No CI
(D20), so both are run by hand before every commit.

**Target Platform**: the operator workstation, macOS 14 (darwin 23.6.0), local only (D2).
The lab is `mediamtx` v1.11.3 for RTSP plus emulated camera firmware.

**Project Type**: single project, CLI application. The current flat layout stays.

**Performance Goals**: lab scale, tens of cameras. The bounds that already exist and are
kept: one RTSP attempt times out at 8 s (`OPENCV_FFMPEG_CAPTURE_OPTIONS` is
`rtsp_transport;tcp|stimeout;8000000`), seven ports per host (D15), five frames per camera
per scan (`face.frames_per_scan`). Face matching is an O(n) scan over stored embeddings,
marked with a `ponytail:` ceiling naming the pgvector upgrade path.

**Constraints**: the CVE proof is read-only (at most one frame, nothing written to the
device). There is no scope gate in code, an accepted risk (D6), so every front states which
target set it can reach. Retention is unlimited by decision, so nothing purges frames or
embeddings (D10, D13). No dependency beyond `alembic` is added without a decision.

**Scale/Scope**: one operator, one lab, one database. Row volume is cameras times ports
times runs for observations, and one row per camera per CVE for findings.

## Constitution Check

*GATE: passed before Phase 0 research, re-checked after Phase 1 design.*

| # | Gate | Verdict | Evidence |
|---|------|---------|----------|
| 1 | Authorized targets only | PASS | Every new egress path is named in a front below. The CVE modules reach only the addresses already stored in `camera`, which came from a scan of the declared range. `scan shodan` checks its query against the declared CIDR list before the API call (D18). The `scan_run.target_set` column records what each run reached (FR-002). |
| 2 | Read-only proof | PASS | Only GET-based proofs are used (R5). The Dahua bypass and the Foscam proof were rejected because they create device state or write. One frame per attempt, enforced by the `cve_finding` check constraint. |
| 3 | Python SOLID | PASS | New code is classes with injected collaborators, at most 3 parameters, at most 20 lines per method, no `elif`, own exception types. |
| 4 | Tests that can fail | PASS | Each front carries a test that fails when the logic breaks, tests the failure path, and uses a fake rather than a mock for IO. The migration front tests both directions of the migration. |
| 5 | Lab-verified | PASS with a stated limit | Front 6 builds the rig, and every front pastes raw output from a real run (D24). The limit: if firmware emulation cannot serve the vulnerable request, the fallback is a mock and the evidence must say so, in the plan and in the front report. No unmeasured value is presented as measured; the face threshold is a labelled placeholder until step 7 of the quickstart. |
| 6 | Recorded decisions | PASS | The schema follows D7 and D33, storage follows D17, the metric fix follows D16, and nothing deletes frames or embeddings. The database port change (D40) and the CLI name gap (R7) were raised and decided rather than assumed. |
| 7 | Migrations | PASS | Every schema change is an Alembic revision, live-safe per R3, with a rollback path. |
| 8 | Smallest diff | PASS | The scope manifest of each front is one line IN and one line OUT, and each front lists the files it touches. No front restructures the layout. |
| 9 | No new dependency | PASS | `alembic` only, authorized by D4. `curl_cffi` is removed, not added. FEMU and FirmAE are lab tools outside the project, not project dependencies. |

No gate failed, so there is no unjustified complexity. The two items that could look like
violations are recorded in Complexity Tracking below, both justified.

## Project Structure

### Documentation (this feature)

```text
specs/001-camera-monitoring-pipeline/
├── plan.md              # this file
├── spec.md              # the specification
├── research.md          # Phase 0 output, R1 to R11
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── cli.md                   # the command line contract
│   └── brand-signatures.md      # the brands.yaml data contract
├── checklists/
│   └── requirements.md  # spec quality checklist, 16 of 16 pass
└── tasks.md             # Phase 2 output, written by /speckit-tasks
```

### Source Code (repository root)

The current layout stays. New modules sit beside their siblings.

```text
main.py                  # CLI entry, becomes subcommands (D34)
alembic.ini              # new
alembic/
├── env.py               # wired to Base.metadata, naming convention, transaction_per_migration
└── versions/
    └── 0001_initial_schema.py

models/
├── camera.py            # camera, face, face_frame; becomes the seven entities of data-model.md
├── database.py          # unchanged in shape
└── managers.py          # repositories per entity

scanners/
├── config.py            # proxy section removed, frames and brands sections added
├── task.py              # nmap, shodan and check tasks; banner fields kept, not discarded
├── rtsp_probe.py        # credential log line removed
├── brand_probe.py       # revived: reads brands.yaml, no hardcoded brand or credential tables
├── vuln_probe.py        # identification, unchanged in role
├── vuln_task.py         # reads observations from the database (D30)
├── face_recognizer.py   # cosine over normed_embedding, 512-d
├── face_task.py         # capture, detect, cluster into person
├── cve/                 # new: one module per CVE class, read-only proof
└── frames.py            # new: the on-disk layout of R8

brands.yaml              # new: brand signatures and brand credential sets
cpe_map.yaml             # kept
docker-compose.yml       # postgres host port moves to 5440

tests/                   # pytest, Fakes for IO, one failing-path test per behavior
```

**Structure Decision**: single project, existing flat layout. No package restructure, no
new service, no scheduler and no API: the operator runs commands by hand (D2, D29).

## Delivery fronts

Six branches, one PR each (D32), in this order. Fronts 1 to 5 are D12. Front 6 was added
during planning because the CVE proof needs a real target (D24).

### Front 1: schema and migrations

- **IN**: the seven entities of `data-model.md`, created by the first Alembic revision on
  the dedicated instance, plus the CLI skeleton with `scan nmap` and `scan shodan`.
- **OUT**: every other command, every scanner behavior change, any data migration from the
  old tables (they hold 0 rows and are on another instance).
- **Files**: `alembic.ini`, `alembic/`, `models/`, `docker-compose.yml`, `main.py`,
  `scanners/config.py`, `config.yaml.example`, `tests/`.
- **Done when**: `alembic upgrade head` on an empty database creates everything and a second
  run changes nothing; a scan writes one observation per camera per port; `uv run pytest -q`
  and `uv run ruff check .` pass.

### Front 2: dead code and bugs

- **IN**: the proxy path and its config, tests and dependency removed; the credential log
  line removed; the unused helper that mutates its input removed; the unreachable branch and
  its dead class state removed; `_probe_names.py`, `docs/proxy-investigation.md`,
  `proxylist.txt` and `.serena/` deleted; `docs/KNOWLEDGE.md` trimmed to a session log (D36).
- **OUT**: any behavior change beyond the removals, the README (rewritten in front 5, after
  the commands it documents exist), and `brand_probe.py` (revived in front 3).
- **Files**: `scanners/proxy.py`, `scanners/proxy_tunnel.py`, `scanners/task.py`,
  `scanners/rtsp_probe.py`, `models/managers.py`, `scanners/config.py`, `pyproject.toml`,
  `uv.lock`, `tests/`, `docs/KNOWLEDGE.md`.
- **Done when**: the suite passes with the retired tests gone and the direct path still
  covered by a test that can fail.

### Front 3: identification

- **IN**: the raw banner stored as evidence, `brands.yaml` driving brand detection and the
  brand credential set, the version range attached from the CVE map, `scan check` in the new
  CLI with brand credentials tried first.
- **OUT**: any new CVE exploitation (front 4) and any active HTTP or ONVIF probe beyond the
  ports already scanned.
- **Files**: `brands.yaml`, `scanners/brand_probe.py`, `scanners/task.py`,
  `scanners/config.py`, `scanners/vuln_probe.py`, `main.py`, `tests/`.
- **Done when**: a known banner yields vendor, product and version with its raw evidence
  kept, an unknown device is stored as unknown with its banner kept, and a new brand added
  only to `brands.yaml` is detected with no code change.

### Front 4: read-only CVE proof

- **IN**: the three classes of R5, one module each, tried in order until one yields a frame,
  with the outcome and the failure reason recorded either way; `scan cve` in the CLI.
- **OUT**: RCE, configuration writes, credential brute force beyond the existing check, and
  the Dahua and Foscam candidates rejected on the read-only rule.
- **Files**: `scanners/cve/`, `scanners/vuln_task.py`, `scanners/frames.py`,
  `scanners/config.py`, `main.py`, `tests/`.
- **Done when**: against the emulated firmware the Hikvision proof returns a JPEG, the
  device state before and after is identical, and a device that does not answer records a
  reason rather than crashing.

### Front 5: faces, people and the monitoring answer

- **IN**: the metric fix (cosine over the 512-d normed embedding), clustering into `person`
  with the merge rule, `scan faces`, `report faces` and `search` in the CLI, and the README
  rewritten for the new commands.
- **OUT**: any automatic labelling of a person, any purge, and any watchlist behavior.
- **Files**: `scanners/face_recognizer.py`, `scanners/face_task.py`, `scanners/frames.py`,
  `models/`, `main.py`, `README.md`, `tests/`.
- **Done when**: a face seen twice is one person, a face matching two people merges them,
  `search` answers who appeared where and when, and the measured threshold replaces the
  placeholder.

### Front 6: the lab rig

- **IN**: `mediamtx` serving a looped stream, emulated Hikvision firmware under FEMU or
  FirmAE, the face pair set for the threshold measurement, and a written rig document with
  the raw output of the vulnerable request.
- **OUT**: any change to the project code. This front produces a target and evidence.
- **Files**: a rig document under `docs/`, plus the compose profile for the lab if one is
  needed. No project dependency.
- **Done when**: the emulated device answers the vulnerable snapshot request with a JPEG and
  the raw response is pasted, or the attempt is recorded as failed with the reason and front
  4 stays blocked.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|------|------------|--------------------------------------|
| Firmware emulation as a lab target (front 6) | A CVE proof cannot be verified without a target that actually carries the vulnerability. The operator chose real firmware over a mock, and this is the concrete written reason principle IV requires. | A local mock that imitates the request shape. It is simpler and faster, and it was rejected by the operator. It stays as the labelled fallback if emulation fails. |
| An O(n) scan over stored embeddings instead of an index | At lab scale, tens of cameras and a bounded number of faces, a linear scan in Python is correct and needs no extension. Marked in code with a `ponytail:` comment naming the ceiling and the pgvector upgrade path. | A vector index now would add a dependency and an extension for a scale this project does not have. |

## Recorded risks carried into the plan

1. `camera.password` stores the credential that worked, in plaintext, in the database. No
   decision covers this, so it is recorded here rather than changed silently. It is needed
   to re-read a stream later, and D39 already accepts plaintext credentials in `config.yaml`.
2. Unlimited retention means the frame directory and the embedding table grow without
   limit, and disk exhaustion is the failure mode. It is silent (D10, D13).
3. The `unauth_read` class returns a file and not an image, so its honest outcome is a
   recorded `no_frame`. Only the `auth_bypass` class yields a frame today.
4. Four details of the chosen CVEs are unverified (R5). The lab run resolves them, and the
   code must not assume the answer.

## Phase outputs

- **Phase 0**: `research.md`, R1 to R11, every unknown resolved or explicitly marked
  unverified.
- **Phase 1**: `data-model.md`, `contracts/cli.md`, `contracts/brand-signatures.md`,
  `quickstart.md`, and the agent context file updated to point at this plan.
- **Phase 2**: `tasks.md`, written by `/speckit-tasks`, with the six fronts as phases.
