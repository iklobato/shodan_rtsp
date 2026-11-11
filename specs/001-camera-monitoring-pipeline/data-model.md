# Data Model: Camera Monitoring Pipeline

**Feature**: `specs/001-camera-monitoring-pipeline/spec.md`
**Plan**: `specs/001-camera-monitoring-pipeline/plan.md`
**Decisions**: `docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md` (D7, D17, D19, D25, D33, D35)
**Created**: 2026-11-11

Target: PostgreSQL 16, created from scratch by the first Alembic migration. The database
is new and empty, so every table is a plain `CREATE TABLE` with no rename step and no
backfill. The three hand-made tables on the Homebrew instance at `127.0.0.1:5432` are
left alone.

Table names are singular throughout (`camera`, `face`, `face_frame`) rather than the
current mix of `cam`, `faces` and `face_frames`. On a fresh database the consistent name
costs nothing, and the schema is not something to fix later.

## Entity overview

```text
scan_run 1---n camera_observation n---1 camera
scan_run 1---n cve_finding          n---1 camera
scan_run 1---n face_frame           n---1 camera
face_frame 1---n face               n---1 person
cve_finding 0---1 face_frame        (the proof frame, when one was obtained)
```

`brand_signature` and `credential_set` are data files, not tables (D27, D15). A new brand
is a line in YAML.

## camera

One device at one address and port. Replaces the `cam` table.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| ip | varchar(45) | no | IPv6-capable length |
| port | integer | no | 1 to 65535 |
| user | varchar(128) | no | the credential that worked, empty when none did |
| password | varchar(256) | no | the credential that worked, empty when none did |
| url | varchar(512) | no | the stream or snapshot URL that worked |
| status | camera_status | no | replaces the `active` boolean (D33) |
| vendor | varchar(128) | no | interpreted identification |
| product | varchar(128) | no | |
| version | varchar(64) | no | |
| raw_banner | jsonb | yes | the raw evidence the identification was based on (D3) |
| city | varchar(128) | no | |
| country_code | varchar(8) | no | |
| country_name | varchar(128) | no | |
| region_code | varchar(32) | no | |
| added_at | timestamptz | no | |
| updated_at | timestamptz | no | |

Constraints and indexes:

- `UNIQUE (ip, port)`: one row per address and port. Two cameras on the same address with
  different ports are two rows, which is the edge case the spec names.
- `INDEX (vendor, product)`: drives the CVE match, which selects by product.
- `INDEX (status)`: drives the report of what is offline.

Validation:

- `ip` is non-empty and parses as IPv4 or IPv6. Rejected at construction, not at the
  database, so a bad range fails before a network call.
- `port` is in 1 to 65535.
- `status` is one of the enum values below.
- `raw_banner`, when present, is a JSON object.

State transitions for `status`:

```text
unknown ──responded──> responded ──rtsp ok────> stream_obtained
                            └─────cve ok────> frame_by_cve
unknown|responded|stream_obtained|frame_by_cve ──no answer──> offline
offline ──answers again──> responded
```

`frame_by_cve` exists because the CVE path never authenticates over RTSP, so no boolean
can express it (D33).

## scan_run

One execution of one scan kind against one target set. New table.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| kind | scan_kind | no | nmap, shodan, check, cve, faces |
| target_set | text | no | the CIDR list or the Shodan query actually reached (FR-002) |
| started_at | timestamptz | no | |
| finished_at | timestamptz | yes | null while the run is in flight |
| camera_count | integer | no | default 0 |

Constraints and indexes:

- `INDEX (kind, started_at)`: lists the recent runs of one kind.
- `target_set` is never empty. It is the record of what the run was allowed to reach,
  and it is the only place that answers the question after the fact (D6 accepted the
  risk of having no gate in code, so the record has to be complete).

## camera_observation

What one camera looked like on one port in one run. New table. This is the time series
that makes change over time visible (D19).

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| camera_id | integer FK camera(id) | no | |
| scan_run_id | integer FK scan_run(id) | no | |
| port | integer | no | |
| status | camera_status | no | as seen in this run |
| vendor | varchar(128) | no | as seen in this run |
| product | varchar(128) | no | |
| version | varchar(64) | no | |
| raw_banner | jsonb | yes | |
| observed_at | timestamptz | no | |

Constraints and indexes:

- `UNIQUE (camera_id, scan_run_id, port)`: one row per camera per scan per port (FR-006).
  This is what makes a repeated run idempotent instead of doubling the series.
- `INDEX (camera_id, observed_at)`: reads the history of one camera in time order.
- `INDEX (scan_run_id)`: reads one run back whole.

## cve_finding

A vulnerable product and version range matched to a camera, plus what happened when the
proof was attempted. New table.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| camera_id | integer FK camera(id) | no | |
| scan_run_id | integer FK scan_run(id) | yes | null until an attempt runs |
| cve_id | varchar(32) | no | e.g. `CVE-2017-7921` |
| cve_class | cve_class | no | auth_bypass, unauth_read, unauth_onvif |
| matched_range | varchar(128) | no | the version range that matched, empty when the match is by product only |
| cvss | real | yes | null when the feed carries no score |
| outcome | cve_outcome | no | default `not_attempted` |
| failure_reason | varchar(512) | no | empty only when a frame was obtained |
| frame_id | integer FK face_frame(id) | yes | the single proof frame |
| first_seen_at | timestamptz | no | when this camera first matched |
| last_attempt_at | timestamptz | yes | null until an attempt runs |

Constraints and indexes:

- `UNIQUE (camera_id, cve_id)`: one row per camera and CVE, updated in place on each
  attempt. `first_seen_at` keeps the history, so a repeated run does not add rows.
- `CHECK (outcome = 'frame_obtained') = (frame_id IS NOT NULL)`: a frame is recorded
  exactly when one was obtained.
- `CHECK (outcome = 'frame_obtained' OR failure_reason <> '')`: a candidate that yielded
  no frame always carries the reason (D31). This is the constraint that makes silence
  impossible.
- `INDEX (cve_id)`: counts how many cameras carry one CVE.
- `INDEX (camera_id)`: lists the findings of one camera.

## face_frame

One stored frame. Replaces the `face_frames` table, and its `image_b64` column becomes a
path (D17).

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| camera_id | integer FK camera(id) | no | |
| scan_run_id | integer FK scan_run(id) | yes | |
| path | varchar(512) | no | path on disk, relative to the configured frame root |
| source | frame_source | no | rtsp or cve |
| width | integer | yes | null when the frame could not be measured |
| height | integer | yes | |
| captured_at | timestamptz | no | |

Constraints and indexes:

- `INDEX (camera_id, captured_at)`: reads the frames of one camera in time order, which
  is the join the monitoring query walks.
- `INDEX (scan_run_id)`.
- `UNIQUE (path)`: one row per file, so a re-run does not point two rows at one file.
- `path` is never empty. A row whose file is missing on disk is a reportable state, not
  a reason to drop the row: the row is the record that the frame was obtained.

## face

One detected face in one frame. Replaces the `faces` table.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| frame_id | integer FK face_frame(id) | no | was nullable; a face always has a frame |
| person_id | integer FK person(id) | yes | null before clustering assigns it |
| embedding | double precision[] | no | 512 values, stored raw, not normalized |
| bbox_top | integer | no | |
| bbox_left | integer | no | |
| bbox_bottom | integer | no | |
| bbox_right | integer | no | |
| confidence | real | no | was a string; now a number |
| created_at | timestamptz | no | |

Constraints and indexes:

- `INDEX (person_id)`: the join from a person to their faces.
- `INDEX (frame_id)`: the faces of one frame.
- `CHECK (array_length(embedding, 1) = 512)`: the `buffalo_l` recognition model
  (`w600k_r50`) emits 512 values, so a vector of another length is a bug and not data.
  Measured on the cached model, not taken from the comment in the code: the repository
  says 128-d in `pyproject.toml:18` and `scanners/face_recognizer.py:3,31`, and that is
  wrong.
- The raw vector is stored, and the comparison normalizes at match time. Storing only the
  normalized form would throw away the original measurement, and a later change of metric
  could not be recomputed from it.

## person

A cluster of faces judged to be the same individual. New table (D28).

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| label | varchar(128) | yes | manual and optional; null means anonymous |
| created_at | timestamptz | no | |
| updated_at | timestamptz | no | |

Constraints and indexes:

- `INDEX (label)`: finds a labeled person by name.
- `label`, when set, is trimmed and non-empty. Null is the default and stays the normal
  state: nothing in this batch labels a person automatically.

Merge rule (D35): when one face matches two people, the older person row wins, every face
of the newer one is re-pointed to the winner, and the newer person row is deleted. No face
and no frame is deleted by a merge, so this does not touch the unlimited retention of D10.

## Data files, not tables

| File | Shape | Consumed by |
|------|-------|-------------|
| `cpe_map.yaml` | product string to `vendor:product` | the CVE match (already exists) |
| brand signatures | banner pattern to brand, vendor and product | brand detection (D27) |
| credential sets | brand to user and password list, plus a generic set | the credential check (D22) |

## Indexes that serve the monitoring question

The primary read path is who appeared, where and when (D25). It walks
`person` to `face` to `face_frame` to `camera`:

1. `face (person_id)` selects the faces of the person.
2. `face (frame_id)` reaches the frame of each face.
3. `face_frame (camera_id, captured_at)` orders by time and reaches the camera.
4. `camera (id)` resolves the address.

No index is added that this path does not use.

## Retention

Frames and embeddings are kept indefinitely (D10, D13). No table carries a `deleted_at`,
no migration adds a purge job, and no code in this batch deletes a `face_frame` or a
`face`. The only deletion in the model is the losing `person` row of a merge, which holds
no frame and no embedding.
