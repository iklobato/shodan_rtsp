# Implementation Plan: Person Search

**Branch**: `002-person-search` | **Date**: 2026-11-12 | **Spec**: `specs/002-person-search/spec.md`
**Input**: Feature specification from `/specs/002-person-search/spec.md`
**Decisions**: `docs/decisions/2026-11-12-busca-pessoa-especifica.md` (D47 to D67)

## Summary

Add one question to the pipeline: given a photo of a specific person, where and when did
that person appear. The photo registers a named target with one or more reference images.
The search compares each target photo against every stored face, writes one hit per target
and face, prints a ranking with the score, and writes the target name into a person that
has no label. On request it also captures fresh frames through the existing face scan path
before answering.

Technical approach: three new tables in one Alembic revision, a new comparison that reuses
the existing cosine metric and the existing face model, a `search` group with `search
person` and the renamed `search appearance`, and the live pass delegated to the existing
`FaceScanTask` behind the same allowlist gate that `scan check` already uses.

## Technical Context

**Language/Version**: Python 3.11.7 (`requires-python = ">=3.11,<3.12"`), managed by `uv`

**Primary Dependencies**: unchanged. SQLAlchemy 2.0.19, alembic, psycopg2-binary, pydantic
2.11.10, pyyaml, opencv-python-headless 4.8.0.74, numpy 1.x, insightface 0.7.3,
onnxruntime 1.20.1. No dependency is added by this feature (D67, constitution).

**Storage**: PostgreSQL 16, compose service `shodan_pg`, host port 5440 (D40). Reference
photos land under `frames.root_path` beside the captured frames (D62, R3). The new tables
are `target`, `target_photo` and `target_hit` (D49, D53).

**Testing**: `pytest` 8.4.1 through `uv run pytest -q`, `uv run ruff check .`, both by hand
(D46 runs them in CI, the local gate is the same two commands). Model tests run on sqlite in
memory through the shared fixtures of `tests/conftest.py`, which already carries the
dialect-conditional `EMBEDDING` type.

**Target Platform**: the operator workstation, macOS 14, local only (D2). One operator, one
lab, one database.

**Project Type**: single project, CLI application, existing flat layout.

**Performance Goals**: lab scale. The comparison is one pass over the stored faces for each
target photo, in Python, marked with a `ponytail:` comment naming the ceiling and the
pgvector upgrade path, as the existing matcher already declares. No new index and no
extension.

**Constraints**: the live pass is off by default and gated by `targets.allowed_cidrs`
(D59, D61). The feature adds no way to reach an address that a previous authorized scan did
not store (FR-020). Retention is unlimited except for the rows this feature creates, which
`search person --forget` deletes (D54, D64).

**Scale/Scope**: tens of cameras, a bounded number of stored faces, a handful of targets.
One target has one or more photos. One hit is one target matched to one stored face.

## Constitution Check

*GATE: passed before Phase 0 research, re-checked after Phase 1 design.*

| # | Gate | Verdict | Evidence |
|---|------|---------|----------|
| I | Python SOLID | PASS | New behavior is classes with injected collaborators: `TargetRegistration`, `TargetSearch`, `TargetRemoval`, `TargetTask`, one repository per new table. At most 3 parameters, at most 20 lines per method, no `elif`, own exception types. |
| II | Tests that can fail | PASS | Each front carries a test that fails if the logic breaks: duplicate hit, manual label preserved, reach gate, photo with no face. Fakes for the database and the detector already exist in `tests/conftest.py`; no mock replaces a real collaborator. |
| III | Review order and form | PASS | Fronts are reviewed in the order the contract requires, each finding with line, why and fix. |
| IV | System-design restraint | PASS | No new service, no API, no scheduler, no vector index. The live pass reuses `FaceScanTask` instead of a second capture path (D56). |
| V | Data, API and dependency safety | PASS | Bound parameters through the ORM, one transaction per write, one Alembic revision with a rollback path, no lockfile change. |
| 1 | Authorized targets only | PASS | The live pass checks every camera against `targets.allowed_cidrs` before any packet (D59) and an address outside the list stops the run. It reaches only stored cameras (FR-020). The search without `--live` makes no network call at all. |
| 2 | Read-only proof | PASS with a scope note | This feature reads no device except through the existing capture path, which pulls frames and writes nothing to the target. |
| 3 | Lab-verified | PASS with a stated limit | Every front pastes a real run. The verification threshold stays a labelled placeholder until the lab pair set is measured (D60); the plan does not pretend it is measured. |
| 4 | Recorded decisions | PASS | Every rule in the plan traces to D47 to D67. Two decisions move earlier ones (`D63` moves `D28`, `D54` moves `D10`), and both are recorded as exceptions in the decisions file. |
| 5 | Migrations | PASS | One new revision, `0003_person_search`, with a downgrade that drops the three tables in dependency order. |
| 6 | Smallest diff | PASS | One new model module, one new task module, one comparison module, one config section, one report renderer, one CLI group. No restructure, no rename of existing modules. |
| 7 | No new dependency | PASS | None requested, none added. |
| 8 | Retention exception recorded | PASS | `--forget` deletes target, photo and hit rows only, never a frame, a face or an embedding (D54, FR-022). |

No gate failed. Two items can look like violations and are recorded in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/002-person-search/
├── plan.md              # this file
├── spec.md              # the specification
├── research.md          # Phase 0 output, R1 to R8
├── data-model.md        # Phase 1 output
├── contracts/
│   └── cli.md           # the command surface, updated for the search group
├── quickstart.md        # the runbook
├── checklists/
│   └── requirements.md  # spec quality checklist
└── tasks.md             # Phase 2 output, written by /speckit-tasks
```

### Source Code (repository root)

```text
models/
├── target.py            # new: Target, TargetPhoto, TargetHit
└── managers.py          # adds TargetRepository, TargetHitRepository, TargetReader,
                         # and a label-only write on PersonRepository

scanners/
├── target_search.py     # new: registration, comparison, ranking, removal
├── target_task.py       # new: the command tasks, including the optional live pass
├── reports.py           # adds TargetRankingReport; PersonReport gains the target line
└── config.py            # adds PersonSearchConfig (threshold, placeholder label)

migrations/versions/
└── 0003_person_search.py  # new: the three tables, with downgrade

main.py                  # search becomes a group: person and appearance
tests/                   # new test modules, plus the migration round trip
```

**Structure Decision**: single project, existing flat layout. New modules sit beside the
ones they extend, following the naming of `scanners/face_task.py`, `scanners/frames.py` and
`scanners/reports.py`.

## Delivery fronts

Four branches, one PR each (D32), in this order.

### Front 1: schema, config and migration

- **IN**: `target`, `target_photo` and `target_hit` as SQLAlchemy models with their
  constraints; the Alembic revision `0003` with downgrade; the `person_search` config
  section with `match_threshold` as a labelled placeholder; the repositories that read and
  write the three tables.
- **OUT**: any command, any comparison, any report line.
- **Files**: `models/target.py`, `models/managers.py`, `migrations/versions/0003_person_search.py`,
  `scanners/config.py`, `config.yaml.example`, `tests/`.
- **Done when**: `alembic upgrade head` on an empty database creates the three tables and a
  second run changes nothing, `downgrade` removes them and leaves the other tables intact,
  and the repository tests run on sqlite and on the lab database.

### Front 2: registration and the stored search

- **IN**: reading a reference photo, refusing one with no face or with more than one face,
  storing the photo under the frame root, registering a target by unique name, comparing a
  target against every stored face, writing one hit per target and face, ranking, and
  `search person --image` and `search person --target-id`; the `search` group with the
  existing command renamed to `search appearance`.
- **OUT**: the label write, the report change, the live pass and `--forget`.
- **Files**: `scanners/target_search.py`, `scanners/target_task.py`, `scanners/config.py`,
  `main.py`, `tests/`.
- **Done when**: a target registered from a photo finds the stored appearances with camera,
  time, path and score, a second run leaves the hit count identical, and a photo with no
  face fails with a reason and creates nothing.

### Front 3: label, report and removal

- **IN**: writing the target name into a person that has no label and never overwriting a
  manual one; the target line in `report faces`; `search person --forget` with the label
  cleanup rule; the command contract updated for all of it.
- **OUT**: any change to the live pass.
- **Files**: `models/managers.py`, `scanners/target_search.py`, `scanners/reports.py`,
  `main.py`, `specs/002-person-search/contracts/cli.md`, `tests/`.
- **Done when**: a target names an unlabeled person, a manual label survives, the face
  report shows the target and the score, and removal leaves every frame, face and embedding
  untouched.

### Front 4: the live pass

- **IN**: `--live`, which runs the existing `FaceScanTask` path first and then the stored
  search, behind the `targets.allowed_cidrs` gate, with the run recorded as a `scan_run` of
  kind `faces`.
- **OUT**: any new capture code, any second way to reach a camera, and any scheduling.
- **Files**: `scanners/target_task.py`, `main.py`, `specs/002-person-search/contracts/cli.md`,
  `tests/`.
- **Done when**: a search without `--live` makes no network call, a search with `--live`
  against the lab camera lists and stores the appearance, and one address outside the list
  stops the run before any packet with the address named.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|------|------------|--------------------------------------|
| A separate comparison class instead of extending `FaceRecognizer.match_against` | The existing method filters by the grouping threshold and answers only "which person". The target search needs every similarity for a ranking and a different threshold (D51). | Passing a second threshold into `match_against`. It would make one method serve two meanings of a score, which is the exact confusion D45 closed. |
| A `search` group with two commands | A target search and an appearance search are different questions, and argparse needs a group for the first one (D52). | `search --image` on the existing command. It was offered and rejected because the two questions would share one flag set. |
| Reference photos kept on disk | The photo that produced an embedding is the evidence for a hit (D62). | Keeping only the embedding. It was rejected because a wrong hit could not be explained or remeasured. |

## Recorded risks carried into the plan

1. The verification threshold is a placeholder until the lab measures it (D60). The report
   must not present it as measured.
2. `--forget` compares the person label to the target name (D64). An edited label leaves the
   target name behind after the target is gone.
3. The live pass stores frames and faces of everyone in view, not only the target (D56).
4. Every photo search creates a stored target, because there is no one-shot mode (D55).
5. The comparison cost grows with stored faces times target photos, silently (D67).
6. Writing the target name into a person label is an exception to D28 and is recorded as
   such. If two targets match one person, the first to write wins and the second is only a
   hit row.

## Phase outputs

- **Phase 0**: `research.md`, R1 to R8, every unknown resolved or explicitly marked
  unverified.
- **Phase 1**: `data-model.md`, `contracts/cli.md`, `quickstart.md`, and the agent context
  file updated to point at this plan.
- **Phase 2**: `tasks.md`, written by `/speckit-tasks`, with the four fronts as phases.
