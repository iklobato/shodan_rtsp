# Tasks: Person Search

**Feature**: `specs/002-person-search/spec.md`
**Plan**: `specs/002-person-search/plan.md`
**Branch**: `002-person-search`
**Created**: 2026-11-12

Organized by the four user stories of the spec. Tests are required by the constitution
(principle II) and by D24, so every story carries the test that fails if its logic breaks.

## Phase 1: Setup

- [x] T001 Confirm the branch and the clean gate: `git status` on `002-person-search`, then `uv run pytest -q` and `uv run ruff check .` to record the baseline in the front report
- [x] T002 [P] Add the `person_search` section to `scanners/config.py` with `match_threshold` and the `PLACEHOLDER` comment (R5)
- [x] T003 [P] Add the same section to `config.yaml.example` with the placeholder note

## Phase 2: Foundational (blocks every story)

- [x] T004 Create `models/target.py` with `Target` (id, name unique, created_at, updated_at) and its trim validation
- [x] T005 Add `TargetPhoto` and `TargetHit` to `models/target.py` with the unique and check constraints of `data-model.md`
- [x] T006 Add the repositories to `models/managers.py`: `TargetRepository` (find by name, find by id, create, add photo, delete), `TargetHitRepository` (upsert keeping the highest score, hits of a target), `TargetReader` (faces with person, camera, frame, score)
- [x] T007 Add `PersonRepository.name_if_empty(person, name)` in `models/managers.py`, writing the label only when it is null
- [x] T008 Write `migrations/versions/0003_person_search.py` with the three tables and a downgrade that drops them in dependency order
- [x] T009 Extend `tests/test_migrations.py` with the upgrade, downgrade and second upgrade round trip for `0003`
- [x] T010 Add `TargetStore` or extend `FrameStore` in `scanners/frames.py` to copy a reference photo under `targets/` and return its relative path (R3)

## Phase 3: User Story 1, give a photo and get the appearances (P1)

**Goal**: a photo registers a named target and the search returns a ranked list of stored
appearances, with hits stored once.

**Independent test**: register one target from one photo against a database holding the
same person in two frames of two cameras, confirm both appearances with camera, time, path
and score, and confirm a second run leaves the hit count identical.

- [x] T011 [P] [US1] Write `tests/test_target_registration.py` covering: a photo with one face registers a target, a photo with no face exits 1 and creates nothing, a photo with two faces is refused, a repeated name adds a photo and creates no second target
- [x] T012 [P] [US1] Write `tests/test_target_search.py` covering: the ranking is best score first, a score under the threshold is not stored as a hit, a repeated search keeps the hit count, the best of several photos is the score used
- [x] T013 [US1] Implement `TargetPhotoReader` in `scanners/target_search.py`: read the file, detect faces with `FaceRecognizer.detect`, refuse zero and more than one face, return the embedding
- [x] T014 [US1] Implement `TargetRegistration` in `scanners/target_search.py`: resolve or create the target by name, store the photo file, store the photo row
- [x] T015 [US1] Implement `TargetComparison` in `scanners/target_search.py`: compare each stored face against each target photo with `CosineSimilarity.of`, keep the maximum, rank, and mark the linear scan with a `ponytail:` comment naming the pgvector upgrade path
- [x] T016 [US1] Implement `TargetSearch` in `scanners/target_search.py`: apply the camera and time filters, compare, write the hits above the threshold, return the ranked appearances
- [x] T017 [US1] Add `TargetRankingReport` to `scanners/reports.py`, one line per appearance with score, person, camera, time and frame path
- [x] T018 [US1] Build the `search` group in `main.py` with `person` and `appearance`, moving the existing flags to `search appearance`
- [x] T019 [US1] Add the `person` options in `main.py`: `--image` repeatable, `--name`, `--target-id`, `--camera-id`, `--since`, `--until`, and the "no target and no photo means every target" rule
- [x] T020 [US1] Wire the new commands into `TaskFactory` and the dispatch table in `main.py`, and map the new refusals to exit 1
- [x] T021 [US1] Extend `tests/test_cli_exit.py` for the renamed `search appearance` and for the new exit codes of `search person`
- [x] T022 [US1] Extend `tests/test_report_output.py` for the ranking lines and the empty result line

## Phase 4: User Story 2, the target gets a name in the report (P2)

**Goal**: an unlabeled person takes the target name, a manual label survives, and the face
report shows the match.

**Independent test**: label one person by hand and let a target match it; the manual label
survives. Let a target match an unlabeled person; the name appears in both reports.

- [x] T023 [P] [US2] Write `tests/test_target_label.py` covering: an empty label takes the target name, a manual label is untouched, two targets matching one person leave the first name and both hits
- [x] T024 [US2] Call `PersonRepository.name_if_empty` from `TargetSearch` for every person of a stored hit
- [x] T025 [US2] Add the target line to `PersonReport` in `scanners/reports.py`, naming the target and the score for each person that has a hit
- [x] T026 [US2] Extend `tests/test_report_output.py` for the new `report faces` line

## Phase 5: User Story 3, look at the cameras now, on request (P3)

**Goal**: `--live` captures through the existing face scan path before answering, gated by
`targets.allowed_cidrs`, and never runs by default.

**Independent test**: without `--live` the log shows zero network calls; with `--live`
against one lab camera showing the target, the appearance is listed and stored; one address
outside the list stops the run with the address named.

- [x] T027 [P] [US3] Write `tests/test_target_live_gate.py` covering: no camera contacted without `--live`, the wide live run refuses an address outside the list before any packet, the run is recorded as a `scan_run` of kind `faces`
- [x] T028 [US3] Implement `SearchPersonCommand` in `scanners/reports.py`: run the face scan first when `--live` is set, then the stored search, then the report
- [x] T029 [US3] Wire `--live` through `TaskFactory` in `main.py`
- [x] T030 [US3] Extend `specs/002-person-search/contracts/cli.md` with the final `--live` behavior if the implementation settles any detail it left open

## Phase 6: User Story 4, undo a wrong registration (P4)

**Goal**: `--forget` removes the target, its photos, its files and its hits, and clears only
the label that equals the target name.

**Independent test**: register a target, run the search, remove the target; the target, its
photos and its hits are gone, the label written by the target is cleared, a manual label and
every face, frame and embedding stay.

- [x] T031 [P] [US4] Write `tests/test_target_removal.py` covering: removal deletes target, photos and hits, clears only the matching label, preserves a manual label, preserves every face and frame, and completes when a photo file is already missing
- [x] T032 [US4] Implement `TargetRemoval` in `scanners/target_search.py`: one transaction for the rows, then the file removal, then the label cleanup
- [x] T033 [US4] Add `--forget N` to `main.py` with the mutual exclusion against `--image`, `--target-id`, `--live`, `--camera-id`, `--since` and `--until`, exiting 2 when combined
- [x] T034 [US4] Extend `tests/test_cli_exit.py` for the `--forget` combinations

## Phase 7: Polish and cross-cutting

- [x] T035 [P] Update the `search` section of `README.md` for the group, the two commands and the placeholder rule
- [x] T036 [P] Add the one-line pointer in `specs/001-camera-monitoring-pipeline/contracts/cli.md` saying the `search` group changed in `002-person-search`
- [x] T037 Run the whole gate: `uv run pytest -q` and `uv run ruff check .`, and fix everything they flag
- [x] T038 Run the quickstart steps 1 to 9 against the lab and paste the raw output of each into the front report
- [x] T039 Confirm the log has no credential, no reference photo path and no embedding value at either level
- [x] T040 Review the diff in the order of principle III (correctness, security, reliability, readability, style) before the PR

## Dependencies

```text
Phase 1 -> Phase 2 -> Phase 3 (US1) -> Phase 4 (US2)
                            |-> Phase 5 (US3)
                            |-> Phase 6 (US4)
Phase 4, 5, 6 -> Phase 7
```

- US1 is the MVP: it alone answers the request.
- US2, US3 and US4 depend on US1 because they extend the search it builds. They are
  independent of each other.
- T013 to T016 are ordered: the photo reader feeds the registration, which feeds the
  comparison, which feeds the search.

## Parallel execution examples

```text
Round A (after Phase 2): T011 and T012 (two test files, no shared code)
Round B (after US1):     T023, T027 and T031 (three independent test files)
Round C (Phase 7):       T035 and T036 (two documents)
```

## Suggested MVP

User Story 1 plus the Phase 2 foundation. It delivers the whole answer for a stored
database, and the other three stories are increments on top of it.
