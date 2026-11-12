# Research: Person Search

**Feature**: `specs/002-person-search/spec.md`
**Plan**: `specs/002-person-search/plan.md`
**Decisions**: `docs/decisions/2026-11-12-busca-pessoa-especifica.md` (D47 to D67)
**Created**: 2026-11-12

Every item below was checked against the repository at `/Users/iklo/shodan_rtsp`, not
assumed. Where a value or a behavior has no measurement, it says so.

---

## R1: What compares a target photo against a stored face

**Decision**: reuse `CosineSimilarity.of` (`scanners/face_recognizer.py:91-110`) and write
the ranking in a new class, `TargetComparison`. Do not call
`FaceRecognizer.match_against`.

**Rationale**: `match_against` (`scanners/face_recognizer.py:135-159`) filters every pair
below `face.match_threshold` and returns only the faces that pass. The target search needs
the opposite: every similarity, so the answer can be ranked and so a value just under the
threshold is still visible as the runner up. Reusing the metric class keeps one definition
of similarity, which is what D44 and D45 bought.

**Alternatives considered**: a second threshold parameter on `match_against`. Rejected
because one method would then mean two different scores depending on the caller, which is
the confusion D45 closed. A new metric implementation: rejected, because the metric already
exists and a second one would be two truths about the same vector.

**Cost**: one pass over `face` rows for each target photo. At lab scale, a linear scan in
Python. Marked in code with a `ponytail:` comment naming the ceiling and the pgvector
upgrade path, matching the existing matcher comment.

---

## R2: Reading the reference photo, and what a photo with two faces means

**Decision**: read with `cv2.imread`, detect with `FaceRecognizer.detect`, and refuse the
photo when it holds zero faces or more than one face. Refusal is a named exception, exit 1,
and no target row.

**Rationale**: zero faces cannot produce an embedding at all. For more than one face, the
pipeline would have to guess which one is the target, and the wrong guess registers the
wrong person, which then writes that persons name into person labels (D63). Refusing is the
only outcome that cannot silently do harm. `DetectedFace.embedding` is already the raw
vector, so no extra model call is needed.

**Alternatives chosen against**: taking the largest face. It is one line and would work most
of the time, but the failure is silent and the damage is a wrong name on a person. The spec
lists "a reference photo that holds two faces" as an edge case, and this is the answer.

**Unverified**: the exact behavior of `cv2.imread` on a truncated JPEG. It returns `None` in
the common case, and `None` is refused like an unreadable file. The lab run confirms it.

---

## R3: Where the reference photo is stored

**Decision**: under `frames.root_path`, in a `targets/` directory, one subdirectory per
target name, with the original file bytes copied and a counter for a repeated name. The
database holds the path relative to the root, like every frame (D62).

**Rationale**: `FrameStore.write` (`scanners/frames.py:39-51`) already owns the root and the
relative path convention, but it takes a camera id and a `FrameSource`, and it re-encodes
through `cv2.imencode`. A target photo has no camera, and re-encoding a JPEG would change
the evidence. The lazy path is one new method on `FrameStore` that copies bytes, reusing the
root handling and the counter idea already in `_relative_path`.

**Alternatives considered**: a second store class. Rejected because the root, the relative
path and the mkdir behavior would be duplicated. Keeping a base64 blob in the database:
rejected by D17 for the same reason it was rejected for frames.

---

## R4: How the live pass runs, and what gates it

**Decision**: the live pass instantiates the existing `FaceScanTask` with the same
`FaceScanDeps` the `scan faces` command builds, calls `scan_frames()`, and then runs the
stored search. No capture code is written.

**Rationale**: `FaceScanTask.scan_frames` (`scanners/face_task.py:134-155`) already does the
whole job: it queues the cameras, gates the wide run with
`TargetGate(...).require_reachable(...)` when no camera id was named, starts a `scan_run` of
kind `faces`, captures, stores and clusters, then closes the run. That is exactly D56 and
D59. Writing a second capture path would duplicate the gate and the run record, which is
where a reach bug would hide.

**Verified in the code**: the gate is `scanners/task.py:235-252` (`require_reachable`), and
it names every address outside the declared list, not only the first one. The refusal type
is `TargetOutsideScopeError`, already mapped to exit 1 in `main.py:49-56`.

**Cost**: with `--live`, a wide run reaches every stored camera holding a frame, at the
existing RTSP timeout of 8 s per attempt. That is the cost the operator accepted by asking
for the live pass explicitly (D61).

---

## R5: Where the verification threshold lives, and its starting value

**Decision**: a new config section, `person_search`, with `match_threshold: float`. The
value ships at the same number the grouping key ships at today, `0.5`, and the comment
labels it `PLACEHOLDER: not measured on this data` exactly as `face.match_threshold` does
(`scanners/config.py:78-84`).

**Rationale**: no measurement of a verification threshold on this data exists, so no number
can be derived from data. Copying the existing unmeasured value is the honest move: both
keys are guesses, both are labelled, and the operator measures them in the same lab step.
Inventing a different-looking number would imply a derivation that did not happen.

**Alternatives considered**: reusing `face.match_threshold` directly (rejected by D51);
refusing to run until measured (rejected by D60).

---

## R6: Hit identity, and what a repeated search writes

**Decision**: `UNIQUE (target_id, face_id)` on `target_hit`. On a repeated search, an
existing hit keeps its row, and its score is raised only if the new score is higher.

**Rationale**: the hit is the record that this face is this target, not a log of each run.
A row per run would grow without a bound the operator did not ask for, and the appearance
time is already carried by the frame the hit points at. Keeping the maximum score is the
only update that cannot lose information: a later, worse reference photo cannot lower the
evidence that the person is there.

**Alternatives considered**: one row per run (more data, same answer); update the score
unconditionally (loses the best match when a photo is removed by a later registration).

---

## R7: How the reports change

**Decision**: a new renderer, `TargetRankingReport`, in `scanners/reports.py`, sharing
`StdoutLines`, `Stamp` and `ColumnWidths`. `PersonReport` gains one line per person that
matches a target.

**Rationale**: `scanners/reports.py` already holds every renderer and the shared width
calculation (`ColumnWidths.of_appearances`, `reports.py:129-137`). A new module would
duplicate the column logic. The ranking line needs: time, target, person, camera, frame
path, score. The `report faces` line needs: target and score.

**Verified**: `PersonReport.render` (`reports.py:163-178`) prints a headline per person and
one line per camera, so the target line fits beside the headline without changing the
existing output format for persons.

---

## R8: The command group change and its blast radius

**Decision**: `search` becomes a group with `person` and `appearance`. `search appearance`
keeps the four flags the current `search` has. The contract file is updated in the same
front, and the README section for `search` is updated in the same front.

**Rationale**: `CommandParser._search` (`main.py:276-294`) adds `search` as a leaf command, so
a subcommand is impossible without the group. The dispatch table keys on
`group command` (`main.py:169-185`), and `search` alone would become the key `search`, which
no longer exists once the group requires a subcommand. Renaming the old command to
`search appearance` keeps both questions under one verb and makes each flag set
unambiguous.

**Blast radius, checked**:
- `main.py`: parser, dispatch table, `TaskFactory`.
- `tests/test_cli_exit.py`: asserts exit codes through the parser, so it covers the rename.
- `tests/test_report_output.py`: asserts the rendered lines of `SearchReport`.
- `README.md`: documents the commands; the search section is part of this front.
- `specs/001-camera-monitoring-pipeline/contracts/cli.md`: the binding contract of the
  previous batch. This feature carries its own `contracts/cli.md`, and the previous one is
  left as the record of that batch, with a one-line note pointing at the new file.

**Not checked**: no script in the repository or in the operators shell history is known to
call `search` programmatically. There is no CI job and no container entrypoint that passes
`search` as an argument, so the rename breaks only the documented command name.

---

## R9: What the tests run on

**Decision**: the model and repository tests run on the sqlite fixture already in
`tests/conftest.py`; the migration round trip and the live gate test run against the lab
PostgreSQL.

**Rationale**: `models/base.py` defines `EMBEDDING` as a PostgreSQL array with a JSON
variant for sqlite, and `Face` skips its `array_length` check on sqlite, so a new table using
the same type needs no new fixture. `test_migrations.py` already exists and runs the real
migration chain.

**Verified**: `tests/conftest.py:1-40` states the database fake is shared by every model
test and that the seven tables are created on sqlite.

---

## Resolved unknowns

None remain that block the design. Two items are unverified and are marked as such:
the exact `cv2.imread` behavior on a truncated file (R2), and the measured value of the
verification threshold, which cannot exist before the lab pair set runs (R5).
