# Decisions: search for a specific person across cameras

Date: 2026-11-12
Repo: `/Users/iklo/shodan_rtsp`
Method: grill session, six rounds, 21 decisions (D47 to D67). Numbering continues
`docs/decisions/2026-11-11-shodan-rtsp-prod-ready.md`, because this batch extends the
pipeline that file settled.
Status: settled. Ready for `spec-driven` to pick the planning tier.

Goal of the batch: answer one question the pipeline cannot answer today. Given a photo of
a specific person, list where and when that person appeared, across every stored frame and,
on request, across the live cameras.

What exists today that this builds on: `scan faces` detects faces, clusters them into an
anonymous `person`, and stores the 512-d embedding. `search` answers who appeared, where
and when by `person_id`. Nothing answers "this person from this photo", because a cluster
has no reference image and a person is anonymous by default (D28).

---

## Decisions

| # | Decision | Answer | Why | Depends on |
|---|----------|--------|-----|------------|
| D47 | What the target is | A reference photo, and also a `person_id` of an existing cluster | The photo is the only input that answers "who is this person". The `person_id` reuses the clustering that already exists, so both reading paths share one search. | D28, D44 |
| D48 | Where the search looks | Stored frames first, then the live cameras only when asked | The stored history is a local compare with no network, so it answers in seconds. A live pass costs one RTSP timeout per camera, so it is a separate, explicit step. | none |
| D49 | Is the target stored | Yes, a persistent target row with a name | A reference photo that is retyped on every search is lost work, and the name is what `report faces` can show. | D47 |
| D50 | Output shape | A ranking with the score, one line per appearance | The score is what lets the operator judge a hit near the threshold instead of trusting a yes or no. | D49 |
| D51 | Verification threshold | Its own key, `target.match_threshold`, measured on the same labelled pair set | A 1:N verification and a clustering step are different tasks with different error costs, so one value cannot serve both (D45). | D16, D44 |
| D52 | Command shape | `search` becomes a group with two commands: `search person --image PATH`, `--target-id N` and `--forget N` for targets, and `search appearance` for the existing who-appeared search, keeping its four flags | The `search` of today is one command with flags (`main.py:276-294`), so a subcommand needs the group. Keeping one verb and splitting the two questions makes each command unambiguous. The rename of `search` to `search appearance` is a contract change, recorded in `contracts/cli.md`. | D38 |
| D53 | Are hits stored | Yes, one `target_hit` row per target and face, with the score | A stored hit is the record of when the target appeared, and a repeated search does not have to rebuild it from scratch. | D49 |
| D54 | Removing a target | `search person --forget N` deletes the target, its photos and its hits | A wrong registration has to be undoable. Deleting the target does not delete a frame, a face or an embedding. | D49, D10 |
| D55 | How the target is created | The search itself creates it. `--name` is required, the name is unique, and a repeat with the same name adds photos to that target | One step instead of two commands, and the name is the identity key, so no duplicate target from a repeated run. | D49 |
| D56 | Live pass implementation | Same path as `scan faces`: capture, detect, store frame and face, cluster, then search | One capture path, already tested, and the live pass leaves history that the next search can use. | D48, D8 |
| D57 | Photos per target | Several. `--image` repeats, and the score is the largest similarity across the target photos | One bad photo would poison the target. Several absorb angle and light. | D49, D55 |
| D58 | Where a hit is visible | `search person` and `report faces`, which gains a line saying the person matches a target and which one | The operator already reads `report faces`. Making a second screen the only place hides the answer. | D50 |
| D59 | Reach of the live pass | The same gate as `scan check`: every camera is checked against `targets.allowed_cidrs` before any packet, and one address outside the list stops the whole run | This is the one search command that opens a stream to every stored camera, so it carries the strictest gate the project has. | D1, D18 |
| D60 | Threshold before measurement | A declared placeholder in the config, search runs | Blocks nothing today. The value is labelled unmeasured until the rig measures it (D45). | D51, D21 |
| D61 | Live pass default | Off. Only with `--live` | No camera is touched by a search the operator did not ask for. A typo in a search must not open streams. | D48, D59 |
| D62 | Reference photo on disk | Kept under the frame root with its path in the database, like every other frame | The photo that produced an embedding is evidence. Without it a wrong hit cannot be explained or remeasured. | D17, D49 |
| D63 | Label written on a hit | The target name is written into `person.label`, only when that label is empty | The report then carries a name. A manually typed label is never overwritten. This is an exception to D28, recorded in the risks below. | D28, D49 |
| D64 | What `--forget` does to the label | Clears `person.label` only where it equals the target name | Undo has to be complete for what the target itself wrote, and must not touch a name the operator typed. | D54, D63 |
| D65 | Filters on the search | `--camera-id`, `--since`, `--until`, the same three the `search` of today accepts | Nothing new to learn, and the answer can be narrowed to one camera or one period. | D52 |

---

## Assumptions made without asking

Each one follows from a decision above and is cheap to reverse. Listed so the operator can
object.

- Data model: `target` (id, name unique, created_at, updated_at), `target_photo`
  (target_id, path, embedding), `target_hit` (target_id, face_id, score, created_at), with
  `UNIQUE (target_id, face_id)` so a repeated search updates instead of duplicating. One
  new Alembic revision with a rollback path (D4, constitution 7).
- A reference photo with no detectable face is a real failure: exit 1 with the reason, no
  target created. Same for a file that cannot be read (contract exit codes).
- No `--image` and no `--target-id` means every registered target is searched against the
  stored faces. A `--target-id` that does not exist is exit 1.
- The compare is an O(n) scan over stored embeddings, with a `ponytail:` comment naming the
  ceiling and the pgvector upgrade path, exactly as the existing matcher already declares.
  No dependency is added.
- `--live` records a `scan_run` of kind `faces`, the same kind the existing scan writes. It
  does not invent a new scan kind.
- A stored hit is never deleted by a later search. Its score is updated to the highest
  value seen.
- `search person` prints the target name beside each line, and persons print as the existing
  contract does: `person <id>` or `person <id> (<label>)`.
- The contract file gains a `search person` section and the `report faces` sample gains the
  target line. A change to either is a breaking change like every other in that file.

---

## Open risks

1. **A new class of biometric data, for one identified person, kept without encryption
   (D62, D49).** The reference photo and its embeddings join the face embeddings already on
   disk. Risk 3 of the previous file grows from anonymous bystanders to a named individual.
2. **D28 said nothing labels a person automatically. D63 does.** The label is written by the
   pipeline now, under the condition that the label is empty. This is a recorded exception,
   not a silent one.
3. **D10 said keep everything forever. D54 deletes target, photos and hits.** The exception
   covers only rows this batch created, never a frame, a face or an embedding.
4. **Every photo search leaves a stored target (D55).** There is no one-shot mode, so a
   search the operator discards still adds a named target to the database.
5. **The live pass stores frames and faces of everyone in view (D56).** A search for one
   person writes biometrics of every other person the cameras saw.
6. **The verification threshold is a placeholder until the rig measures it (D60).** Until
   then the ranking can be wrong in both directions: a miss above the threshold and a false
   hit below it. Labelling it is the only control.
7. **`--forget` compares the label text (D64).** If the operator edits a label that the
   target wrote, the target name stays on that person after the target is gone.
8. **The compare cost is the number of stored faces times the number of target photos.**
   At lab scale it is a linear scan in seconds. It is silent when the table grows.

---

## Left undecided

- Whether D63 makes the "anonymous by default, manual label" rule of D28 obsolete, or a
  target label is a third kind of label. The writing is decided, the classification is not.
- Whether two targets that both hit one person are a case the report has to show.
- Any alert, notification or watch loop when a target appears: out of scope here.
- A vector index, a package release, and any cleanup job for hits: not decided.
- Normalization of the target name (case, spaces) beyond "trimmed and unique".

---

## Facts established during the session

Lookups run against the repository at `/Users/iklo/shodan_rtsp`, not decisions.

- `main.py` already exposes `search` with `--person-id`, `--camera-id`, `--since` and
  `--until`, and `report faces` with `--person-id` (`main.py:266-299`). `search` is a single
  command with flags, not a group, which is what forced D52 to name a rename.
- `scanners/face_recognizer.py` exposes `FaceRecognizer.detect`, `FaceRecognizer.match_against`
  and `CosineSimilarity` over the L2-normalized vector, so the verification reuse needs no
  new metric code.
- `scanners/face_task.py` already writes `face_frame`, `face` and `person`, and its merge
  rule is the one D35 settled, so D56 reuses a tested path.
- `scanners/reports.py` holds `PersonReport` and `SearchReport` with a shared `ColumnWidths`,
  so the new ranking and the `report faces` line extend existing renderers, not a new module.
- `specs/001-camera-monitoring-pipeline/contracts/cli.md` is the binding command surface
  (D38, D43), and it lists no command that searches by image.
- `models/` holds one module per entity (`person.py`, `face.py`, `frame.py`), and no target
  entity exists.
- The face config carries `face.match_threshold` as a labelled placeholder
  (`scanners/config.py:69-83`).
- The out of scope section of `specs/001-camera-monitoring-pipeline/spec.md:327-336` says
  "any automatic watchlist: people stay anonymous unless the operator labels one", which is
  the line D63 now moves.
