# Front 5 report: faces, people and the monitoring answer

Front 5 of D12, the last one: the face metric of D44, the person entity and its cluster of
D35, the two read-only reports of FR-027 and FR-028, and the threshold measurement of D16.
Tasks T060 to T074 of `specs/001-camera-monitoring-pipeline/tasks.md`.

Branch: `feat/schema-migrations`, on top of `65728db`. Every command below ran on
2026-11-11 (UTC), on this host, against the lab container `shodan_pg` (postgres 16,
`127.0.0.1:5440`) and the mock device on `127.0.0.1:8000` described in
`docs/front-4-rig.md`. Nothing here ran against a third-party host.

The frames this front reads are the ones the CVE front already stored, so the face path
was proved without a stream to open. Section 7 adds the stream, and section 8 says what
still is not proved.

## 1. Before and after

Before, at `HEAD` in a tree extracted with `git archive HEAD` and run with the repository
venv, so the comparison is the same interpreter and the same dependency set:

```
$ cd /tmp/front5-before && /Users/iklo/shodan_rtsp/.venv/bin/python -m pytest -q
ERROR tests/test_migrations.py::test_upgrade_from_zero_creates_every_table - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_second_upgrade_changes_nothing - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_cam_rows_move_into_the_new_schema - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_migration_rolls_back_and_keeps_the_old_rows - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_downgrade_base_returns_to_zero_tables - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
102 passed, 5 errors in 5.48s
```

The five errors are the database tests, and they are an artefact of the extracted tree:
`config.yaml` is git-ignored and holds credentials, so the archive has none. Adding 102 and
5 gives the 107 the suite reported at the end of Front 4.

After, in the repository:

```
$ .venv/bin/python -m pytest -q
140 passed in 8.68s

$ .venv/bin/ruff check .
All checks passed!
```

The 33 new tests are the seven modules of this front:

| Module | Tests | What it holds |
| --- | --- | --- |
| `tests/test_face_metric.py` | 4 | the cosine over the normalized vector, and the ordering the cluster reads |
| `tests/test_person_cluster.py` | 9 | one person per face, the frame read either way, the scope gate, the disabled scan, and the frames of one capture |
| `tests/test_person_merge.py` | 3 | open a person, join one, merge two without losing a face or a frame |
| `tests/test_report_output.py` | 7 | the two output shapes, the padding included, and the same two reports over stored rows |
| `tests/test_person_anonymous.py` | 2 | a person prints as an id, and the label stays on the row |
| `tests/test_threshold_measure.py` | 5 | the measurement, the two groups, and the four refusals of the pair set |
| `tests/test_cli_exit.py` | 3 | a real `main()`: exit 1 on a refusal, exit 2 on a bad command line |

`tests/conftest.py` grew the shared lab for these modules: `FaceLab` (a stored camera, the
frames it holds, and the rows a run writes), `CapturedLines` (a writer that keeps the lines
instead of printing them) and the `face_lab` fixture.

## 2. The metric, and the dimension (D44)

The recognition model of `buffalo_l` emits 512 values, and the identity of a face is the
**direction** of that vector, not its length. `FaceRecognizer.match_against` scores every
stored face with the cosine similarity of the L2-normalized vectors and returns the ones at
or above the threshold, closest first.

The regression test pins the difference between a cosine and a distance. Two vectors that
point the same way but differ in length are 6.5 apart as points and identical as
directions:

```python
unit = Vectors.unit(0.0)
longer = Vectors.scaled(0.0, _SCALE)

# A distance metric separates these two: they sit 6.5 apart, well past the
# threshold. The cosine does not, because they point the same way.
assert float(np.linalg.norm(longer - unit)) > _THRESHOLD
assert CosineSimilarity.of(unit, longer) == pytest.approx(1.0)
```

The lab confirms the same property on real vectors. The two frames of the same person in
section 4 hold embeddings of norm 25.411 and cosine 0.9949, and the stored value is the raw
vector, not the normalized one:

```
face 1 person 1 frame 2 231/20261111T154504Z-cve.jpg
face 2 person 1 frame 3 231/20261111T154514Z-cve.jpg
face 3 person 2 frame 4 231/20261111T154523Z-cve.jpg
cosine face1-face2 (same person): 0.9949
cosine face1-face3 (different):   0.0348
norm of raw face1 embedding:      25.411
dim: 512
```

## 3. The threshold, measured (D16, SC-010)

The pair set is one directory per identity, two images each, under a git-ignored path
(`logs/faces`, because `lab/` is committed and a real photo of a real person has no place
in the repository). The two identities are public sample images: a face cropped out of the
group photo that ships with insightface, and the astronaut sample that ships with scikit
image. For each identity the second image is the first one resized to 480 wide and
re-encoded at JPEG quality 70, so the two images of one person are genuinely different
bytes and not the same file twice.

```
$ .venv/bin/python main.py --config config.yaml measure threshold --pairs logs/faces
same identity        pairs 2   min 0.978  mean 0.986  max 0.993
different identity   pairs 4   min 0.039  mean 0.042  max 0.044
separation           0.934 between the largest different and the smallest same
```

Re-run at 12:48 UTC, same numbers, exit code 0. The output is the whole truth about the set:
six pairs, and a gap between 0.044 and 0.978.

The refusals work too, and they are the exit code of section 6. With a directory holding
two flat grey frames, so the detector finds no face to label:

```
$ .venv/bin/python main.py --config config.yaml measure threshold --pairs logs/faces
2026-11-11 12:48:15,229 ERROR logs/faces/nobody/01.jpg holds 0 faces, and a labelled image holds exactly 1: a second face makes the label ambiguous
exit code: 1
```

**The placeholder is still a placeholder.** `face.match_threshold` is 0.5 in
`scanners/config.py` and in `config.yaml.example`, and both say so. The measured separation
of 0.934 is real, and the placeholder sits inside the gap, but a set of two identities says
nothing about the pairs that will actually be confused. Replacing the value is an open
decision, recorded in section 9.

## 4. One face, two frames, one person (FR-022)

The lab device served three frames through the one path it has, the CVE read of the mock:
two different images of the same face, then one image of another person. The three CVE runs
and the face run, verbatim:

```
$ .venv/bin/python main.py -v --config config.yaml scan cve --camera-id 231
2026-11-11 12:45:04,793 INFO Verbose mode enabled
2026-11-11 12:45:04,797 INFO Starting the CVE task
2026-11-11 12:45:04,890 INFO 127.0.0.1:8000 matches 1 CVE(s)
2026-11-11 12:45:04,901 INFO CVE read GET http://127.0.0.1:8000/onvif-http/snapshot?auth=YWRtaW46MTEK
2026-11-11 12:45:04,928 INFO Executors: finished the CVE task
```

The same command ran twice more, at 12:45:14 with the second image of the same person and at
12:45:23 with the other person, so the camera holds three frames:

```
$ ls logs/frames/231/
20261111T145832Z-cve.jpg     # the flat frame of the Front 4 run, no face in it
20261111T154504Z-cve.jpg
20261111T154514Z-cve.jpg
20261111T154523Z-cve.jpg
```

Then the face scan:

```
$ .venv/bin/python main.py -v --config config.yaml scan faces --camera-id 231
2026-11-11 12:45:28,576 INFO Starting the face scan
2026-11-11 12:45:33,379 DEBUG face 1 joined person 1
2026-11-11 12:45:33,708 DEBUG face 2 joined person 1
2026-11-11 12:45:34,103 DEBUG face 3 joined person 2
2026-11-11 12:45:34,104 INFO 127.0.0.1:8000 holds 3 face(s)
2026-11-11 12:45:34,111 INFO Executors: finished the face scan with 3 face(s)
```

Two faces of one person in two frames of one camera became one person, and the third became
another. The rows, read straight out of the database:

```
persons: [(1, None), (2, None)]
faces per person: [(1, 2), (2, 1)]
runs: [(13, 'faces', '127.0.0.1', 1), (12, 'cve', '127.0.0.1', 1)]
```

Both people carry no label, which is the point of D28. The merge path is proved by
`tests/test_person_merge.py` rather than by the lab, because the lab has no way to make one
face match two people on demand: the test seeds two people and a face that matches both,
and asserts that the older survives, that every face points at it, and that no frame is
lost.

## 5. The monitoring answer (FR-027, FR-028)

```
$ .venv/bin/python main.py --config config.yaml report faces
person 1  faces 2  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T15:45:14Z
  camera 127.0.0.1:8000  frames 2  frame cve
person 2  faces 1  first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 1  frame cve

$ .venv/bin/python main.py --config config.yaml search
2026-11-11T15:45:04Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:14Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:23Z  person 2  camera 127.0.0.1:8000  frame cve

$ .venv/bin/python main.py --config config.yaml search --person-id 1
2026-11-11T15:45:04Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:14Z  person 1  camera 127.0.0.1:8000  frame cve

$ .venv/bin/python main.py --config config.yaml report faces --person-id 2
person 2  faces 1  first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 1  frame cve
```

Both reports read through `PersonReader`, which has no write method at all, so a report
cannot change a person. The `search` filters are built as one `AppearanceFilters` value and
handed to the reader; no SQL is assembled from strings anywhere in the path.

A label set on the row by hand is data the reports carry, so both of them print it beside
the id. Same lab, after the RTSP runs of section 7:

```
$ docker exec shodan_pg psql -U scanner -d cameras -c "UPDATE person SET label = 'lab-demo' WHERE id = 2;"
UPDATE 1

$ .venv/bin/python main.py --config config.yaml report faces
person 1             faces 13  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T15:57:46Z
  camera 127.0.0.1:8000  frames 2  frame cve
  camera 127.0.0.1:8554  frames 11  frame rtsp
person 2 (lab-demo)  faces 1   first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 1  frame cve

$ .venv/bin/python main.py --config config.yaml search
2026-11-11T15:45:04Z  person 1             camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:14Z  person 1             camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:23Z  person 2 (lab-demo)  camera 127.0.0.1:8000  frame cve
2026-11-11T15:52:06Z  person 1             camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:26Z  person 1             camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:31Z  person 1             camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:36Z  person 1             camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:41Z  person 1             camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:46Z  person 1             camera 127.0.0.1:8554  frame rtsp
```

The label widens the person column in both reports, because the width is the widest cell
the report is about to print and not a fixed number. The label was set back to `NULL` after
this run, so the lab keeps its two persons unlabelled, which is what the clustering opened.
`tests/test_person_anonymous.py` covers the three cases: no label, a label, and the label
still on the row.

## 6. The exit code of a refusal

`contracts/cli.md` fixes three codes: 0 for a command that completed, 1 for a run that
could not do its job, 2 for a command line that is wrong. `main.py` now carries the list of
refusals it converts into exit 1, and the lab shows the difference between that and an
argparse error:

```
$ .venv/bin/python main.py --config config.yaml measure threshold --pairs logs/faces
2026-11-11 12:48:15,229 ERROR logs/faces/nobody/01.jpg holds 0 faces, and a labelled image holds exactly 1: a second face makes the label ambiguous
exit code: 1
```

`tests/test_cli_exit.py` runs the real `main()` three times from a temporary directory, with
a minimal config and a real command line, and asserts the three codes: 1 for a pair set that
is not a directory, 1 for a `--since` that is not a timestamp, and 2 for a command line with
no command. A refusal is a value the operator can fix, so it is reported as the message the
exception carries instead of a traceback; anything else keeps its traceback, because that is
a bug and hiding it would cost more than it saves.

## 7. The RTSP capture path, and the defect it exposed

Sections 4 and 5 read frames the CVE path had stored. The other half of `scan faces`, the
camera that holds no frame at all, needs a stream, so the lab grew one: `mediamtx` v1.11.3
serving the path `h264/ch1/main/av_stream` on `127.0.0.1:8554`, with `ffmpeg` publishing the
same photo on a loop. `lab/mediamtx.yml` is the lab config (mediamtx with no config file
serves only declared paths), and the camera row is the one `scan check` would store for that
address.

The first run failed, and the failure is the point:

```
$ .venv/bin/python main.py -v --config config.yaml scan faces --camera-id 232
...
sqlalchemy.exc.IntegrityError: (psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "uq_face_frame_path"
DETAIL:  Key (path)=(232/20261111T155206Z-rtsp.jpg) already exists.
```

Two defects, one shape. The scan captured every `frames_per_scan` frame first and stored them
afterwards, so all the writes of a run landed in the same second. `FrameStore` names a file
`<camera_id>/<YYYYMMDDTHHMMSSZ>-<source>.jpg`, to the second, and `UNIQUE (path)` refuses the
second row: the run died on its second frame, leaving one frame on disk, one row in the table
and one `scan_run` never closed.

The timestamp was wrong too, and quietly. `captured_at` was the instant of the store and not
of the capture, so five sightings spread over 8 s were recorded as five at the same instant.
Both come from the same decoupling, and the fix has the same shape:

- `FaceScanTask._captured_frames` is a generator now: each frame is handed over as it is read,
  so the caller stores it before the next capture, and the row and the file name carry the
  instant of the capture.
- `FrameStore._relative_path` adds a counter suffix when the plain name is already on disk
  (`...-1.jpg`), because a name is not free to reuse while `UNIQUE (path)` holds. With
  `frame_interval: 0`, which the config allows, interleaving alone would still collide.

`tests/test_person_cluster.py::test_each_frame_of_one_capture_is_stored_before_the_next_is_read`
fails on the old code with the same defect in sqlite (`UNIQUE constraint failed:
face_frame.path`) and pins both halves: three captured frames, three distinct paths, and the
count of stored rows read at each capture, `[0, 1, 2]`, so every frame was stored before the
next one was read.

After the fix, the same command against the live stream:

```
$ .venv/bin/python main.py -v --config config.yaml scan faces --camera-id 232
2026-11-11 12:57:41,019 INFO [!] 127.0.0.1:8554 answered
2026-11-11 12:57:41,408 DEBUG face 8 joined person 1
2026-11-11 12:57:46,273 INFO 127.0.0.1:8554 holds 5 face(s)
2026-11-11 12:57:46,282 INFO Executors: finished the face scan with 5 face(s)
exit code: 0

$ ls logs/frames/232/
20261111T155206Z-rtsp.jpg     # the single frame of the failed run
20261111T155726Z-rtsp.jpg
20261111T155731Z-rtsp.jpg
20261111T155736Z-rtsp.jpg
20261111T155741Z-rtsp.jpg
20261111T155746Z-rtsp.jpg
```

Five frames, five names, five seconds apart, five faces, one person. The spacing is
`frame_interval` plus the time one capture takes (about 3 s here, opening the stream and
decoding a keyframe), so the names sit further apart than the config value alone suggests.

A second run read the five frames the first one had stored, which is D33 over files this path
wrote, and it also walked the unreadable branch: one file was moved aside for that run, so the
log carries

```
2026-11-11 12:57:55,613 WARNING the frame 232/20261111T155206Z-rtsp.jpg is not readable, skipping it
```

and the run continued over the five readable frames. The file was put back afterwards.

The monitoring answer now shows the sightings at the instants they were captured:

```
$ .venv/bin/python main.py --config config.yaml report faces
person 1  faces 13  first seen 2026-11-11T15:45:04Z  last seen 2026-11-11T15:57:46Z
  camera 127.0.0.1:8000  frames 2  frame cve
  camera 127.0.0.1:8554  frames 11  frame rtsp
person 2  faces 1   first seen 2026-11-11T15:45:23Z  last seen 2026-11-11T15:45:23Z
  camera 127.0.0.1:8000  frames 1  frame cve

$ .venv/bin/python main.py --config config.yaml search --person-id 1
2026-11-11T15:45:04Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:45:14Z  person 1  camera 127.0.0.1:8000  frame cve
2026-11-11T15:52:06Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:26Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:31Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:36Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:41Z  person 1  camera 127.0.0.1:8554  frame rtsp
2026-11-11T15:57:46Z  person 1  camera 127.0.0.1:8554  frame rtsp
```

One `person` row spans both cameras, one read through a CVE class and one over RTSP, which is
FR-022 and FR-027 in a single answer. The `search` lines are five seconds apart because that
is when the frames were captured, which is the half of the fix no error message would have
shown.

Two smaller things this run corrected. `scanners/config.py` said `frames_per_scan: 0`
disables multi-frame and keeps a single frame; it does not, the loop runs zero times and the
camera is never read, and the comment says that now. And `quickstart.md` step 4 published
`lab/face.mp4`, which the repository does not ship; it now publishes a still image, with the
two options the run needed (`scale=trunc(iw/2)*2` for libx264, `-loop 1 -re` because
`-stream_loop` does not loop an image input).

## 8. What is not proved

- **No emulated firmware.** The device is still the mock of `docs/front-4-rig.md`. It
  proves the client, not Hikvision code. The face path inherited that: it reads the frame
  the CVE path stored, and the frame the RTSP path stored.
- **The threshold is measured on two identities.** Six pairs. It shows the tool works and
  the two groups separate; it does not settle a production value.
- **Nothing sets a label automatically.** A person the clustering opens is an id in both
  reports. The rendering of a label is implemented and was run against the lab (section 5),
  but the row that carried it was labelled by hand: no code in this batch writes
  `person.label`, so the id remains the only name the pipeline itself can give a person.
- **The quickstart was not run end to end on this machine.** The lab database carries the
  229 rows that revision `0002` copied out of the legacy `cam` table (`docs/front-1-report.md`
  section 5), so a wide `scan check` or `scan faces` is refused by the gate, which is FR-001
  working. Every run in this report names its camera, and the gate itself is covered by
  `tests/test_person_cluster.py` and by the Front 4 lab run. Proving that refusal live would
  mean aiming a credential attempt at third-party cameras if the gate had a bug, which is not
  a test worth running.

## 9. Deviations and open decisions

| # | What | Where | Why |
| --- | --- | --- | --- |
| D-22 | `scan faces` also writes one `scan_run` of kind `faces` | `contracts/cli.md` lists `face_frame`, `face`, `person` | the run has to be recorded like every other run, and `scan_run.kind` already had a `faces` member; the contract line is the incomplete one |
| D-23 | `main.py` carries `_REFUSALS` and exits 1 | `contracts/cli.md` fixes the codes, not the list | the contract names the codes and four examples; which exceptions are refusals is an implementation choice, and the list is now in one place |
| D-24 | `lab/mock_camera.py` gained `--image` | `lab/mock_camera.py` | the synthetic frame has no face in it, so the face path could not be run against the lab at all without a way to serve a real photo |
| D-25 | The lab pair set lives in `logs/faces`, not `lab/faces` | `quickstart.md` step 7 | `lab/` is committed; a photo of a real person must not be |
| D-26 | Three dead config keys deleted: `min_faces_per_frame`, `max_faces_per_camera`, `save_frames` | `scanners/config.py`, `config.yaml.example` | read by nothing; `max_faces_per_camera` also contradicted the unlimited retention of D10 |
| D-27 | The `insightface` comment in `pyproject.toml` says 512-d, not 128-d | `pyproject.toml` | the model emits 512 values (D44) |
| D-28 | The frame file name gains a counter suffix when the plain name is taken, and `scan faces` stores each frame as it is captured | R8 fixes the name as `<camera_id>/<YYYYMMDDTHHMMSSZ>-<source>.jpg` | the second resolution cannot name two frames of one second, and `UNIQUE (path)` refused the second row in the lab; the plain name stays the first name of a second, so the R8 layout still holds for the ordinary case |
| D-29 | `lab/mediamtx.yml` added, and the lab RTSP rig documented with it | `quickstart.md` step 4 started `mediamtx` with no config | mediamtx with no config file serves only declared paths, and the path a camera URL carries is not known in advance |
| D-30 | `quickstart.md` step 4 publishes a still image, not `lab/face.mp4` | the same step named a file the repository does not ship | the lab needs a stream, not a video: a looping photo is enough for `scan faces`, and it is a file the repo already has on the machine |
| D-31 | Both reports print a person as `person <id> (<label>)` when the row carries a label | `contracts/cli.md` printed only `person <id>` and left the labelled case open | the label is data the row holds, so a report that dropped it would print less than it read; the unlabelled form is unchanged, so the printed shape of today is still the printed shape |

Open decisions, for the user and not for this report:

1. **The threshold value.** The measurement exists (section 3) and the placeholder 0.5 is
   still in the config. Replace it with a measured value, or widen the pair set first?
2. **The trace of the failed run.** The lab database held the `scan_run` the crash left open
   (kind `faces`, no `finished_at`) and the single frame row of that run, both evidence of
   the defect in section 7. The run was closed at the instant of its own frame row
   (`2026-11-11T15:52:06.548944+00`, the last thing it did) and the frame row was kept, so no
   run of the lab is left open and the defect keeps its record. The schema has no column for
   a run that ended by failing, so a closed run that crashed and a closed run that finished
   read the same: decide whether a `status` column is worth adding.
