# Front 3 report: identification

Front 3 of D12: the brand signature data file, the rewritten identification module, the raw
banner and the interpreted identity on the camera row, the brand credential set ahead of
the generic wordlists, the target gate over stored cameras, and `scan check` on the command
line. Tasks T036 to T046 of `specs/001-camera-monitoring-pipeline/tasks.md`.

Branch: `feat/schema-migrations`, on top of `4770b1f`. Every command below ran on
2026-11-11 (UTC), on this host, against the lab container `shodan_pg` (postgres 16,
`127.0.0.1:5440`) and the lab rig on `127.0.0.1` described in section 3. Nothing here ran
against a third-party host.

## 1. Before and after

Before, measured at `HEAD` in a tree extracted with `git archive HEAD` and run with the
repository venv, so the comparison is the same interpreter and the same dependency set:

```
$ cd /tmp/front3-before && /Users/iklo/shodan_rtsp/.venv/bin/python -m pytest -q
ERROR tests/test_migrations.py::test_upgrade_from_zero_creates_every_table - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_second_upgrade_changes_nothing - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_cam_rows_move_into_the_new_schema - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_migration_rolls_back_and_keeps_the_old_rows - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_downgrade_base_returns_to_zero_tables - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
46 passed, 5 errors in 2.30s
```

The five errors are the database tests, and they are an artefact of the extracted tree, not a
result: `config.yaml` is git-ignored and holds credentials, so the archive has none and the
tests that need the DSN cannot reach the lab. Adding 46 and 5 gives the 51 the suite reports
in the repository, which is where Front 2 ended.

After, in the repository:

```
$ .venv/bin/python -m pytest tests/ -q
79 passed in 4.41s

$ ruff check .
All checks passed!
```

28 tests are new. Per file, from `pytest --collect-only`:

| File | At HEAD | Now |
|---|---|---|
| `tests/test_refactor.py` | 20 | 27 |
| `tests/test_brand_detection.py` | absent | 6 |
| `tests/test_brand_unknown.py` | absent | 4 |
| `tests/test_brands_file.py` | absent | 7 |
| `tests/test_version_range.py` | absent | 4 |
| the other six files | 31 | 31 |

## 2. What changed

| File | Change |
|---|---|
| `brands.yaml` | new. 26 brands as data, so a new brand is a line and no release (D27) |
| `scanners/brand_probe.py` | rewritten, 533 to 304 lines |
| `scanners/vuln_probe.py` | the matched version range travels with the finding |
| `scanners/config.py` | `targets:` section replaces `shodan.allowed_cidrs` |
| `scanners/task.py` | identification wired into nmap and Shodan, `TargetGate`, `scan check` |
| `models/managers.py` | `find_by_id` and `record_identity` |
| `main.py` | `scan check` registered, `TaskFactory` builds the identifier |
| `config.yaml.example` | `targets:` section, `allowed_cidrs` out of `shodan` |
| `specs/.../contracts/cli.md` | the gate over stored cameras written down |
| `specs/.../quickstart.md` | `targets.allowed_cidrs` in the config step |

The diff, tracked files against `HEAD`:

```
 config.yaml.example                                |  15 +-
 main.py                                            |  50 +-
 models/managers.py                                 |  23 +
 scanners/brand_probe.py                            | 727 +++++++--------------
 scanners/config.py                                 |  14 +-
 scanners/task.py                                   | 327 ++++++---
 scanners/vuln_probe.py                             |  40 +-
 specs/.../contracts/cli.md                         |   6 +
 specs/.../quickstart.md                            |   4 +
 specs/.../tasks.md                                 |  45 +-
 tests/test_refactor.py                             | 169 ++++-
 11 files changed, 821 insertions(+), 599 deletions(-)
```

New files, none of them tracked yet: `brands.yaml`, `docs/front-3-report.md`,
`tests/test_brand_detection.py`, `tests/test_brand_unknown.py`,
`tests/test_brands_file.py`, `tests/test_version_range.py`.

`scanners/brand_probe.py` goes from 533 lines to 304: 249 added, 478 removed, so 229 net
lines fewer even after gaining the `_Entry` and `BrandSignature` types. What went is the
loader chain, the pattern table and the duplicated generic entry.

### `scanners/brand_probe.py`

The old module was dead outside its tests: nothing imported `BrandProbe`,
`BrandDetector`, `BrandCredentialLoader` or `BRAND_PATTERN_SPECS`, and the pattern table
duplicated the brand names already in the wordlist files. The rewrite is four types:

- `ServiceEvidence`: what a scan reported, frozen, built from an nmap service dict, a
  Shodan banner or a stored row. `asdict` of it is what the camera row keeps as
  `raw_banner`, so a device that matched nothing today can be read again once `brands.yaml`
  gains its brand (FR-014).
- `BrandSignature`: one file entry, with its compiled patterns and its credential set.
- `BrandBook`: the file, read once. A malformed entry is refused at load, naming the file
  and the line the brand sits on.
- `Identifier`: reads the identity of a device off the evidence. A CPE the scan reported
  wins over a pattern, because the device said it.

### The target gate

`TargetGate` (was `ShodanScope`) now guards two ways of reaching an address, both from the
one `targets.allowed_cidrs` list (D18):

- `require_inside(query)`: the Shodan query, checked on its `net:` filter. Unchanged.
- `require_reachable(addresses)`: every address a check run would reach, which the operator
  did not type this time. New.

Both fail closed: an empty declared list authorizes nothing. A run narrowed with
`scan check --camera-id N` is not gated, because naming the camera is the authorization.

The refusal names the outside addresses, and stops at the tenth:

```
scanners.task.TargetOutsideScopeError: 226 of 226 addresses are outside the declared ranges []:
187.120.243.55, 201.75.97.31, 138.94.52.217, 177.86.175.11, 168.227.102.27, 177.72.56.202,
179.34.49.77, 38.9.4.135, 179.104.50.159, 177.85.167.60 and 216 more; declare them in
targets.allowed_cidrs, or narrow the run with --camera-id
```

### The two findings taken from the review

The front was reviewed before it was committed. Two findings were fixed in place:

1. **The refusal message was uncapped.** It joined every outside address, so a table of 227
   cameras produced one 227-address line. `TargetGate._named` now names the first ten and
   counts the rest (`and 216 more`), with `_NAMED_LIMIT` as the knob. The count is what keeps
   the line useful: the operator still learns how many addresses are out.
2. **Two brands were missing from the file.** `Boa/` and `GoAhead`, the two web servers cheap
   cameras embed instead of writing their own. Naming them is what points the vuln front at
   the CVEs that cover the server, which is where an unauthenticated read usually sits. Both
   pairs were checked against the NVD CPE dictionary before being written:
   `cpe:2.3:a:boa:boa` (7 CVEs) and `cpe:2.3:a:embedthis:goahead` (50) are real.
   `h264dvr`, `xiongmai dvr`, `xiongmaitech:xmeye` and `xiongmaitech:dvr` are not: the
   Xiongmai vendor has only per-model hardware CPEs (515 results, e.g.
   `cpe:2.3:h:xiongmaitech:ahb7008f8-h`), so a `H264DVR` banner is left unnamed on purpose
   and the reason is written into `brands.yaml`. The shipped file now has a test that reads it
   and asserts the two servers are named, so a malformed entry breaks the suite.

Verified, over the shipped `brands.yaml`:

```
$ .venv/bin/python -c "...Identifier(BrandBook.load('brands.yaml'))..."
'Boa/0.94.14rc21' -> Identified(vendor='boa', product='boa', version='', brand='boa')
'GoAhead-Webs'    -> Identified(vendor='embedthis', product='goahead', version='', brand='goahead')
'H264DVR'         -> Identified(vendor='', product='', version='', brand='')
```

## 3. Lab run (T046)

The rig, all of it on `127.0.0.1`, none of it a third-party device:

| Piece | Address | What it answers |
|---|---|---|
| `mediamtx` v1.11.3 | `127.0.0.1:8554` | an RTSP stream published by `ffmpeg` at path `h264/ch1/main/av_stream` |
| HTTP server, `Server: Hikvision-IP camera` | `127.0.0.1:8080` | the banner that matches `brands.yaml` |
| HTTP server, `Server: Frobnicator/1.2` | `127.0.0.1:8000` | a banner that matches no signature |

The RTSP side, from the runbook:

```
$ mediamtx mediamtx.yml &
2026/11/11 10:48:13 INF [RTSP] listener opened on :8554 (TCP), :8000 (UDP/RTP), :8001 (UDP/RTCP)
$ ffmpeg -re -f lavfi -i "testsrc=size=640x480:rate=10" -pix_fmt yuv420p \
    -c:v libx264 -preset ultrafast -tune zerolatency \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/h264/ch1/main/av_stream
2026/11/11 10:48:13 INF [RTSP] [session 4353361a] is publishing to path 'h264/ch1/main/av_stream', 1 track (H264)
```

### 3.1 Identification

```
$ .venv/bin/python main.py scan nmap 127.0.0.1/32
2026-11-11 10:50:41,701 INFO Starting nmap scanning on 127.0.0.1/32
2026-11-11 10:52:41,762 INFO Found 1 hosts using nmap scan
2026-11-11 10:52:41,765 INFO nmap XML written to logs/nmap.xml
2026-11-11 10:52:41,834 INFO Executors: finished nmap scan
```

What the run stored, read straight out of the database:

```
id=231 127.0.0.1:8000 vendor='' product='' version='' status=CameraStatus.unknown
   raw_banner={'cpe': '', 'banner': 'Frobnicator/1.2 ', 'source': 'nmap', 'product': 'Frobnicator/1.2 ', 'version': ''}
id=1 127.0.0.1:8080 vendor='hikvision' product='ip_camera' version='' status=CameraStatus.unknown
   raw_banner={'cpe': '', 'banner': 'Hikvision-IP camera ', 'source': 'nmap', 'product': 'Hikvision-IP camera ', 'version': ''}
id=232 127.0.0.1:8554 vendor='' product='' version='' status=CameraStatus.unknown
   raw_banner={'cpe': '', 'banner': '', 'source': 'nmap', 'product': '', 'version': ''}
run id=4 kind=ScanKind.nmap target_set=127.0.0.1/32 cameras=3 finished=2026-11-11 13:52:41.827657+00:00
```

Three things this shows at once:

- `127.0.0.1:8080` is named `hikvision` / `ip_camera` from the `Hikvision-IP` pattern in
  `brands.yaml`, with no code change and no release.
- `127.0.0.1:8000` is stored unnamed, and its banner survives on the row, which is what
  FR-014 needs to name it later.
- `127.0.0.1:8080` is camera `id=1`: the row already existed from an earlier lab run.
  `record_identity` found it and wrote the name onto it instead of adding a duplicate, so a
  device first seen before its brand was in the file picks up the name on the next run.

### 3.2 The gate refuses a wide run

`config.yaml` has no `targets:` section, so the declared list is empty and every stored
camera is outside it. The wide run is refused before any packet leaves:

```
$ .venv/bin/python main.py scan check
...
  File "/Users/iklo/shodan_rtsp/scanners/task.py", line 235, in require_reachable
    raise TargetOutsideScopeError(
scanners.task.TargetOutsideScopeError: 227 of 227 addresses are outside the declared ranges []: 177.44.208.33, 189.103.1.104, 189.90.52.246, 186.210.186.37, 177.52.31.193, 187.120.243.55, 181.216.125.145, 177.141.96.174, 187.182.142.10, 179.215.116.239, 186.208.182.214, 45.227.251.139, 177.38.157.61, 187.60.155.113, 187.66.251.52, 186.244.252.63, 138.121.197.17, 189.98.124.236, 177.65.37.57, 187.103.242.214, 186.205.210.16, 45.190.101.12, 45.190.112.253, 189.15.27.223, 177.52.29.60, 177.65.18.82, 201.72.50.131, 191.179.16.14, 138.97.94.80, 192.12.113.180, 177.80.134.194, 201.72.50.136, 179.159...
```

227 addresses are the cameras waiting for a frame, measured at 10:56 UTC, before the
narrowed run of section 3.3. The other five of the 232 were already `stream_obtained`, so
the queue does not include them. After section 3.3 the queue would be 226, because the lab
camera joined them. These are the rows the legacy import brought in, and the refusal is the
point of the front: before it, this command would have opened an RTSP connection to every
one of them.

The line above was captured before the cap of section 2 landed, which is why it prints all
227. The same run after the cap prints ten and `and 216 more`.

### 3.3 The gate lets a narrowed run through

```
$ time .venv/bin/python main.py scan check --camera-id 232
...
2026-11-11 10:59:04,554 INFO Executors: finished testing cameras
.venv/bin/python main.py scan check --camera-id 232 2>&1  4.08s user 1.61s system 1% cpu 5:54.21 total
```

Exit code 0. The run reached the camera the operator named and found credentials:

```
$ grep "answered" logs/rtsp_scanner.log | tail -5
2026-11-11 10:57:24,321 INFO [!] 127.0.0.1:8554 answered
2026-11-11 10:57:49,320 INFO [!] 127.0.0.1:8554 answered
2026-11-11 10:58:14,320 INFO [!] 127.0.0.1:8554 answered
2026-11-11 10:58:39,321 INFO [!] 127.0.0.1:8554 answered
2026-11-11 10:59:04,320 INFO [!] 127.0.0.1:8554 answered
```

The row the run wrote:

```
id=232 127.0.0.1:8554 status=CameraStatus.stream_obtained user='user' password='123456' url='rtsp://user:123456@127.0.0.1:8554/h264/ch1/main/av_stream'
```

15 of the 60 combinations answered, which is the arithmetic: 5 url templates x 3 users x 4
passwords, and exactly the 3 users x 5 passwords whose template is
`h264/ch1/main/av_stream` reach the published stream. The other 45 templates are paths
mediamtx has nothing on. The row keeps the last one that answered, not the first.

The frame is real, not a capture that merely reported success:

```
$ .venv/bin/python -c "... RtspProbe().probe(target) ..."
result: ('rtsp://user:123456@127.0.0.1:8554/h264/ch1/main/av_stream', (480, 640, 3), dtype('uint8'))
```

`scan check` writes no frame to disk: the contract gives it `camera.user`, `camera.password`,
`camera.url` and `camera.status`, and the frame belongs to the face front. `logs/frames` is
empty after this run, which is that contract holding.

One observation, not chased: OpenCV prints `VIDEOIO(FFMPEG): backend is generally available
but can't be used to capture by name` on stderr during the run. It does not track the
outcome: 15 probes read a frame anyway, and the direct probe above returns a 480x640x3
array.

## 4. Deviations

1. **`targets.allowed_cidrs` replaces `shodan.allowed_cidrs`.** As decided. The local
   `config.yaml` now carries the section, set to `["127.0.0.1/32"]`, so the wide check run is
   still refused: the 226 legacy rows are outside it. Section 3.2 is that state, and it is
   deliberately kept.
2. **The four `generic_*` entries are not in `brands.yaml`.** They duplicated
   `wordlists/rtsp_urls_small.txt` and the password file. The generic set is still tried,
   through the wordlists, after the brand set (D22).
3. **`NmapTask` takes an `identifier`.** The immutable rules cap a method at three
   parameters, so the identifier is the second positional and the database stays third.
4. **`ShodanScope` is renamed `TargetGate`.** The old name said Shodan; the type now guards
   two things.
5. **`ruff format` is not enforced in this repository.** `ruff format --check .` flags nine
   files, four of them untouched by any front (`migrations/env.py`, `scanners/face_task.py`,
   `scanners/frames.py`, `research.md`). Only `ruff check` runs, through
   `~/.claude/hooks/quality.sh`. Reformatting the repository is a separate decision.
6. **`scan nmap` stays ungated.** D6 accepted that risk and the contract already says so;
   the run's `target_set` is what records, after the fact, what it reached.

## 5. Open risks

1. **The legacy rows cannot be re-identified from the database.** Measured at 14:00 UTC,
   after every run above:

   ```
   cameras total: 232
   with a vendor: 1
   with a raw_banner: 3
   by status: [(stream_obtained, 6), (unknown, 226)]
   ```

   Only the three rows this lab run wrote have a banner. The 229 rows the legacy import
   brought in have none, so `brands.yaml` gaining their brands does not name them: only a
   fresh scan of their addresses can. Those addresses are outside every declared list, so
   under the gate as it stands they cannot be reached at all. The 226 `unknown` rows are
   therefore inert until someone declares a range that covers them, in writing.

   The five `stream_obtained` rows the import brought in carry working credentials and a
   Dahua-style URL, so the old pipeline had already reached those cameras. The gate is what
   stops this one from doing it again.
2. **Closed: the refusal message was uncapped.** With 227 rows it was one line of 227
   addresses. It now names ten and counts the rest, and `_NAMED_LIMIT` is the knob if ten
   turns out to be the wrong number in use.
3. **A Shodan run does not refresh a row it already has.** `ShodanTask._store_banner`
   returns early when the camera exists, before writing the identity and before recording
   the observation, so a camera nmap created stays unnamed even when a later Shodan banner
   names it, and no `camera_observation` is written for that camera in that run (FR-006).
   This is pre-existing behaviour, not a regression of this front, and it cannot be tested
   here without a Shodan key.
4. **The check run is slow at the configured concurrency.** `concurrency: 1` and a dead
   camera costing the 8 s `stimeout` of `rtsp_probe`, over 5 url templates x 3 users x 4
   passwords. Section 3.3 is the measurement: 60 combinations, 5 minutes 54 seconds, of
   which the 15 that worked only start at 4 minutes 13 seconds in, because the shuffle put
   the right template late. `checkers.concurrency` is the knob.
5. **A camera that a CPE names gets no brand credential set.** `Identifier.identify` lets a
   reported CPE win over a pattern and returns an empty `brand`, while `_brand_combos`
   matches the banner text against `brands.yaml`. So a device whose banner matches no
   pattern but whose CPE names its vendor is stored under the right vendor and product, and
   still gets only the generic wordlists. `brands.yaml` gaining a pattern for it is the fix,
   which is the point of the file.
6. **The 226 `unknown` rows keep their status after identification.** `record_identity`
   writes vendor, product, version and banner but not status, so a named camera stays
   `unknown` until credentials work. That is what `CameraStatus` means here, but the name
   reads like "not identified", and section 3.1 shows a row with `vendor='hikvision'` and
   `status=unknown` side by side.
