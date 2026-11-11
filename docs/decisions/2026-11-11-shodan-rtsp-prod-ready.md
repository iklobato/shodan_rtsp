# Decisions: shodan_rtsp to production ready

Date: 2026-11-11
Repo: `/Users/iklo/shodan_rtsp`
Method: grill session, ten rounds, 39 decisions, then 6 more added while writing the plan
(D40 to D45) after measurement and research contradicted three of the original facts.
Status: settled. The planning artifacts live in `specs/001-camera-monitoring-pipeline/`.

The goal of the batch: scan the network, identify camera types, use known CVEs to
obtain frames, run face recognition on those frames, and organize the data as a
monitoring source.

---

## Decisions

| # | Decision | Answer | Why | Depends on |
|---|----------|--------|-----|------------|
| D1 | Scope of targets | Own lab plus targets with written authorization | Exploitation and biometric processing are only lawful with authorization. Every other branch hangs on this. | none |
| D2 | What production ready means | Stays local; fix code and data only | No deploy work was asked. Removes app container, scheduler, metrics and alerting from the batch. | none |
| D3 | Fingerprint source | Store the raw Shodan banner (`data`, `http`, `cpe`) plus the `nmap -sV` fields | The banner is the input brand detection already expects, and today it is discarded at `scanners/task.py:42`. An active HTTP or ONVIF probe was not selected. | none |
| D4 | Database | Dedicated Postgres plus Alembic migrations | The schema is created by hand today and points at an instance shared with another project. | none |
| D5 | CVE exploitation form | One module per CVE, proof read only: one frame, no write and no persistence on the target | Answers request 3 without turning the tool into a different one. | D1 |
| D6 | Scope enforcement in code | None | Operator decision. The risk is recorded below. | D1 |
| D7 | Data model | Normalized with history: camera, scan_run, camera_observation, cve_finding, face, face_frame, person | Monitoring needs a time series. Today there are three loose tables with no foreign keys. | D4 |
| D8 | Face pipeline | Detect, cluster into a person entity, with configurable retention | Turns a pile of rows into something that answers a question. | D7 |
| D9 | CVE classes, first batch | Auth bypass and fixed firmware credentials; unauthenticated read (snapshot, file, path traversal); unauthenticated ONVIF | Shortest path to a frame, and the ONVIF one also yields model and firmware. RCE was not selected. | D5 |
| D10 | Retention | Keep everything forever | Operator choice, overriding the retention part of D8. | D7 |
| D11 | Residential proxy | Retire. Remove `scanners/proxy.py` and `scanners/proxy_tunnel.py` | No use in a lab scope. Removes 467 lines, the proxy config section, the nmap proxy check, and about 20 of the 35 tests. | D1 |
| D12 | Work order | Foundation first: schema plus Alembic, then dead code and bugs, then fingerprint, then CVE exploitation, then face | Everything writes to the schema, so it lands before anything that writes to it. | none |
| D13 | Retention conflict | Keep everything forever, confirmed | Resolves the direct conflict between D8 and D10. D10 wins. | D10 |
| D14 | Shodan mode | Keep, locked to own ranges | Operator choice. Refined by D37. | D1 |
| D15 | nmap ports | 554 plus 80, 443, 8000, 8080, 8554, 34567 | Finds the camera that exposes web or ONVIF instead of RTSP, which is most of them, and feeds the fingerprint work. | none |
| D16 | Face match threshold | Measure on known pairs in the lab and derive the value. Also fix the bug: the config says cosine, the code computes a Euclidean norm | A value taken from outside is not measured on this data. | D21 |
| D17 | Frame storage | File on disk, path in the database | With keep forever, hex in a varchar column is the most expensive of the three options and doubles the stored size. | D10 |
| D18 | Shodan lock | CIDR list in config; the query is validated before API credit is spent | Checkable before the call. | D14 |
| D19 | Observation granularity | One row per scan per port | Answers firmware change, uptime, and when a CVE first appeared. | D7 |
| D20 | CI | None. Local tools only | Operator choice. The only gate is running ruff and pytest by hand. | none |
| D21 | Lab | mediamtx plus a VM with known vulnerable camera firmware, isolated with no route out | Read only proof and threshold measurement cannot be verified without a real target. | D1, D16 |
| D22 | Credential check | Keep, but try the brand specific credential set first | Gives brand detection a consumer and cuts scan time. | D3 |
| D23 | Cleanup | Delete merged branches; remove `_probe_names.py`, `docs/proxy-investigation.md`, `proxylist.txt` and `.serena/` | Destructive, so the operator marked each one explicitly. | D11 |
| D24 | Definition of done | A test that fails if the logic breaks, plus a real run in the lab with the raw output pasted | This is the rule of verify, do not claim, applied to this batch. | D21 |
| D25 | What monitoring must answer | Who appeared, where and when | This is the primary query path, so indexes and the read path are designed around it. | D7 |
| D26 | Batch size | Run all five fronts to the end | Operator choice. | D12 |
| D27 | Brand signature | YAML, following the existing `cpe_map.yaml` pattern | A new brand becomes a data line, not a code change and a release. | D3 |
| D28 | Person entity | Anonymous by default, with an optional manual label | Serves the lab without becoming an automatic watchlist. | D8 |
| D29 | How the monitoring answer is consumed | A CLI subcommand that prints it | Closes request 5 with something the operator runs, with no need to remember SQL. | D25 |
| D30 | CVE match source | Read observations from the database. The nmap XML becomes scan input only | Makes when a CVE appeared answerable, and removes the duplicated `nmap_xml` and `xml_path` config pair. | D19, D7 |
| D31 | CVE matches version but no frame comes back | Try the other classes before giving up, and record the candidate with the failure reason | Honest data instead of silence. | D9 |
| D32 | Delivery | One branch per front, one PR each, with review | Resolves the problem recorded in KNOWLEDGE: merges only pass today through an admin bypass. | none |
| D33 | Camera status | A status enum that records which path produced the frame: unknown, responded, stream_obtained, frame_by_cve, offline. Replaces the `active` boolean | The CVE path never authenticates over RTSP, so a boolean cannot express it. | D7 |
| D34 | CLI shape | Reorganize into subcommands | Six modes no longer fit a flat list of flags. | D29 |
| D35 | Person cluster collision | When a face matches two clusters, merge them | Both clusters were already the same person. Keeps the count of different people correct. | D28 |
| D36 | `docs/KNOWLEDGE.md` | Trim to a dated session log. Current state moves to the README and to `docs/decisions/` | Half of the file is history and the other half is an open issues list that this batch closes. | none |
| D37 | Shodan mode, confirmed | Kept, and only useful for a public range that is yours. A private lab range returns nothing from Shodan | Shodan does not index private space, so the mode cannot serve the lab. | D14 |
| D38 | Subcommand names | `scan nmap`, `scan check`, `scan cve`, `scan faces`, `report faces`, `search` | Groups what scans and separates what only reads. | D34 |
| D39 | Credentials | Do not rotate | Operator choice. Risk recorded below. | none |
| D40 | Dedicated database, corrected | The repository compose file moves to host port 5440, and the tool points at it | Measured 2026-11-11: port 5433 was already taken by the container `deploy-postgres-1`, so the `shodan_pg` service as written could not start. Port 5440 is free. Keeps D4 meaning a dedicated instance. | D4 |
| D41 | spec-kit artifacts in git | Commit them: negate the global ignore inside the repository | The global ignore at `/Users/iklo/.gitignore` lines 317 and 318 drops `.specify/` and `specs/`, which would keep the constitution, the spec and the plan out of the review surface. | D32 |
| D42 | Lab rig for the CVE front | Emulate real vendor firmware with FEMU or FirmAE, using an old Hikvision build, and target CVE-2017-7921 | Operator choice over a local mock. No public container reproduces a camera CVE, and both emulators expect the operator to supply the firmware binary. Old Hikvision firmware downloads without a vendor login. If the emulation cannot be made to answer the vulnerable request, the outcome is recorded and the front stays blocked, never faked. | D21, D24 |
| D43 | Shodan command name | `scan shodan` discovers, `search` answers the monitoring question | D38 listed six names and left the Shodan mode, which D14 and D37 keep, without one, while `--start_search` already means Shodan and D38 gives `search` to the monitoring query. | D38 |
| D44 | Face embedding | 512 dimensions, cosine similarity over the L2-normalized vector, raw vector stored | Measured on the cached `w600k_r50.onnx`: the output shape is 1 by 512. The repository says 128-d in `pyproject.toml:18` and `scanners/face_recognizer.py:3,31`, and the matcher computes a Euclidean norm while the config documents cosine. Fixing the metric now is free because no embedding is stored yet. | D16 |
| D45 | Threshold meaning | A minimum cosine similarity, and it stays a placeholder until the lab measures it | The key `face.match_threshold` means three different things today: the config calls it a cosine distance, the comment says Euclidean, and the code compares Euclidean norms. One meaning, stated in the config, and no value trusted before measurement. | D16, D44 |

---

## Open risks

1. **No scope gate (D6).** Nothing in the code stops a wrong `ip_range` from
   scanning a network the operator does not own. The README warning and the
   operator are the only controls.
2. **Keep everything forever (D10, D13).** Frames and biometric embeddings grow
   with no limit and there is no purge. Disk exhaustion is the failure mode, and
   it will be silent.
3. **Biometric data of third parties, kept indefinitely, in plain files on disk,
   with no encryption and no access control (D10, D17).** In a lab with
   consenting people this is a deliberate choice. It is recorded here as one.
4. **The Shodan mode cannot serve the chosen scope (D37).** It keeps a config
   section, an API key and a code path that the lab scope cannot use.
5. **The face threshold has no value yet (D16).** It is unvalidated until the lab
   measures it. Any number used before that measurement is a placeholder and
   must be labelled as one.
6. **Credentials are not rotated (D39).** The Shodan key and the 2captcha token
   sit in plaintext in `config.yaml`. Verified never committed, so nothing
   leaked, but this is the file that gets copied around.
7. **Removing the proxy removes about 20 of 35 tests (D11).** RTSP transport
   coverage drops to the direct path only.
8. **The working credential is stored in plaintext in the database (no decision covers
   this).** The `camera.password` column holds the credential that worked, because the
   tool needs it to read the stream again later. Combined with risk 3, a database dump
   carries both the biometric data and the credentials that reach the device. Recorded
   during planning; not changed, because nothing decided it.
9. **The `unauth_read` class cannot produce a frame.** The two candidates in that class
   return a file and not an image, so their honest outcome is a recorded absence. Only the
   authentication bypass class yields a picture today (research R5).

---

## Left undecided

- Retention periods: removed by D10 and D13.
- Encryption, access control and audit for stored frames and embeddings: not
  decided, outside this batch.
- Backup policy for the frame directory: not decided.
- CI: declined (D20).
- Whether the person label gets a command, a view or SQL: not decided.

---

## Facts established during the session

These are lookups, not decisions.

- Baseline verified 2026-11-11: `uv run pytest -q` reports 35 passed,
  `uv run ruff check .` reports all checks passed.
- The database holds 0 rows in `cam`, 0 in `faces`, 0 in `face_frames`.
- `config.yaml` is git ignored and was never committed. `git log --all -- config.yaml`
  returns nothing.
- `scanners/brand_probe.py` has no importer outside itself. No test file
  references it. `_generic_nginx` is duplicated in two classes.
- The live database is the native Homebrew Postgres 17.8 on `127.0.0.1:5432`,
  database `cameras`, holding `cam`, `faces` and `face_frames` with 0 rows. That
  instance also hosts the databases `mercur` and `suleiman`.
  **Corrected 2026-11-11**: the first version of this file said the live database was
  the container `deploy-postgres-1` on `127.0.0.1:5432`. Both halves were wrong.
  Measured with `docker ps` and `lsof -nP -iTCP -sTCP:LISTEN`: `deploy-postgres-1`
  is the container on `127.0.0.1:5433`, `deploy-db-1` is on `127.0.0.1:5439`, and the
  listener on 5432 is the Homebrew Postgres. This is what forced D40.
- No migration tooling exists. The three tables were created by hand.
- `scanners/task.py:241` holds dead code: `_classify_banner` never returns
  `low`, so the low priority branch and the `_LOW_PRIORITY_COUNT` class state
  never run.
- `scanners/rtsp_probe.py:146` logs the user and the password at INFO level.

---

## Assumptions made without asking

Each of these is reversible and cheap to undo. They are listed so the operator
can object.

- The dedicated database uses the existing `docker-compose.yml`, with its host port
  moved from 5433 to 5440 as D40 records. The database the tool points at today holds
  no rows, so there is no data to migrate and the initial migration is generated from
  scratch. The three hand-made tables on the Homebrew instance at 5432 are left in
  place and untouched, because that instance is shared with other projects.
- Table and column names will be normalized: `cam` becomes `camera`, and
  `image_b64` becomes a path column, since the payload is a file path after D17.
- The credential log line at INFO will be removed.
- The dead `_sanitize_city` helper will be deleted. SQLAlchemy already
  parameterizes, so it protects nothing and it mutates its input.
- `Face.confidence` becomes a float column instead of a string.
- `nmap` will exclude the local machine addresses.
- The README will be rewritten for the new subcommands, because D34 and D38
  break every command it documents, and D11 removes a section it describes.
