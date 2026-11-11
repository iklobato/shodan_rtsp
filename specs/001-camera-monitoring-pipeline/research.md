# Research: Camera Monitoring Pipeline

**Feature**: `specs/001-camera-monitoring-pipeline/spec.md`
**Created**: 2026-11-11

Every entry follows Decision / Rationale / Alternatives considered. Claims that came from
a web source carry the URL. Claims that came from a command on this machine carry the
command. Anything not verified is marked as such, in the entry it affects.

## R1. Face embedding: 512 dimensions, cosine similarity

**Decision**: the embedding is 512-d, matching uses cosine similarity over the
L2-normalized vector, and the raw vector is what gets stored. The configured threshold is
a minimum cosine similarity, and its value is measured in the lab before it is trusted.

**Rationale**: the `buffalo_l` pack is SCRFD-10GF for detection plus `w600k_r50`
(ResNet50 trained on WebFace600K) for recognition, and the recognition output is 512-d.
Measured on the model already cached on this machine, not taken from a document:

```console
$ .venv/bin/python -I -c "... ort.InferenceSession('~/.insightface/models/buffalo_l/w600k_r50.onnx') ..."
INPUTS: [('input.1', ['None', 3, 112, 112])]
OUTPUTS: [('683', [1, 512])]
```

The repository is wrong about this in three places: `pyproject.toml:18` says "128-d
embedding", and `scanners/face_recognizer.py:3,31` repeats it. The current matcher
(`face_recognizer.py:98`) computes `np.linalg.norm(new - known)` on the raw vector, which
is Euclidean distance, while `config.yaml` documents the threshold as "cosine distance
below = same person" and the code comment at line 41 says "Euclidean distance". So the
config, the comment and the code already disagree with each other, and all three disagree
with the model.

`insightface` exposes `normed_embedding` next to `embedding`, computed as
`embedding / l2norm(embedding)`, so the normalization costs nothing to obtain
([app/common.py](https://github.com/deepinsight/insightface/blob/master/python-package/insightface/app/common.py)).
The official guidance is cosine similarity over L2-normalized embeddings
([insightface guide](https://insightface.ai/guides/choose-face-recognition-model-and-evaluate)).
That page publishes no single threshold for `buffalo_l`: it gives 0.30 to 0.45 cosine at
FMR 1e-4 to 1e-5 for 1:1 verification and says to recompute on your own set. A third party
(LocalAI) uses 0.35. None of those is a measurement on this lab data, so the value stays a
placeholder until the lab produces one (D16).

Storing the raw vector and normalizing at match time is the choice that keeps the data
recomputable: a normalized vector cannot be turned back into the original, so a later
change of metric could not be re-derived from stored data if only the normalized form
were kept. Normalizing at match time is one `np.linalg.norm` per stored vector, which is
nothing at lab scale.

**Alternatives considered**: keeping the Euclidean distance on the raw vector (what the
code does today) would mean the recorded threshold and the computed metric describe
different things, and it is the weaker metric on unnormalized face embeddings. Storing the
normalized vector only would make matching a plain dot product, at the cost of losing the
original measurement.

## R2. Alembic: layout, naming convention, and the first migration

**Decision**: `alembic init` layout at the repository root, `env.py` wired to the
declarative `Base.metadata`, a naming convention passed to `MetaData` at construction, and
the first migration written to create the whole schema from zero.

**Rationale**: the target database is new and empty, so the first revision is a plain
`CREATE TABLE` set with no rename step and no backfill. The naming convention has to be
passed in the `MetaData` constructor, not assigned afterwards, and a `CHECK` constraint is
ignored by autogenerate unless it carries a name
([naming](https://alembic.sqlalchemy.org/en/latest/naming.html),
[autogenerate](https://alembic.sqlalchemy.org/en/latest/autogenerate.html)):

```python
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
```

The existing hand-made tables live on a different instance (the Homebrew Postgres at 5432,
shared with `mercur` and `suleiman`), so nothing there needs stamping and nothing there is
touched. If a future environment does hold the old tables, the documented move is
`stamp head` so the upgrade does not try to recreate them
([cookbook](https://alembic.sqlalchemy.org/en/latest/cookbook.html)).

**Alternatives considered**: `create_all` on startup, which is what the code does today and
what makes the schema unreproducible. A single squashed revision is already the plan, since
the database starts empty.

## R3. Live-safe migration patterns

**Decision**: every schema change is written to take the weakest lock that does the job,
and any index on a table that is being read gets `CONCURRENTLY`.

**Rationale**, from the PostgreSQL 16 documentation
([ALTER TABLE](https://www.postgresql.org/docs/16/sql-altertable.html),
[explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html)):

| Form | Lock | Rewrites the table |
|------|------|--------------------|
| `ADD COLUMN` with a non-volatile default | ACCESS EXCLUSIVE | no, metadata only |
| `ADD COLUMN` with a volatile default | ACCESS EXCLUSIVE | yes |
| `RENAME TO`, `RENAME COLUMN` | ACCESS EXCLUSIVE | no |
| `ADD CONSTRAINT` (check, unique, primary key) | ACCESS EXCLUSIVE | no, scan only |
| `ADD FOREIGN KEY` | SHARE ROW EXCLUSIVE | no |
| `CREATE INDEX` | SHARE, blocks writes | no |
| `CREATE INDEX CONCURRENTLY` | SHARE UPDATE EXCLUSIVE, does not block writes | no |

The safe pair for a constraint on a busy table is `ADD CONSTRAINT ... NOT VALID` followed
by `VALIDATE CONSTRAINT`, which takes the weaker lock for the scan.

This batch adds a whole schema to an empty database, so the only live concern is the first
migration after the schema exists. The rule is recorded now so the next migration does not
have to rediscover it.

**Alternatives considered**: none worth taking. The lock table is the decision.

## R4. `CREATE INDEX CONCURRENTLY` inside Alembic

**Decision**: a migration that needs a concurrent index wraps it in
`op.get_context().autocommit_block()`, and `transaction_per_migration=True` is set so the
block only splits its own revision.

**Rationale**: Alembic runs migrations inside a transaction on PostgreSQL, and
`CREATE INDEX CONCURRENTLY` cannot run inside a transaction block. The autocommit block
commits the preceding transaction unconditionally, so without
`transaction_per_migration=True` it also commits the work of earlier revisions
([autocommit_block](https://alembic.sqlalchemy.org/en/latest/api/runtime.html#alembic.runtime.migration.MigrationContext.autocommit_block)):

```python
with op.get_context().autocommit_block():
    op.create_index(
        "ix_example", "example", ["column"],
        postgresql_concurrently=True, if_not_exists=True,
    )
```

**Alternatives considered**: running the index by hand outside Alembic, which breaks the
rule that the schema has one source of truth.

## R5. Which CVEs, and which of them are read-only

**Decision**: the first batch carries three classes, and only requests that are a plain
read are used as proof.

**Rationale**: the tool must obtain at most one frame and write nothing to the device
(D5). The research returned these, with the exact request that proves each one:

| Class | CVE | Request | Returns | Writes to the device |
|-------|-----|---------|---------|----------------------|
| auth bypass | CVE-2017-7921, Hikvision | `GET /onvif-http/snapshot?auth=YWRtaW46MTEK`, no auth | JPEG | no |
| unauth read | CVE-2025-34022, Selea Targa | `POST /cgi-bin/get_file.php` with `files_list=/etc/passwd`, and `GET /common/get_file.php` (sources disagree on the path) | file, not an image | no |
| unauth read | CVE-2016-15055, JVC VN-T | `check.cgi` with a user-controlled `file` parameter | file, not an image | no |
| unauth ONVIF | CVE-2025-65856, Xiongmai XM530 | `POST /onvif/device_service` with `tds:GetDeviceInformation`, no WS-Security | XML with manufacturer, model, firmware | no |

Sources: [NVD CVE-2017-7921](https://nvd.nist.gov/vuln/detail/CVE-2017-7921),
[Hikvision advisory](https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification--privilege-escalating-vulnerability-in-cer/),
[VulnCheck on Selea](https://www.vulncheck.com/advisories/selea-targa-ip-camera-path-traversal),
[EDB-49456](https://www.exploit-db.com/exploits/49456),
[GHSA on JVC](https://github.com/advisories/ghsa-x9hg-4fh7-crh8),
[CISA ICSA-26-113-05 on Xiongmai](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-05).

Two candidates were rejected on the read-only rule, and the reason is recorded because it
is the rule doing the work:

- **Dahua CVE-2021-33044 / CVE-2021-33045** creates a server-side session with
  `POST /RPC2_Login`. It does not change configuration, but it does create state on the
  device, so it is not a plain read. It is also in the CISA known-exploited catalog.
- **Foscam CVE-2018-19067** has fixed firmware credentials, and the published proof of
  concept switches telnetd on. That is a write.

The `auth_bypass` class is the one that yields a frame. The two `unauth_read` entries
return a file and not an image, so their honest outcome is a recorded
`no_frame` with the reason, which is exactly what the `cve_finding` constraint is for
(D31). Only the ONVIF class also returns the model and the firmware, which is what makes
it worth a class of its own even when it produces no picture.

**Alternatives considered**: picking CVEs for their severity rather than for whether the
proof is a read. Rejected: an RCE or a config write is out of scope for this project.

**Not verified, and therefore not relied on**: the exact parameter syntax of the JVC
`check.cgi` call, the correct path for the Selea call (VulnCheck and EDB disagree), whether
the Dahua snapshot path returns a JPEG after the bypass, and whether the Hikvision bypass
alone exposes model and firmware through a dedicated endpoint. Each of these is a
`NEEDS CLARIFICATION` that the lab run resolves, not a fact to build on. A `CVE-2026-61515`
entry that the search returned was dropped: the identifier could not be confirmed outside
the repository of its own proof of concept.

## R6. The lab rig for the CVE front

**Decision**: the lab emulates real vendor firmware with FEMU or FirmAE, using old
Hikvision firmware, and the target is the Hikvision snapshot bypass
(CVE-2017-7921). If the emulation cannot be made to serve the vulnerable request, that
outcome is recorded and the front is blocked, not faked.

**Rationale**: no public container reproduces a camera CVE. `vulhub` has no IP camera
entry at all. `FirmAE` and `FEMU` emulate firmware and both expect the operator to supply
the binary; firmware old enough to carry the vulnerability is downloadable without a
vendor login only from the Hikvision European portal. ONVIF mock containers exist
(for example `ghcr.io/kate-goldenring/onvif-build`) and validate the shape of the request,
but they are not the vulnerable firmware.

Firmware emulation of a camera is not a solved problem: the HTTP server usually comes up,
and the media pipeline usually does not. The acceptance for this front is therefore
narrow and checkable: the emulated device answers the vulnerable snapshot request with a
JPEG, and the raw output is pasted. Anything less is a recorded failure.

**Alternatives considered**: a local mock that imitates the vulnerable request shape. It
was rejected by the operator in favour of real firmware. The mock remains the fallback if
emulation fails, and if it is used, the plan and the report must say that the proof is
against a mock and not against vendor code.

## R7. Command names

**Decision**: `scan nmap`, `scan shodan`, `scan check`, `scan cve`, `scan faces`,
`report faces`, `search`.

**Rationale**: D38 listed six names and left the Shodan mode, which D14 and D37 keep,
without one. Today `--start_search` already means Shodan, and D38 gives `search` to the
monitoring query, so the two meanings would collide. `scan shodan` fills the gap and
`search` keeps the meaning D38 gave it.

**Alternatives considered**: keeping `search` for Shodan and renaming the monitoring query
to `report people`, which contradicts D38 and hides the primary read path under a name
that does not say what it does.

## R8. Where the frames live on disk

**Decision**: one directory per camera under a configured root, and the file name carries
the capture time and the source:
`<frame_root>/<camera_id>/<YYYYMMDDTHHMMSSZ>-<source>.jpg`.

**Rationale**: the database holds the path (D17), so the layout only has to be readable by
a human and stable across runs. A directory per camera keeps a `ls` useful and keeps any
single directory from holding every frame. A timestamp in the name sorts by time without a
query, and the source suffix (`rtsp` or `cve`) makes it obvious at a glance which path
produced the file, which is the same fact the camera status carries (D33). The
`UNIQUE (path)` constraint in the data model is what keeps a re-run from writing two rows
for one file.

**Alternatives considered**: a flat directory (unreadable past a few thousand frames), a
content hash as the name (deduplicates identical frames, but hides when a frame was
taken), and a database blob (rejected by D17 on cost).

## R9. Clustering faces into people

**Decision**: a face is compared against the stored faces of existing people, and a match
joins that person. When a face matches more than one person, those people are merged, with
the older person row surviving. Comparison is an O(n) scan over stored embeddings.

**Rationale**: the lab holds tens of cameras and a bounded number of faces, so a linear
scan in Python is correct and simple, and it needs no extension. The merge is a union of
two clusters that were already the same person, so the surviving row is the older one and
the faces are re-pointed to it. No face and no frame is deleted, which keeps the merge
clear of the unlimited retention decision (D10).

Marked as a deliberate ceiling in code: `ponytail:` on the scan, naming the upgrade path
(a Postgres vector index such as pgvector, which is a new dependency and therefore needs
its own decision).

**Alternatives considered**: an approximate-nearest-neighbour index now, which is a new
dependency for a scale this project does not have. A clustering pass over everything at
report time, which would make the stored `person_id` a derived value and lose the history
of when a person was first seen.

## R10. The dedicated database

**Decision**: the compose service keeps the name `shodan_pg` and moves to host port 5440.

**Rationale**: measured on 2026-11-11. `docker ps` shows `deploy-postgres-1` on
`127.0.0.1:5433` and `deploy-db-1` on `127.0.0.1:5439`; `lsof -nP -iTCP -sTCP:LISTEN`
shows a Homebrew Postgres 17.8 on `127.0.0.1:5432` hosting the databases `cameras`,
`mercur` and `suleiman`. The compose file as written maps 5433, which is already
allocated, so the service could not start. 5440 is free.

The tool points at `127.0.0.1:5432` database `cameras` today, which is the shared Homebrew
instance. The three hand-made tables there hold 0 rows and are left untouched.

**Alternatives considered**: keeping the shared Homebrew instance, rejected because the
whole point of D4 was to stop sharing. Reusing the container on 5433 with a new database
name, rejected for the same reason.

## R11. Retiring the residential proxy

**Decision**: delete `scanners/proxy.py`, `scanners/proxy_tunnel.py`, the `proxy` config
section, the proxy branch of the nmap check and the proxy tests.

**Rationale**: D11. There is no use for a residential exit in a lab scope, and the lab
range is private, so a residential exit could not reach it anyway. The removal is what
takes the test count from 35 to roughly 15, which is why the test suite is the check on
this front.

**Alternatives considered**: keeping it behind a flag, which keeps 467 lines, a config
section and its tests alive for a path the scope cannot use.
