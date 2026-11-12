# Contract: command line surface

**Feature**: `specs/001-camera-monitoring-pipeline/spec.md` (FR-026, FR-027, FR-028)
**Decisions**: D34, D38, and the name for the Shodan mode settled in `research.md` R7
**Created**: 2026-11-11

This is the interface the operator uses, so it is a contract: a change to a command name,
an option or an exit code is a breaking change and needs a decision.

## Invocation

```text
python main.py [--config PATH] [-v] <group> <command> [options]
```

`--config` defaults to `config.yaml` in the working directory. `-v` raises the log level
from INFO to DEBUG. The `--start_*` flags of the current version are removed, not aliased:
the README is rewritten in the same front (FR-032), and a silent alias would keep two
spellings alive.

## Commands

### `scan nmap [target]`

Finds cameras on the network, writes one `scan_run`, one `camera` row per address and port
and one `camera_observation` per port.

| | |
|---|---|
| `target` | optional CIDR. Defaults to the `nmap.ip_range` of the config |
| writes | `scan_run`, `camera`, `camera_observation` |
| network egress | the target argument, or `nmap.ip_range` when omitted |

There is no gate on this argument (D6 accepted that risk). The `target_set` column of the
`scan_run` row is what records, after the fact, what the run reached.

### `scan shodan [query]`

Finds cameras through the Shodan API, same writes as `scan nmap`.

| | |
|---|---|
| `query` | optional Shodan query. Defaults to the `shodan.query` of the config |
| writes | `scan_run`, `camera`, `camera_observation` |
| network egress | the Shodan API, plus the addresses the query returns |

The query is validated against the CIDR list of the config before the API call, so a query
that names a range outside the declared list fails before API credit is spent (D18). This
is a narrowing check, so it does not contradict D6. Shodan does not index private space, so
this command cannot serve a private lab range (D37).

### `scan check [--camera-id N]`

Tries credentials against the stored cameras and records what worked. Brand specific
credentials are tried before the generic set (D22, FR-015).

| | |
|---|---|
| `--camera-id N` | optional. Restricts the run to one camera |
| writes | `camera.user`, `camera.password`, `camera.url`, `camera.status` |
| network egress | the RTSP port of the cameras already stored |

A run over every camera waiting for a frame is gated: every address it would reach is
checked against `targets.allowed_cidrs` first, and one address outside the declared list
stops the whole run before any packet leaves, with the outside addresses named (FR-001,
D18). A run narrowed with `--camera-id` reaches the camera the operator named, which is
the authorization itself, so it is not gated.

### `scan cve [--camera-id N]`

Reads the stored observations (D30), matches them against the CVE map, and for each match
tries the classes in order until one returns a frame (FR-017). Writes one `cve_finding` per
camera and CVE, updated in place, plus at most one proof frame per finding.

| | |
|---|---|
| `--camera-id N` | optional. Restricts the run to one camera |
| writes | `cve_finding`, `face_frame` (at most one per finding), `camera.status` |
| network egress | the HTTP, ONVIF and RTSP ports of the cameras already stored |

Read-only against the target: at most one frame is pulled and nothing is written to the
device (FR-003). A class that yields no frame is recorded with its reason and the next
class is tried (FR-018). The command exits 0 when the run completed, including when no
frame was obtained: a recorded absence is a successful run, not a failure.

### `scan faces [--camera-id N]`

Captures frames through the path that worked, detects faces, and assigns each face to a
person, merging people when one face matches two (FR-022, FR-023).

| | |
|---|---|
| `--camera-id N` | optional. Restricts the run to one camera |
| writes | `scan_run`, `face_frame`, `face`, `person` |
| network egress | the stored `camera.url` of each camera |

A run is recorded like every other run: one `scan_run` of kind `faces`, closed when the run
finishes (D-22).

### `report faces [--person-id N]`

Prints what the face scan found, and for each result the path that produced the frame
(FR-028). Reads only.

```text
person 3  faces 12  first seen 2026-11-11T09:14:02Z  last seen 2026-11-11T11:02:41Z
  camera 192.0.2.10:554  frames 4  frame rtsp, cve
person 4  faces 2   first seen 2026-11-11T10:20:00Z  last seen 2026-11-11T10:20:00Z
  camera 192.0.2.11:80   frames 2  frame cve
```

A person prints as `person <id>`, or as `person <id> (<label>)` when the row carries a label
(D28).

### `search [--person-id N] [--camera-id N] [--since TS] [--until TS]`

Answers who appeared, where and when (FR-027, D25). Reads only, from the database, with no
SQL written by hand.

> Changed in `002-person-search`: this command is now `search appearance`, with the same
> four flags and the same output. `search` became a group that also holds `search person`.
> See `specs/002-person-search/contracts/cli.md`.

```text
2026-11-11T09:14:02Z  person 3  camera 192.0.2.10:554  frame rtsp
2026-11-11T10:20:00Z  person 4  camera 192.0.2.11:80   frame cve
```

One line per appearance, oldest first. A person prints as `person <id>`, or as
`person <id> (<label>)` when the row carries a label (D28). Nothing labels a person
automatically, so the id is the only name the pipeline itself can give one, and a label is
what an operator put on the row.

### `measure threshold [--pairs PATH]`

Measures the face match threshold on a labelled pair set (D16, SC-010). Reads only.

| | |
|---|---|
| `--pairs PATH` | directory of identities. Defaults to `face.pairs_path` of the config |
| writes | nothing |
| network egress | none |

The directory holds one subdirectory per identity, each holding two or more images:

```text
lab/faces/
├── person_a/
│   ├── 01.jpg
│   └── 02.jpg
└── person_b/
    ├── 01.jpg
    └── 02.jpg
```

Every pair inside one subdirectory is a same identity pair. Every pair across two
subdirectories is a different identity pair. The command prints, for each group, the count
and the smallest, mean and largest cosine similarity, plus the separation between the two
groups:

```text
same identity        pairs 6   min 0.612  mean 0.734  max 0.811
different identity   pairs 18  min 0.044  mean 0.121  max 0.238
separation           0.374 between the largest different and the smallest same
```

The chosen value is written into `face.match_threshold` by hand, and the raw output, the
pair set and the value go into the front report (quickstart step 7). The command does not
write the config: a value that changes itself is not a measured value.

An identity directory with fewer than two images is an error and exits 1, because one image
cannot form a pair.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | the command completed. For `scan cve` and `scan faces` this includes a run that found nothing |
| 1 | a real failure: the config is invalid, the database is unreachable, the target refused every attempt, or a required input file is missing |
| 2 | the command line is wrong |

A finding of nothing is exit 0 with output that says so. Exit 1 is reserved for a run that
could not do its job, so a caller can tell "nothing there" apart from "it broke".

## Logging

- Logs go to stderr, results go to stdout, so a result can be piped.
- No credential value appears in any log line at any level (FR-030). The current
  `scanners/rtsp_probe.py:146` line that logs the user and the password is removed.
- Every network step logs the target it is about to reach, at INFO, before the call. That
  is the line that makes an accidental scan visible in the log while it is happening.
