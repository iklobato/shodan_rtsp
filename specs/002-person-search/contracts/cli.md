# Contract: command line surface of Person Search

**Feature**: `specs/002-person-search/spec.md` (FR-005 to FR-022, FR-025)
**Decisions**: D52, D55, D61, D64, D65
**Created**: 2026-11-12

This file extends the command surface documented in
`specs/001-camera-monitoring-pipeline/contracts/cli.md`. That file remains the record of the
previous batch. Where the two disagree, this file wins for the `search` group: `search`
stops being one command and becomes a group with two.

## Invocation

```text
python main.py [--config PATH] [-v] <group> <command> [options]
```

Unchanged, including the exit codes:

| Code | Meaning |
|------|---------|
| 0 | the command completed, including a search that found nothing |
| 1 | a real failure: a photo with no face, an unreadable file, an unknown target id, an address outside the declared ranges, the database unreachable |
| 2 | the command line is wrong, including a missing required option |

## The group

```text
search
├── person      search for a named target, or remove one
└── appearance  who appeared, where and when (the command of the previous batch)
```

`search appearance` takes the four flags the old `search` took, with the same meaning:
`--person-id`, `--camera-id`, `--since`, `--until`. Nothing else about it changes.

### `search person --image PATH [--image PATH ...] --name NAME`

Registers the target if the name is new, adds the photos if the name exists, searches the
stored faces, writes the hits, and prints the ranking.

| | |
|---|---|
| `--image PATH` | required at least once. Repeatable (D57). The photo file must exist and hold exactly one detectable face |
| `--name NAME` | required. Trimmed, non-empty, unique (D55) |
| `--camera-id N` | optional. Narrows the search to one camera (D65) |
| `--since TS` | optional. ISO 8601, read as UTC |
| `--until TS` | optional. ISO 8601, read as UTC |
| `--live` | optional. Runs the face scan over the stored cameras first (D61) |
| writes | `target`, `target_photo`, `target_hit`, `person.label` when empty, `scan_run` of kind `faces` only with `--live` |
| network egress | none without `--live`. With `--live`, the stored cameras, behind the `targets.allowed_cidrs` gate |

The command exits 0 when the search completed, including when no face matched. A photo with
no face, a photo with more than one face, an unreadable file, or a name that cannot be
stored exit 1 with the reason on stderr and create no target.

Output, one line per appearance, best score first:

```text
score 0.812  target maria  person 3 (maria)  camera 192.0.2.10:554  2026-11-11T09:14:02Z  frame 3/20261111T091402Z-rtsp.jpg
score 0.744  target maria  person 7         camera 192.0.2.11:80  2026-11-11T10:20:00Z  frame 4/20261111T102000Z-cve.jpg
```

A person prints as `person <id>`, or `person <id> (<label>)` when the row carries a label,
the format the previous contract already uses. The frame path is relative to
`frames.root_path`, the shape `report faces` already prints. A search that finds nothing
prints `no appearance matched <scope> (threshold <value>)` and exits 0, where `<scope>` is
`target <name>`, `target <id>`, or `any target` when the run named none.

### `search person --target-id N`

Searches an already registered target, with no photo. Same optional narrowing, same
`--live`, same output. An id that does not exist exits 1 and names the id.

### `search person` with no photo and no target id

Searches every registered target, printing the target name in front of each line. A database
with no target prints `no appearance matched any target (threshold <value>)` and exits 0,
the same line a run that found nothing prints, because the two look the same to the
operator.

### `search person --forget N`

Removes the target, its photos and its files, and its hits, then clears the person label
only where it equals the target name (D64). Prints one line naming what was removed.

| | |
|---|---|
| `--forget N` | required. The target id |
| writes | deletes `target`, `target_photo`, `target_hit`; sets `person.label` to null where it equals the name |
| network egress | none |

`--forget` cannot be combined with `--image`, `--target-id`, `--live`, `--camera-id`,
`--since` or `--until`. Combining them exits 2, through the same refusal path the other
wrong command lines take.

## What `--live` runs

With `--live` the command does three things in order (D52, D61): registers the photos,
runs the face scan as `scan faces` runs it (same camera set, same `targets.allowed_cidrs`
gate, same `scan_run` row), then compares the stored faces, the ones the scan just wrote
included. Without the flag nothing opens a socket.

## The threshold line

When `person_search.match_threshold` carries the shipped value, the search prints its
threshold with the word `PLACEHOLDER` beside it, because it has not been measured on this
data (D60, D45). A measured value prints without that word. The command never writes the
config.

## Logging

- Results go to stdout, logs to stderr, as the previous contract states.
- The search logs the target set it searched, in the same shape the scans use.
- No credential, no reference photo path and no embedding value appears in any log line at
  any level (FR-024).
- With `--live`, the run logs each address it is about to reach before the call, which is
  what makes an accidental wide run visible while it happens.

## What this contract does not include

- Any alert, watch loop or notification.
- Any output format other than the plain lines above: no JSON, no CSV.
- Any merge of two targets.
- Any removal of a single hit.
