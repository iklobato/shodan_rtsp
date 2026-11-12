# D68 to D82: command line and developer experience

Settled 2026-11-12 in a grill session over `/Users/iklo/shodan_rtsp`. It follows the person
search batch (`2026-11-12-busca-pessoa-especifica.md`, D47 to D67) and touches only the
command surface, the setup text and the shape of `main.py`. No pipeline behavior changes.

## What the surface looked like before this batch

Measured on `main.py` before any edit:

| Fact | Value |
|------|-------|
| Groups | 4: `scan`, `report`, `search`, `measure` |
| Leaf commands | 9: `scan {nmap,shodan,check,cve,faces}`, `report faces`, `search {appearance,person}`, `measure threshold` |
| Root options | `--config PATH`, `-v`, and they are only read before the group |
| `search person` flags | 8: `--image`, `--name`, `--target-id`, `--forget`, `--live`, `--camera-id`, `--since`, `--until` |
| Way to see registered targets | none |
| `main.py` | 578 lines, 4 argparse and wiring classes |
| Setup | `docker compose up -d postgres`, `uv run alembic upgrade head`, copy `config.yaml.example`, then `uv run python main.py` |
| Packaging | `[tool.uv] package = false`, so there is no console script today |

Two facts decided several answers below: this repository has no external user, and `main`
requires one approving review with no reviewer in its history, so the change ships as one
pull request.

## Decisions

One line each: the decision, the answer chosen, why, and what it depends on.

| Id | Decision | Answer | Why | Depends on |
|----|----------|--------|-----|------------|
| D68 | Scope of the work | The command surface, the setup text and the internal shape of `main.py` | The three are what a developer touches daily; nothing in `models/` or `scanners/` changes | |
| D69 | Breaking the current commands | Allowed: rename and regroup freely, with no compatibility alias | No external user and no published CLI contract to keep; an alias would keep the wide surface alive | |
| D70 | How the project is invoked | `uv run python main.py`, unchanged | A Makefile adds a second entry point, and a console script needs `package = false` to go away | D68 |
| D71 | `--config` and `-v` | Accepted at any position, on the root and on every group through `parents=`; the default path stays `config.yaml` | Today `main.py scan nmap --config x` fails, which is a pure argparse accident | D69 |
| D72 | Command tree | `find {nmap,shodan}`, `scan {credentials,vulns,faces}`, `report faces`, `search {appearance,person}`, `target {add,list,remove}`, `measure threshold` | Discovery moves next to the other verbs instead of hanging under `scan`; `check` and `cve` say what they look for | D68, D69 |
| D73 | Name of the face commands | `scan faces` and `report faces` keep their names; `search appearance` keeps its name | Only the two unclear names were asked for; `faces` at the scan step is accurate (the row is a face, the grouping is a person) | D72 |
| D74 | `search person` scope | Search only | One command, one job; registration belongs to `target add` | D72 |
| D75 | `search person --image` | Kept as a shortcut that registers and searches in one run | Convenient for the first run of a new target; the user chose it over the split | D74 |
| D76 | `search person --forget` | Removed | Removal is a `target` job; with it gone the refusal for combining removal with search options disappears too | D72 |
| D77 | `search person` selection | `--name` or `--target-id`, and neither means every registered target | Keeps D65 and the way the command is typed today | D74 |
| D78 | `target add` on an existing name | Resolves the name and adds the photos | Keeps D55: a second photo is how a target gets better | |
| D79 | `target remove` argument | A name or an id; an exact name is tried first, a numeric value is read as an id when no such name exists | The name is what the operator remembers, the id is what `target list` prints | |
| D80 | `target list` columns | Id, name, number of reference photos, number of hits | Enough to pick something to remove and to know whether the target ever matched | |
| D81 | Setup | One copy-paste block in the README; no `setup` command and no new script | The user chose text over code; both alternatives add an entry point or a file for something done once | D70 |
| D82 | Shape of `main.py` | One file, the classes split smaller inside it; no `cli/` package | Keeps every import path stable and the review centered on the parsing code | D68 |
| D83 | Pull requests | One, carrying the whole change | No reviewer in history, so splitting buys no smaller review, only more ceremony | |

## What this leaves decided by me, not by the interview

Recorded so a later reader knows these were not asked:

- Exit codes stay `1` for a refusal and `2` for a wrong command line.
- Every help string is rewritten, since the names changed under them.
- `find nmap` and `find shodan` keep their optional positional argument (CIDR, query).
- `--live` stays on `search person` alone, under the same `allowed_cidrs` gate.
- Group and command names stay in English, as the rest of the repository.

## Open risks

- A target whose name is only digits can be removed by id alone (D79).
- Two commands write to the database after this change as well: `target add` and
  `search person --image` (D75).
- Renaming `scan check` and `scan cve` invalidates the command names written in the dated
  sections of `docs/KNOWLEDGE.md` and in `specs/001-camera-monitoring-pipeline/`. Dated
  records are not rewritten; the current contract files are.
- With no aliases (D69), any old command line in a note, a log or a shell history stops
  working without a clear message from argparse.

## Left undecided on purpose

- A machine readable form of `target list` (for example a flag that prints JSON).
- Any packaging of the project as a console script.
- Aliases for the old command names.
