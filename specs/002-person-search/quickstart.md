# Quickstart: Person Search

**Feature**: `specs/002-person-search/spec.md`
**Plan**: `specs/002-person-search/plan.md`
**Created**: 2026-11-12
**Command names updated**: 2026-11-12 (D68 to D83: groups `find` and `target`, renamed
`scan credentials` and `scan vulns`, `--config` accepted anywhere on the line)

Runbook to prove the feature works on the lab, in order, with the raw output kept for the
front report (D24). Every command is run by hand; there is no scheduler and no service.

## Before starting

1. The dedicated PostgreSQL is up on host port 5440 and reachable with the config of the
   operator (`docker compose up -d shodan_pg`).
2. The lab camera rig of the previous batch is running, and at least one person whose photo
   you hold has appeared in a stored frame.
3. The database already holds frames and faces:

```bash
uv run python main.py report faces
```

Expect at least one `person <id>` line. If the report is empty, run `find nmap`, `scan
credentials`, `scan vulns` and `scan faces` first, as the previous quickstart says.

## Step 1: apply the migration

```bash
uv run alembic upgrade head
uv run alembic downgrade -1
uv run alembic upgrade head
```

Expect the three tables to exist after the second upgrade and to be gone after the
downgrade. Paste both outputs into the front report.

## Step 2: register a target and search the history

```bash
uv run python main.py target add --name maria --image lab/faces/maria/01.jpg
uv run python main.py target list
uv run python main.py search person --name maria
```

Expect `target add` to print the id and the reference photo count, `target list` to print
that same target with its hits, and the search to print a line per stored appearance, best
score first, with `person <id>`, the camera, the time, the frame path and the score. Expect
no network call in the log.

The one command form works too and is the shortcut D75 keeps: `search person --image
lab/faces/maria/01.jpg --name maria` registers and searches in one run.

## Step 3: prove the hit is stable

```bash
uv run python main.py search person --target-id 1
psql -h 127.0.0.1 -p 5440 -U postgres -d cameras -c "select count(*) from target_hit;"
```

Run the command twice. Expect the count to be identical after the second run.

## Step 4: prove a bad photo is refused

```bash
uv run python main.py target add --name group --image lab/faces/group.jpg
```

With a photo holding two faces, expect exit 1, the reason on stderr, and no new target:

```bash
echo $?
psql -h 127.0.0.1 -p 5440 -U postgres -d cameras -c "select name from target;"
```

## Step 5: prove the label rule

1. Label a person by hand:
   `psql ... -c "update person set label = 'joao' where id = 3;"`
2. Register a target named `maria` whose photo matches that person.
3. Run the search.

Expect `person 3 (joao)` to keep `joao`, and the hit to be stored anyway. Then repeat with
an unlabeled person and expect the target name to appear.

## Step 6: prove the report change

```bash
uv run python main.py report faces
```

Expect the person that matches a target to carry a line naming the target and the score.

## Step 7: prove the reach gate and the live pass

1. Without `--live`, confirm zero network calls in the log.
2. With `--live` and one lab camera showing the target:

```bash
uv run python main.py search person --target-id 1 --live --camera-id 2
```

Expect the new appearance in the output and in the next stored search.

3. Put one camera outside `targets.allowed_cidrs` and run the wide live pass:

```bash
uv run python main.py search person --target-id 1 --live
```

Expect exit 1, no packet sent, and the outside address named in the message.

## Step 8: prove removal

```bash
uv run python main.py target remove maria
uv run python main.py target list
psql ... -c "select count(*) from target_hit where target_id = 1;"
psql ... -c "select count(*) from face;"
```

Expect the removal line to name the target, its photo count and its hit count, then `no
target registered`, zero hit rows for that target and an unchanged face count.

Run the same removal as `target remove 1` to prove the id form reaches the same target when
no target carries the name `1`.

## Step 9: measure the verification threshold

The threshold ships as a placeholder. Measure it on the labelled pair set:

```bash
uv run python main.py measure threshold --pairs lab/faces
```

Write the chosen value into `person_search.match_threshold` by hand and paste the raw output
into the front report. Until this step runs, every report line about the threshold carries
the word `PLACEHOLDER`.

## What this runbook does not prove

- Behavior on a stored face count much larger than the lab. The comparison is linear and the
  ceiling is recorded in code.
- Any behavior of a reference photo that is a non-JPEG image format other than the ones
  opencv reads in the lab.
- That a measured threshold generalizes beyond the people in the pair set.
