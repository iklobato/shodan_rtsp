# Front 1 report: the schema and the subcommand skeleton

Front 1 of D12: `models/`, the first Alembic revision, the repositories and the
`scan nmap` / `scan shodan` skeleton. Tasks T001 to T024 of
`specs/001-camera-monitoring-pipeline/tasks.md`.

Branch: `feat/schema-migrations`. Every command below ran on 2026-11-11 (UTC), on
this host, against the lab container `shodan_pg` (postgres 16, `127.0.0.1:5440`)
and against loopback. Nothing here ran against a third-party host.

## 1. The schema, from zero

```
$ uv run alembic upgrade head
$ uv run alembic upgrade head
$ uv run alembic check
No new upgrade operations detected.
```

Both upgrades print nothing above `INFO` level: the first one had already run, so
the second is a no-op and `alembic check` finds no drift between the models and
the database.

The full round trip (create, no-op, `downgrade base`, create again) is covered by
`tests/test_migrations.py`, which runs it on a throwaway database
`shodan_migration_test` and drops it afterwards:

```
$ uv run pytest tests/test_migrations.py -q
3 passed
```

The test asserts the table set equals `BASE.metadata.tables` plus
`alembic_version`, that the second upgrade changes neither the tables nor the
revision, that `downgrade base` leaves zero tables and zero enum types, and that
the next upgrade rebuilds all nine tables and the five enum types.

## 2. One scan of the lab, with raw output

Listener on the lab host, so the scan has something to find on one of the
scanned ports:

```
$ uv run python -m http.server 8080 --bind 127.0.0.1
```

First scan, nothing listening:

```
$ uv run python main.py scan nmap 127.0.0.1/32
2026-11-11 10:05:54,239 INFO Starting nmap scanning on 127.0.0.1/32
2026-11-11 10:05:54,731 INFO Found 1 hosts using nmap scan
2026-11-11 10:05:54,735 INFO nmap XML written to logs/nmap.xml
2026-11-11 10:05:54,748 INFO Executors: finished nmap scan
```

Second scan, with port 8080 open:

```
$ uv run python main.py scan nmap 127.0.0.1/32
2026-11-11 10:06:08,451 INFO Starting nmap scanning on 127.0.0.1/32
2026-11-11 10:06:14,881 INFO Found 1 hosts using nmap scan
2026-11-11 10:06:14,882 INFO nmap XML written to logs/nmap.xml
2026-11-11 10:06:14,917 INFO Executors: finished nmap scan
```

What the two runs left in the database:

```
$ docker exec shodan_pg psql -U scanner -d cameras \
    -c "SELECT id, kind, target_set, finished_at, camera_count FROM scan_run ORDER BY id DESC LIMIT 2;" \
    -c "SELECT id, ip, port, status FROM camera ORDER BY id DESC LIMIT 3;" \
    -c "SELECT id, camera_id, scan_run_id, port, status FROM camera_observation ORDER BY id DESC LIMIT 3;"
 id | kind |  target_set  |          finished_at          | camera_count
----+------+--------------+-------------------------------+--------------
  2 | nmap | 127.0.0.1/32 | 2026-11-11 13:06:14.909537+00 |            1
  1 | nmap | 127.0.0.1/32 | 2026-11-11 13:05:54.740616+00 |            0
(2 rows)

 id |    ip     | port | status
----+-----------+------+---------
  1 | 127.0.0.1 | 8080 | unknown
(1 row)

 id | camera_id | scan_run_id | port | status
----+-----------+-------------+------+---------
  1 |         1 |           2 | 8080 | unknown
(1 row)
```

Reading it: each run is a row that says what range it was allowed to reach
(`target_set`), when it closed, and how many cameras it reached. Run 1 reached
nothing, so `camera_count` is 0 and no camera row was written. Run 2 found the
listener, so one camera row exists and one observation ties that camera to run 2.
The observation is the series: it keeps what the camera looked like at the moment
of that run, and a later run adds another row against the same camera instead of
overwriting it.

## 3. The gates

```
$ uv run pytest tests/ -q
65 passed in 2.96s

$ uv run ruff check .
All checks passed!
```

The immutable-rules hook (`~/.claude/hooks/immutable-rules-check.py`) reports no
new violation on the files this front touches.

## 4. What Front 1 does not cover

- `scanners/proxy.py` and `scanners/proxy_tunnel.py` are still live, so the
  `proxy` section stays in the config (deviation D-1 in `tasks.md`). Front 2
  removes both.
- `models/managers.py` holds three repositories, not one per entity (deviation
  D-3). The others land with the front that calls them.
- The nmap path has no `allowed_cidrs` gate. `nmap.ip_range` is itself the
  declaration, and the nmap task scans exactly that string; the Shodan path is
  the one that can ask for something else, so it is the one that got the gate
  (`ShodanScope`, T023).
- `cam`, a legacy table with 229 rows, is in the live database and in none of the
  models. `migrations/env.py` lists it in `LEGACY_TABLES` so autogenerate never
  proposes dropping it. Nothing was dropped. The rows were not read by any of the
  runs above; section 5 is the revision that reads them, and it is the one thing
  in this report that ran after the commit of Front 1.

## 5. Amendment: revision 0002 moves the legacy rows

`cam` holds 229 rows from one Shodan scan on 2026-08-09 that declared no range.
Revision `0002` copies them into `camera` and `camera_observation`, under one
`scan_run` whose `target_set` records that they have no declared target. `cam`
itself is not dropped, so the 5 frames in its `image_b64` column stay where they
are until the decode to a file that D17 asks for lands.

Before, on the live lab database:

```
$ uv run alembic current
0001
$ docker exec shodan_pg psql -U scanner -d cameras -c "SELECT (SELECT count(*) FROM cam) AS legacy_cam, (SELECT count(*) FROM camera) AS camera, (SELECT count(*) FROM camera_observation) AS observation, (SELECT count(*) FROM scan_run) AS scan_run;"
 legacy_cam | camera | observation | scan_run
------------+--------+-------------+----------
        229 |      1 |           1 |        2
```

After:

```
$ uv run alembic upgrade head
INFO  [alembic.runtime.migration] Running upgrade 0001 -> 0002, migrate the legacy cam table into camera and camera_observation

 legacy_cam | camera | observation | scan_run
------------+--------+-------------+----------
        229 |    230 |         230 |        3

     status      | count
-----------------+-------
 unknown         |   225
 stream_obtained |     5

 id |  kind  | camera_count |                                           target_set
----+--------+--------------+--------------------------------------------------------------------------------------------
  3 | shodan |          229 | unknown: imported from the legacy cam table (shodan scan of 2026-08-09 that declared no range)
```

`camera` and `camera_observation` each grew by 229, `cam` did not change, and the
5 rows that were `active` carry status `stream_obtained` while the other 224 are
`unknown`. The 225th `unknown` is the camera the Front 1 lab scan wrote.

The credentials came across, and the value is the stored one:

```
$ docker exec shodan_pg psql -U scanner -d cameras -c "SELECT (SELECT count(*) FROM cam WHERE \"user\" <> '') AS legacy_with_user, (SELECT count(*) FROM camera WHERE \"user\" <> '') AS migrated_with_user, (SELECT count(*) FROM cam WHERE password <> '') AS legacy_with_password, (SELECT count(*) FROM camera WHERE password <> '') AS migrated_with_password;"
 legacy_with_user | migrated_with_user | legacy_with_password | migrated_with_password
------------------+--------------------+----------------------+------------------------
                5 |                  5 |                    5 |                      5

$ docker exec shodan_pg psql -U scanner -d cameras -c "SELECT \"user\", password FROM cam WHERE \"user\" <> '' LIMIT 3;"
 user | password
------+----------
 root | password
 root | password
 root | password
```

This is worth its own check because `user` is a reserved word in PostgreSQL. Read
without quotes, `SELECT user FROM cam` returns the name of the connected role for
every row instead of the column, which is a silent wrong value rather than an
error. Both the revision and the test quote it, and the query below is the proof
that no migrated row holds the role name:

```
$ docker exec shodan_pg psql -U scanner -d cameras -c "SELECT count(*) AS with_the_db_username FROM camera WHERE \"user\" = current_user;"
 with_the_db_username
----------------------
                    0
```

A second `alembic upgrade head` changes nothing and `alembic check` still reports
no drift, so the revision is idempotent:

```
$ uv run alembic upgrade head
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
$ uv run alembic check
No new upgrade operations detected.
```

`tests/test_migrations.py` covers the whole thing on a throwaway database: two
legacy rows land as two cameras with one observation each, a second upgrade adds
nothing, and `downgrade 0001` takes the migrated rows back out while `cam` keeps
them. `67 passed`, `All checks passed!`.

### Open risk this amendment leaves behind

The 224 rows that arrive as `unknown` are exactly the set that
`CameraRepository.get_random_without_frame()` selects. A later `scan check` would
therefore point credential combinations at 224 third-party cameras that no
declared range covers. The gate for that belongs to the check task, in Front 3,
and it has to be in place before that subcommand runs against this database.
