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
  proposes dropping it. Nothing was dropped, and the rows were not read.
