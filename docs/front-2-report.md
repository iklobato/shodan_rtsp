# Front 2 report: dead code and bugs

Front 2 of D12: the retired proxy path, the credential log lines, the unused helper, the
unreachable branch and the stale docs. Tasks T025 to T035 of
`specs/001-camera-monitoring-pipeline/tasks.md`.

Branch: `feat/schema-migrations`, on top of `ee42097`. Every command below ran on
2026-11-11 (UTC), on this host, against the lab container `shodan_pg` (postgres 16,
`127.0.0.1:5440`). Nothing here ran against a third-party host.

## 1. Before and after

Before, measured at `HEAD` in a tree extracted with `git archive HEAD` and run with the
repository venv, so the comparison is the same interpreter and the same dependency set:

```
$ cd /tmp/front2-before && /Users/iklo/shodan_rtsp/.venv/bin/python -m pytest -q
ERROR tests/test_migrations.py::test_legacy_cam_rows_move_into_the_new_schema - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_migration_rolls_back_and_keeps_the_old_rows - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_downgrade_base_returns_to_zero_tables - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
62 passed, 5 errors in 1.67s

$ /Users/iklo/shodan_rtsp/.venv/bin/python -m ruff check .
All checks passed!
```

The five errors are the database tests, and they are an artefact of the extracted tree, not
a result: `config.yaml` is git-ignored and holds credentials, so the archive has none and
the tests that need the DSN cannot reach the lab. Adding 62 and 5 gives the 67 the full
suite reported at the end of Front 1, so the front starts from 67 passed and a clean lint.

After:

```
$ uv run pytest -q
51 passed in 3.39s

$ uv run ruff check .
All checks passed!
```

The net 16 fewer tests is 24 retired proxy tests against 7 new ones (three for the
credential log, four for the direct transport). The full diff:

```
 config.yaml.example      |  16 +--
 docs/KNOWLEDGE.md        | 350 ++++++++++++-----------------------------------
 main.py                  |  15 +-
 models/managers.py       |   7 -
 pyproject.toml           |   3 +-
 scanners/config.py       |  26 +---
 scanners/face_task.py    |   5 +-
 scanners/proxy.py        | 290 ---------------------------------------
 scanners/proxy_tunnel.py | 177 ------------------------
 scanners/rtsp_probe.py   |  74 +++-------
 scanners/task.py         |  49 +------
 tests/conftest.py        |  39 ++++++
 tests/test_refactor.py   | 290 +--------------------------------------
 uv.lock                  |  94 -------------
 14 files changed, 163 insertions(+), 1272 deletions(-)
```

## 2. The credential leak was three lines, not one

T030 named one line, `scanners/rtsp_probe.py:146`. The test written first (T025) found two
of them and the reading of the file found the third. All three are gone.

The test is `tests/test_logging.py`, and it failed before the fix with the leak named:

```
$ uv run pytest tests/test_logging.py -q
a credential reached the log: ['rtsp://leakeduser:leakedpassword@10.0.0.5:554/live', 'No frame for rtsp://leakeduser:leakedpassword@10.0.0.5:554/live']
```

The three sites:

| Site | Line, before | What it wrote |
|------|--------------|---------------|
| DEBUG, on opening the camera | `logging.debug("Opening %s", target.url)` | the whole URL, credentials included |
| DEBUG, when no frame arrives | `logging.debug("No frame for %s", url)` | the same URL |
| INFO, when the camera answers | `logging.info("[!] %s:%s - user: %s password: %s", ...)` | the user and the password in two fields |

The probe now logs the address and the port only. `_grab` carries the reason in its
docstring, so the next edit does not reintroduce it:

```python
def _grab(self, url: str, target: RtspTarget) -> ProbeResult | None:
    """Log what was reached by address only: the URL carries the credentials."""
```

The test keeps a positive control, so it can fail for the right reason: the same run also
asserts the URL handed to the capture still carries both credentials. Without that, a probe
that opened nothing at all would pass.

```
$ uv run pytest tests/test_logging.py -q
3 passed
```

## 3. The direct transport, covered before the removal

T026 asks for a test that the direct path still works once the proxy is gone, and it was
written before the proxy code was deleted, so it passed against the old tree as well:

```
$ uv run pytest tests/test_rtsp_direct.py -q
4 passed
```

It replaces the cv2 capture with `FakeCapture` in `tests/conftest.py`, so the probe is
exercised with no camera and no ffmpeg: the URL that reaches the capture is the target URL
with nothing configured, the camera comes back with its address, the frame comes back, and
a capture that reads nothing returns `None` instead of raising.

## 4. What was removed

- `scanners/proxy.py` and `scanners/proxy_tunnel.py` (D11), with `TwoCaptchaProxy`,
  `AnonymousProxyClient`, `ProxyTunnel` and the two handshakes.
- The `proxy` config model and field in `scanners/config.py`, and `_nmap_proxy` in
  `main.py`. `NmapTask` now takes `(config, database)`.
- The proxy branch of the nmap check: `_NMAP_PROXY_SCHEMES`, `UnsupportedProxySchemeError`
  and `_proxy_arguments`, so `_scan` is `arguments = f"-p {self._ports_argument()} -sV"`.
- `curl_cffi` from `pyproject.toml`, and `uv lock` removed six packages with it:
  `curl-cffi v0.15.0`, `cffi v2.1.1`, `pycparser v3.0`, `rich v15.0.0`,
  `markdown-it-py v4.2.0`, `mdurl v0.1.2`. The lockfile was regenerated, never edited.
- The `proxy` section of `config.yaml.example`, which closes deviation D-1.
- `_sanitize_city` in `models/managers.py`, which mutated its argument. Deleting it is safe
  because the column default covers an explicit `None`: a `Camera(city=None)` insert stores
  `''`, which is what the helper was producing by hand.
- The unreachable low-priority branch and the `_LOW_PRIORITY_COUNT` / `_LOW_PRIORITY_LIMIT`
  / `_should_skip_low_priority` class state in `scanners/task.py`.
- `_probe_names.py`, `docs/proxy-investigation.md`, `proxylist.txt` and `.serena/` (D23).
- `docs/KNOWLEDGE.md` from 322 to 144 lines (D36): the current-state sections went to
  `plan.md`, `contracts/cli.md` and `docs/decisions/`, and what is left is the dated session
  log with its raw evidence.

## 5. What Front 2 does not cover, and what it leaves behind

**Not covered, on purpose.** The README still documents the proxy, in its mode table, its
configuration table and its examples. The plan puts the README rewrite in Front 5 (T074),
after the commands it documents exist, so the proxy text is stale until then and is the one
place where the repository still describes code that is gone.

**The local `config.yaml` still has a `proxy:` section.** The file is git-ignored and holds
credentials, so no tool edited it. Pydantic ignores the extra keys, so the scanner loads and
runs, but the section is dead text. It is six lines to delete by hand, from `proxy:` down to
`gateway_password:`.

**One leftover kept on purpose.** `Transport` in `scanners/rtsp_probe.py` is a Protocol with
a single implementation, `DirectTransport`. The plan does not retire it and removing it is a
refactor of the probe rather than a deletion of the proxy, so it stays. It is the shape that
the read-only CVE front can implement if a frame ever has to come from somewhere other than
RTSP.

**Open risk carried into Front 3**, unchanged from section 5 of the Front 1 report: the 224
rows migrated at status `unknown` are exactly what
`CameraRepository.get_random_without_frame()` selects, so a `scan check` pointed at this
database would run credential combinations against all of them. The target gate of the check
task has to close that before the check command is wired to the CLI.
