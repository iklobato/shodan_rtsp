# Front 4 report: the read-only CVE classes

Front 4 of D12: the four CVE classes of D9, tried in the order of the batch until one yields
a frame, one finding row per camera and CVE updated in place, the frame stored once, every
network step bounded by a timeout, and the ONVIF read recording the model and the firmware
even when it yields no picture. Tasks T047 to T059 of
`specs/001-camera-monitoring-pipeline/tasks.md`.

Branch: `feat/schema-migrations`, on top of `d8aaa40`. Every command below ran on
2026-11-11 (UTC), on this host, against the lab container `shodan_pg` (postgres 16,
`127.0.0.1:5440`) and the mock device on `127.0.0.1:8000` described in
`docs/front-4-rig.md`. Nothing here ran against a third-party host.

The device is a mock. Section 6 says exactly what that leaves unproved.

## 1. Before and after

Before, at `HEAD` in a tree extracted with `git archive HEAD` and run with the repository
venv, so the comparison is the same interpreter and the same dependency set:

```
$ cd /tmp/front4-before && /Users/iklo/shodan_rtsp/.venv/bin/python -m pytest -q
ERROR tests/test_migrations.py::test_upgrade_from_zero_creates_every_table - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_second_upgrade_changes_nothing - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_cam_rows_move_into_the_new_schema - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_legacy_migration_rolls_back_and_keeps_the_old_rows - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
ERROR tests/test_migrations.py::test_downgrade_base_returns_to_zero_tables - FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
74 passed, 5 errors in 6.28s
```

The five errors are the database tests, and they are an artefact of the extracted tree:
`config.yaml` is git-ignored and holds credentials, so the archive has none. Adding 74 and 5
gives the 79 the suite reported at the end of Front 3.

After, in the repository:

```
$ .venv/bin/python -m pytest tests/ -q
107 passed in 21.52s

$ ruff check .
All checks passed!
```

## 2. The read-only property (D-16)

T049 asks for a test that the reads are read-only. What the test asserts is not "GET only,
no body": two of the four classes must send a body, because the sources R5 gathered publish
only those shapes. The Selea read is a form POST to `/cgi-bin/get_file.php`, and the ONVIF
read is a SOAP POST to `/onvif/device_service`. The assertion instead is the exact set of
reads.

The transport records every request, and `tests/test_cve_read_only.py` asserts that the set
of `(method, path)` pairs equals the five declared reads and nothing else:

```
_DECLARED_READS = (
    ("GET", "/onvif-http/snapshot"),
    ("POST", "/cgi-bin/get_file.php"),
    ("GET", "/common/get_file.php"),
    ("GET", "/check.cgi"),
    ("POST", "/onvif/device_service"),
)
```

The methods come from `ReadMethod`, an enum with two members, `get` and `form_post`, so no
write verb can be expressed at all. The test runs the real `HttpReadTransport` over a
loopback server that records what it was asked, and it also asserts the count of stored
frames is at most one and that the camera status did not change. The redirect test sends a
302 and asserts the redirected path is never requested, because `http.client` does not follow
redirects and the class must not add that.

## 3. The transport that never worked (D-17)

The loopback test failed on its first run:

```
TypeError: 'HTTPConnection' object does not support the context manager protocol
```

`HttpReadTransport._read` opened the connection with
`with self._connection(parts) as connection:`, and `http.client.HTTPConnection` has no
`__enter__`. Every real read raised `TypeError` before a byte left the process, and the
earlier tests did not see it because they injected a fake transport. The connection is now
closed in a `finally`, so a read that times out still closes its socket, and the request and
the answer were split into `_answered` to keep the method inside the length limit.

## 4. The identity chain that matched nothing (D-19)

The lab run found this, and it is the largest thing in this front. With the mock device
answering and a real `nmap -sV` naming it, `scan cve` matched nothing at all, in 3.4 seconds:

```
$ .venv/bin/python main.py -v scan cve --camera-id 231
2026-11-11 11:46:25,029 INFO Verbose mode enabled
2026-11-11 11:46:25,039 INFO Starting the CVE task
2026-11-11 11:46:25,282 INFO Executors: finished the CVE task
```

The cause is in the identity the probe looks the CVE up by. `brands.yaml` stored the camera
as `hikvision` / `ip_camera`, and no camera brand has a product the NVD dictionary carries:

```
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' --data-urlencode 'cpeMatchString=cpe:2.3:h:hikvision:ip_camera' --data-urlencode 'resultsPerPage=1' | .venv/bin/python -c "import json,sys; print('totalResults', json.load(sys.stdin)['totalResults'])"
totalResults 0
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' --data-urlencode 'cpeMatchString=cpe:2.3:h:hikvision:ds-2cd2032-i' --data-urlencode 'resultsPerPage=1' | .venv/bin/python -c "import json,sys; print('totalResults', json.load(sys.stdin)['totalResults'])"
totalResults 1
$ curl -sG 'https://services.nvd.nist.gov/rest/json/cpes/2.0' --data-urlencode 'cpeMatchString=cpe:2.3:o:hikvision:ds-2cd2032-i_firmware' --data-urlencode 'resultsPerPage=1' | .venv/bin/python -c "import json,sys; print('totalResults', json.load(sys.stdin)['totalResults'])"
totalResults 1
```

A camera CVE names a model, and its vulnerable range sits on the model firmware CPE, part
`o`, while the hardware CPE of that same model is flagged not vulnerable. From the real
record of CVE-2017-7921 in `samples/nvd_camera_sample.json`, 116 cpeMatch entries, 58 of them
vulnerable, every one of the 58 on a `hikvision:<model>_firmware` product:

```
$ .venv/bin/python -c "
import json
from scanners.vuln_probe import NvdRecordParser
feed = json.load(open('samples/nvd_camera_sample.json'))
parser = NvdRecordParser()
for record in feed['vulnerabilities']:
    cve = record['cve']
    matches = [(m.get('vulnerable'), m.get('criteria')) for c in cve.get('configurations', []) for n in c.get('nodes', []) for m in n.get('cpeMatch', [])]
    entry = parser.parse(record)
    print(cve['id'], 'matches=', len(matches), 'vulnerable_true=', sum(1 for v, _ in matches if v), '-> entry:', None if entry is None else len(entry.ranges))
"
CVE-2016-15055 matches= 0 vulnerable_true= 0 -> entry: None
CVE-2017-7921 matches= 116 vulnerable_true= 58 -> entry: 58
CVE-2025-34022 matches= 0 vulnerable_true= 0 -> entry: None
CVE-2025-65856 matches= 2 vulnerable_true= 1 -> entry: 1
```

Two things follow. The lookup now retries a pair as `<product>_firmware`, once, only when the
pair itself found nothing, so the match is not widened. And the brand file gained a
model-level entry, because the brand pair can never reach a CVE:

```
$ .venv/bin/python -c "
from scanners.vuln_probe import VulnProbe, CveFeed, CpeMap, DeviceFingerprint
probe = VulnProbe(CveFeed('samples/nvd_camera_sample.json'), CpeMap('cpe_map.yaml'))
for vendor, product in (('hikvision', 'ip_camera'), ('hikvision', 'ds-2cd2032-i')):
    device = DeviceFingerprint(host='127.0.0.1', port=8000, vendor=vendor, product=product)
    print(f'{vendor}:{product} ->', [(m.cve_id, m.cvss) for m in probe.match(device)])
"
hikvision:ip_camera -> []
hikvision:ds-2cd2032-i -> [('CVE-2017-7921', 9.8)]
```

The test for the retry was written first and failed with
`AssertionError: the model firmware CPE is the one the range names, got []`, and a second
test asserts that a pair the feed carries in neither form still matches nothing.

The two records with no cpeMatch at all are the other half of the same finding, and it is
D-20: `CVE-2016-15055` (JVC) and `CVE-2025-34022` (Selea) carry no configuration in NVD, so
`NvdRecordParser` drops them and no device can ever select those two classes. They stay in
the batch, because a feed that carries a CPE for them selects them the same way.

Why the suite was green while the front could not match, which is D-21: the feed in
`tests/test_version_range.py` was written by hand with the product
`cpe:2.3:o:hikvision:ip_camera`, a name the NVD dictionary does not carry. The test agreed
with the code, not with the feed. The file now also carries the record shape a real camera
CVE has.

## 5. The lab run (T059)

The device state before the run, the access log of the mock after the `scan nmap` that named
it, copied aside:

```
$ wc -l /tmp/mock_before.log
      86 /tmp/mock_before.log
$ tail -3 /tmp/mock_before.log
127.0.0.1 - - [11/Nov/2026 11:58:08] "GET / HTTP/1.1" 404 -
127.0.0.1 - - [11/Nov/2026 11:58:09] code 400, message Bad HTTP/0.9 request type ('\\x80\\x00\\x00((²²>\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x01\\x86')
127.0.0.1 - - [11/Nov/2026 11:58:09] "\x80\x00\x00((²²>\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86 ..." 400 -
```

The camera row the real scan stored, and the tables the run was about to write:

```
$ docker exec shodan_pg psql -U scanner -d cameras -c "select id, ip, port, status, vendor, product, version, raw_banner from camera where id = 231;"
 id  |    ip     | port | status  |  vendor   |   product    | version |                                                            raw_banner
-----+-----------+------+---------+-----------+--------------+---------+-----------------------------------------------------------------------------------------------------------------------------------
 231 | 127.0.0.1 | 8000 | unknown | hikvision | ds-2cd2032-i |         | {"cpe": "", "banner": "Hikvision-Webs/DS-2CD2032-I ", "source": "nmap", "product": "Hikvision-Webs/DS-2CD2032-I ", "version": ""}

$ docker exec shodan_pg psql -U scanner -d cameras -t -c "select count(*) from cve_finding;" -c "select count(*) from face_frame;"
     0

     0
```

The run:

```
$ time .venv/bin/python main.py -v scan cve --camera-id 231
2026-11-11 11:58:31,784 INFO Verbose mode enabled
2026-11-11 11:58:31,796 INFO Starting the CVE task
2026-11-11 11:58:32,080 INFO 127.0.0.1:8000 matches 1 CVE(s)
2026-11-11 11:58:32,123 INFO CVE read GET http://127.0.0.1:8000/onvif-http/snapshot?auth=YWRtaW46MTEK
2026-11-11 11:58:32,217 INFO Executors: finished the CVE task
.venv/bin/python main.py -v scan cve --camera-id 231 2>&1  3.08s user 1.01s system 101% cpu 4.019 total
```

The device state after, and the difference from before:

```
$ diff /tmp/mock_before.log logs/mock_camera.log
86a87,90
> 127.0.0.1 - - [11/Nov/2026 11:58:32] "GET /onvif-http/snapshot?auth=YWRtaW46MTEK HTTP/1.1" 200 -
> 127.0.0.1 - - [11/Nov/2026 12:02:10] "GET /onvif-http/snapshot HTTP/1.1" 404 -
> 127.0.0.1 - - [11/Nov/2026 12:02:10] "GET /check.cgi?file=/etc/passwd HTTP/1.1" 404 -
> 127.0.0.1 - - [11/Nov/2026 12:02:10] "GET /common/get_file.php HTTP/1.1" 404 -
```

The run added exactly one line, the first of the four: one GET, answered 200. The three lines
at 12:02:10 are the manual checks quoted in `docs/front-4-rig.md`, run afterwards and also
reads. No line of the log is a write, and no line of the run is anything but the one request
the matched class sends.

The rows it wrote, and the frame on disk:

```
$ docker exec shodan_pg psql -U scanner -d cameras -c "select id, camera_id, cve_id, cve_class, outcome, matched_range, frame_id, failure_reason from cve_finding;"
 id | camera_id |    cve_id     |  cve_class  |    outcome     | matched_range | frame_id | failure_reason
----+-----------+---------------+-------------+----------------+---------------+----------+----------------
  1 |       231 | CVE-2017-7921 | auth_bypass | frame_obtained |               |        1 |

$ docker exec shodan_pg psql -U scanner -d cameras -c "select id, camera_id, scan_run_id, source, path, width, height, captured_at from face_frame;"
 id | camera_id | scan_run_id | source |             path             | width | height |          captured_at
----+-----------+-------------+--------+------------------------------+-------+--------+-------------------------------
  1 |       231 |           9 | cve    | 231/20261111T145832Z-cve.jpg |   640 |    480 | 2026-11-11 14:58:32.161091+00

$ ls -l logs/frames/231/
total 16
-rw-r--r--@ 1 iklo  staff  5427 Nov 11 11:58 20261111T145832Z-cve.jpg
$ file logs/frames/231/20261111T145832Z-cve.jpg
logs/frames/231/20261111T145832Z-cve.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 640x480, components 3

$ docker exec shodan_pg psql -U scanner -d cameras -c "select id, ip, port, status, vendor, product, version from camera where id=231;"
 id  |    ip     | port |    status    |  vendor   |   product    | version
-----+-----------+------+--------------+-----------+--------------+---------
 231 | 127.0.0.1 | 8000 | frame_by_cve | hikvision | ds-2cd2032-i |

$ docker exec shodan_pg psql -U scanner -d cameras -c "select id, kind, target_set, started_at, finished_at from scan_run order by id desc limit 2;"
 id | kind |  target_set  |          started_at           |          finished_at
----+------+--------------+-------------------------------+-------------------------------
  9 | cve  | 127.0.0.1    | 2026-11-11 14:58:32.06065+00  | 2026-11-11 14:58:32.19499+00
  8 | nmap | 127.0.0.1/32 | 2026-11-11 14:56:36.300954+00 | 2026-11-11 14:58:09.572472+00
```

The frame on disk is 5427 bytes, the same size the device answered with in
`docs/front-4-rig.md`, and the row carries 640x480, the size the encoder wrote. The run is
closed, its target set was recorded before any packet left, and the camera moved from
`unknown` to `frame_by_cve`.

SC-004 holds for this device: one frame obtained, and the state before and after identical
apart from the one read.

## 6. What this front does not prove

- The device is a mock. Nothing here says anything about Hikvision firmware, and the class is
  not proved against the real flaw, only against the request shape the advisory publishes.
  T008 was not done: `docs/front-4-rig.md` records why.
- Only one of the four classes ran. A class runs only when its CVE matched the camera, and
  this device matched one. The order of the batch is covered by
  `tests/test_cve_class_order.py`, not by this run.
- The other three classes were never sent at a device that answers, so what they read is
  covered by tests and by the read-only assertion, not by a live read.
- The timeout is covered by `tests/test_cve_timeout.py` over real sockets, not by this run.
- Two of the four classes can never be selected while the feed carries no CPE for their
  CVE, which is D-20 above.
- Every brand pair in `brands.yaml` except the one model entry still matches no CVE. Fixing
  that needs a model list per brand, checked against the NVD dictionary, and it is data
  work, not code.
