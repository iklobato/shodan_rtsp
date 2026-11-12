# shodan_rtsp: knowledge index

Snapshot: `main` @ `ff75d0b` (2026-11-12). Verified by reading the files this session touched
plus `uv run pytest -q` and `uv run ruff check .`; the six `test_migrations` cases were skipped
because the lab postgres container was down (port 5440 refused).

The session history log stays in `docs/KNOWLEDGE.md` (append-only, one section per session).
This folder holds topic files that describe the code as it stands.

## Status at a glance

- **Done:** the CVE batch covers 11 camera CVEs over three snapshot path families, on top of the
  four original classes; `brands.yaml` reaches the model firmware CPEs those CVEs hang on.
- **Discovered:** the real ceiling for CVE ids this batch can claim is 11, not 100. Measured
  below, in `cve-batch.md`.
- **Next steps:** an RTSP read class would take the batch from 11 to about 20 of the measured 41.
- **What is left:** the 41 CVE inventory is a keyword floor, not an NVD CPE enumeration; no real
  device answered any of the new paths.
- **Monitor:** whether NVD rewrites a description so a CVE stops naming the path the class reads.

## Topics

- `cve-batch.md`: how the read-only batch is shaped, the 11 added CVEs, and the measured ceiling.

## Session log

- 2026-11-12: added `scanners/cve/snapshot_read.py`, batch 4 to 7 classes, 11 CVEs, five model
  brand entries plus four brand entries, docs and one test. See `cve-batch.md` and the matching
  section at the end of `docs/KNOWLEDGE.md`.
