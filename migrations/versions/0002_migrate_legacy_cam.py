"""migrate the legacy cam table into camera and camera_observation

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-11 10:20:00.000000

`cam` is what the scanner wrote before the schema of 0001: 229 rows, all of them
from one Shodan scan on 2026-08-09 that named no address range. The pipeline
refuses to run that query now (FR-001), but the rows are already here, so they
move as they are instead of being lost with the table.

They move under one scan_run whose target_set says where they came from. That
string is not a range, and it is not meant to be read as one: it is the record
that these rows have no declared target, which is the only honest thing a run
row can say about them.

Three columns do not survive as they were. `active` becomes the status, because
the CVE path never authenticates over RTSP and a boolean cannot say how a frame
was obtained (D33): the 5 rows that were active become `stream_obtained` and the
other 224 become `unknown`. `vendor`, `product` and `version` arrive empty,
because the old table never identified anything and empty is what the rest of
the schema means by "not known". The 5 frames in `image_b64` stay in `cam`,
which is not dropped by this revision or by any other; moving them needs the
decode to a file that D17 asks for, and that is a separate job.

Nothing here runs on a database that never had `cam`, so a fresh install and the
migration test are unaffected.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LEGACY_TABLE = "cam"
LEGACY_TARGET_SET = (
    "unknown: imported from the legacy cam table "
    "(shodan scan of 2026-08-09 that declared no range)"
)
_ACTIVE_STATUS = "stream_obtained"
_INACTIVE_STATUS = "unknown"

_INSERT_CAMERAS = """
INSERT INTO camera (
    ip, port, "user", password, url, status,
    vendor, product, version,
    city, country_code, country_name, region_code, added_at, updated_at
)
SELECT
    cam.ip,
    cam.port,
    coalesce(cam."user", ''),
    coalesce(cam.password, ''),
    coalesce(cam.url, ''),
    (CASE WHEN cam.active THEN 'stream_obtained' ELSE 'unknown' END)::camera_status,
    '',
    '',
    '',
    coalesce(cam.city, ''),
    coalesce(cam.country_code, ''),
    coalesce(cam.country_name, ''),
    coalesce(cam.region_code, ''),
    coalesce(cam.added_at, now()),
    coalesce(cam.updated_at, now())
FROM cam
ON CONFLICT (ip, port) DO NOTHING
"""

# One observation per migrated camera, against the run this revision opened. The
# join is on (ip, port), the identity of a camera, so a row that collided with a
# camera already in the table still gets its observation on that camera.
_INSERT_OBSERVATIONS = """
INSERT INTO camera_observation (
    camera_id, scan_run_id, port, status, vendor, product, version, observed_at
)
SELECT camera.id, :run_id, cam.port, camera.status,
       camera.vendor, camera.product, camera.version,
       coalesce(cam.added_at, now())
FROM cam
JOIN camera ON camera.ip = cam.ip AND camera.port = cam.port
ON CONFLICT (camera_id, scan_run_id, port) DO NOTHING
"""

_OPEN_RUN = """
INSERT INTO scan_run (kind, target_set, started_at, finished_at, camera_count)
VALUES ('shodan', :target_set, now(), now(), 0)
RETURNING id
"""

_FIND_RUN = "SELECT id FROM scan_run WHERE target_set = :target_set"

_COUNT_OBSERVATIONS = (
    "SELECT count(*) FROM camera_observation WHERE scan_run_id = :run_id"
)

_CLOSE_RUN = "UPDATE scan_run SET camera_count = :count WHERE id = :run_id"

_DROP_OBSERVATIONS = "DELETE FROM camera_observation WHERE scan_run_id = :run_id"

# The cameras this revision brought in, never one that another run also
# observed: a camera shared with a real scan has to outlive the rollback. It has
# to be read before the observations go, because that is where the answer lives.
_CAMERAS_ONLY_IN_RUN = """
SELECT camera_id FROM camera_observation WHERE scan_run_id = :run_id
EXCEPT
SELECT camera_id FROM camera_observation WHERE scan_run_id <> :run_id
"""

_DROP_CAMERAS = "DELETE FROM camera WHERE id = ANY(:ids)"

_DROP_RUN = "DELETE FROM scan_run WHERE id = :run_id"


def upgrade() -> None:
    """Move the legacy rows into the new schema, once."""
    connection = op.get_bind()
    if LEGACY_TABLE not in sa.inspect(connection).get_table_names():
        return
    already = connection.execute(
        sa.text(_FIND_RUN), {"target_set": LEGACY_TARGET_SET}
    ).first()
    if already is not None:
        return

    run_id = connection.execute(
        sa.text(_OPEN_RUN), {"target_set": LEGACY_TARGET_SET}
    ).scalar_one()
    connection.execute(sa.text(_INSERT_CAMERAS))
    connection.execute(sa.text(_INSERT_OBSERVATIONS), {"run_id": run_id})
    count = connection.execute(
        sa.text(_COUNT_OBSERVATIONS), {"run_id": run_id}
    ).scalar_one()
    connection.execute(sa.text(_CLOSE_RUN), {"count": count, "run_id": run_id})


def downgrade() -> None:
    """Take the migrated rows back out. `cam` keeps them, so nothing is lost."""
    connection = op.get_bind()
    run = connection.execute(
        sa.text(_FIND_RUN), {"target_set": LEGACY_TARGET_SET}
    ).first()
    if run is None:
        return
    run_id = run[0]
    doomed = [
        row[0]
        for row in connection.execute(sa.text(_CAMERAS_ONLY_IN_RUN), {"run_id": run_id})
    ]
    connection.execute(sa.text(_DROP_OBSERVATIONS), {"run_id": run_id})
    if doomed:
        connection.execute(sa.text(_DROP_CAMERAS), {"ids": doomed})
    connection.execute(sa.text(_DROP_RUN), {"run_id": run_id})
