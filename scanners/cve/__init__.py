"""The CVE batch of D9, and the order the classes are tried in."""

from scanners.cve.auth_bypass import HikvisionAuthBypass
from scanners.cve.base import CveAttempt
from scanners.cve.snapshot_read import CgiImageRead, StaticSnapshotRead, StreamPathRead
from scanners.cve.unauth_onvif import XiongmaiOnvifInfo
from scanners.cve.unauth_read import JvcFileRead, SeleaFileRead

# D9: the classes that yield a picture first, then the two file reads, then the
# one that only describes the device. The task stops at the first frame (FR-017).
CVE_BATCH: tuple[type[CveAttempt], ...] = (
    HikvisionAuthBypass,
    StaticSnapshotRead,
    StreamPathRead,
    CgiImageRead,
    SeleaFileRead,
    JvcFileRead,
    XiongmaiOnvifInfo,
)
