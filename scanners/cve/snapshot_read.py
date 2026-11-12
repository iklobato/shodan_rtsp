"""The unauthenticated snapshot paths vendor CVEs name, one class per family.

Each class here is a plain GET of a path an advisory publishes, and the answer is
the picture itself. The grouping is by the family of paths a device serves, not
by vendor: a device that answers `/snapshot` answers it for the same reason
whatever its brand, so one class proves every CVE that named that path.

Only the paths a source names are sent. A CVE whose advisory names no path at
all is left out of `cve_ids`, because a class that guesses where to read is not
proof of that CVE.
"""

from models.finding import CveClass
from scanners.cve.base import CveTarget, ImageAttempt, ReadMethod, ReadRequest


class SnapshotRead(ImageAttempt):
    """A family of GET paths, all of them returning a picture without a login."""

    _PATHS: tuple[str, ...] = ()
    _CVES: tuple[str, ...] = ()

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return self._CVES

    @property
    def cve_class(self) -> CveClass:
        return CveClass.auth_bypass

    def _requests_for(self, target: CveTarget, port: int) -> tuple[ReadRequest, ...]:
        return tuple(
            ReadRequest(method=ReadMethod.get, url=target.url(port, path))
            for path in self._PATHS
        )


class StaticSnapshotRead(SnapshotRead):
    """The `/snapshot` family: a still image served to anyone who asks.

    NightOwl and Denver both publish `/snapshot`. Denver's backdoor answers it on
    a second HTTP port (8001), so it is reachable only when the config lists that
    port in `web_ports`.
    """

    _PATHS = ("/snapshot", "/snapshot.jpg", "/jpg/image.jpg", "/video.mjpg")
    _CVES = (
        "CVE-2021-31793",
        "CVE-2021-4469",
        "CVE-2021-47796",
        "CVE-2018-18428",
        "CVE-2018-17559",
    )


class StreamPathRead(SnapshotRead):
    """The motion-JPEG family: one long-lived image stream, read as one frame."""

    _PATHS = ("/live.mjpeg", "/snapshot.jpg", "/FC/PT/D")
    _CVES = ("CVE-2018-25141", "CVE-2017-20213")


class CgiImageRead(SnapshotRead):
    """The CGI family: the box firmware names the script, not the file.

    The APEXIS advisory names an unprotected CGI method and no path, and this
    class is the CGI image family it belongs to, so its attempt answers for it.
    """

    _PATHS = ("/cgi-bin/get_jpeg?channel=1", "/cgi-bin/animate.cgi?channel=1")
    _CVES = ("CVE-2019-25236", "CVE-2019-25240", "CVE-2017-17101")
