"""The camera entity refuses bad input before it reaches the database."""

import pytest

from models.base import InvalidEntity
from models.camera import Camera, CameraStatus
from tests.conftest import MemoryDatabase

_RTSP_PORT = 554
_ADDRESS = "10.0.0.1"


def test_a_camera_stored_without_a_status_comes_back_unknown(
    database: MemoryDatabase,
) -> None:
    """The default is the database's, so it only shows after the insert."""
    with database.session_scope() as session:
        session.add(Camera(ip=_ADDRESS, port=_RTSP_PORT))
    with database.session_scope() as session:
        assert session.query(Camera).one().status is CameraStatus.unknown


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_camera_refuses_a_port_outside_the_range(port: int) -> None:
    with pytest.raises(InvalidEntity, match="port out of range"):
        Camera(ip=_ADDRESS, port=port)


def test_camera_refuses_an_address_that_does_not_parse() -> None:
    with pytest.raises(InvalidEntity, match="ip does not parse"):
        Camera(ip="not-an-address", port=_RTSP_PORT)


def test_camera_refuses_an_empty_address() -> None:
    with pytest.raises(InvalidEntity, match="ip is required"):
        Camera(ip="", port=_RTSP_PORT)


def test_camera_refuses_a_banner_that_is_not_an_object() -> None:
    with pytest.raises(InvalidEntity, match="raw_banner must be a JSON object"):
        Camera(ip=_ADDRESS, port=_RTSP_PORT, raw_banner="554/tcp open rtsp")


@pytest.mark.parametrize("status", list(CameraStatus))
def test_every_status_survives_a_round_trip(
    database: MemoryDatabase, status: CameraStatus
) -> None:
    """The status is the record of how far the pipeline got, so it must come back."""
    with database.session_scope() as session:
        session.add(Camera(ip=_ADDRESS, port=_RTSP_PORT, status=status))
    with database.session_scope() as session:
        assert session.query(Camera).one().status is status
