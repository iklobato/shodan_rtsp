import logging

from sqlalchemy import func

from models.camera import Camera
from models.database import Database


class CameraRepository:
    """Encapsulates every query against the camera table."""

    def __init__(self, database: Database = None):
        self._db = database or Database()

    def insert_camera(self, camera: Camera) -> None:
        camera.city = self._sanitize_city(camera.city)
        with self._db.session_scope() as session:
            session.add(camera)

    def get_random_inactive(self):
        with self._db.session_scope() as session:
            return (
                session.query(Camera)
                .filter(Camera.active.is_(False))
                .order_by(func.random())
                .all()
            )

    def get_inactive(self):
        with self._db.session_scope() as session:
            return session.query(Camera).filter(Camera.active.is_(False)).all()

    def find(self, ip: str, port: int):
        with self._db.session_scope() as session:
            return (
                session.query(Camera).filter(Camera.ip == ip, Camera.port == port).all()
            )

    def set_active(self, camera: Camera) -> bool:
        with self._db.session_scope() as session:
            db_cam = (
                session.query(Camera)
                .filter(Camera.ip == camera.ip, Camera.port == camera.port)
                .first()
            )
            if db_cam is None:
                logging.warning(
                    f"Camera {camera.ip}:{camera.port} not found in the database."
                )
                return False
            db_cam.active = True
            db_cam.url = camera.url
            db_cam.image_b64 = camera.image_b64
            logging.debug(f"Updated {camera.ip}:{camera.port}")
            return True

    def get_active(self):
        with self._db.session_scope() as session:
            return session.query(Camera).filter(Camera.active.is_(True)).all()

    @staticmethod
    def _sanitize_city(city: str) -> str:
        if not city:
            return ""
        return city.replace("'", "").replace('"', "").replace(";", "")
