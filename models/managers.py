import logging

from sqlalchemy import func

from models.camera import Camera, DatabaseConnection


class CameraManager(DatabaseConnection):

    def insert_into_cameras(self, ip, port, user, password, url, city, country_code, country_name, region_code):
        city = city.replace("'", "").replace('"', '').replace(';', '')
        camera = Camera(ip=ip, port=port, user=user, password=password, url=url, active=False,
                        city=city, country_code=country_code, country_name=country_name, region_code=region_code)
        with self.session as session:
            session.add(camera)
            session.commit()

    def get_random_from_db(self):
        with self.session as session:
            return session.query(Camera).filter(Camera.active == 0).order_by(func.random()).all()

    def get_from_db(self):
        with self.session as session:
            return session.query(Camera).filter(Camera.active == 0).all()

    def search_on_db(self, ip, port):
        with self.session as session:
            return session.query(Camera).filter(Camera.ip == ip, Camera.port == port).all()

    def update_active_from_db(self, ip, port):
        with self.session as session:
            camera = session.query(Camera).filter(Camera.ip == ip, Camera.port == port).first()
            if not camera:
                logging.debug(f'Camera {ip}:{port} not found')
                return False
            camera.active = 1
            session.commit()
            logging.debug(f'Updated {ip}:{port} to active')
            return True

    def update_from_db_values(self, host, port, user, password, rtsp_string, active):
        with self.session as session:
            camera = session.query(Camera).filter(Camera.ip == host, Camera.port == port).first()
            if camera:
                camera.user = user
                camera.password = password
                camera.url = rtsp_string
                camera.active = active
                session.commit()
                logging.debug(f'Updated {host}:{port} with {user}:{password} and {rtsp_string}')
