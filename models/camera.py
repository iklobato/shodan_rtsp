from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Camera(Base):
    __tablename__ = "cam"

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    port = Column(Integer)
    user = Column(String, default="")
    password = Column(String, default="")
    url = Column(String, default="")
    active = Column(Boolean, default=False)
    city = Column(String, default="")
    country_code = Column(String, default="")
    country_name = Column(String, default="")
    region_code = Column(String, default="")
    image_b64 = Column(String, default="")
    added_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Camera {self.ip}:{self.port} ({self.city}, {self.country_code}) - {self.active}>"
