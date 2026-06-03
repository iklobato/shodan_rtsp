from models.camera import DatabaseConnection
from models.camera import Camera

db = DatabaseConnection()

# IMPORTANT: ensures models are registered
Base = db.base()

# Create tables
Base.metadata.create_all(db.engine)
