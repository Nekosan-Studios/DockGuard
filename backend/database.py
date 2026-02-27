import os

from sqlmodel import Session, create_engine

DATABASE_PATH = os.environ.get("DATABASE_PATH", "docker_security_watch.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Database:

    def __init__(self, url: str = DATABASE_URL):
        self.engine = create_engine(url)

    def init(self):
        from pathlib import Path

        from alembic import command
        from alembic.config import Config
        alembic_cfg = Config(str(Path(__file__).parent / "alembic.ini"))
        command.upgrade(alembic_cfg, "head")

    def get_session(self):
        with Session(self.engine) as session:
            yield session


db = Database()
