from sqlmodel import Session, create_engine

DATABASE_URL = "sqlite:///docker_security_watch.db"


class Database:

    def __init__(self, url: str = DATABASE_URL):
        self.engine = create_engine(url)

    def init(self):
        from alembic import command
        from alembic.config import Config
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")

    def get_session(self):
        with Session(self.engine) as session:
            yield session


db = Database()
