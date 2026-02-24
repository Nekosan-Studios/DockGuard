from sqlmodel import Session, SQLModel, create_engine

DATABASE_URL = "sqlite:///docker_security_watch.db"


class Database:

    def __init__(self, url: str = DATABASE_URL):
        self.engine = create_engine(url)

    def init(self):
        SQLModel.metadata.create_all(self.engine)

    def get_session(self):
        with Session(self.engine) as session:
            yield session


db = Database()
