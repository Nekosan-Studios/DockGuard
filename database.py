from sqlmodel import Session, SQLModel, create_engine

DATABASE_URL = "sqlite:///docker_security_watch.db"

engine = create_engine(DATABASE_URL)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
