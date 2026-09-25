from sqlalchemy import create_engine, text  # type: ignore[reportMissingImports]
from sqlalchemy.orm import DeclarativeBase, sessionmaker  # type: ignore[reportMissingImports]
from config import settings

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models import User, Investigation, Report  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Lightweight migration for existing SQLite databases.
    if settings.DATABASE_URL.startswith("sqlite"):
        with engine.begin() as connection:
            columns = connection.execute(
                text("PRAGMA table_info(users)")
            ).fetchall()

            column_names = {column[1] for column in columns}

            if "auth_provider" not in column_names:
                connection.execute(
                    text(
                        "ALTER TABLE users "
                        "ADD COLUMN auth_provider VARCHAR(20) "
                        "NOT NULL DEFAULT 'local'"
                    )
                )

            if "google_id" not in column_names:
                connection.execute(
                    text(
                        "ALTER TABLE users "
                        "ADD COLUMN google_id VARCHAR(255)"
                    )
                )

            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "ix_users_google_id ON users (google_id)"
                )
            )
