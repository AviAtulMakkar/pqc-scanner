"""
Database setup — SQLAlchemy engine for PostgreSQL.
Retries connection on startup until PostgreSQL is ready.
"""

import os
import time
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from .models import Base

log = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://pqcuser:pqcpassword@db:5432/pqcscanner"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def wait_for_db(retries: int = 30, delay: float = 2.0):
    """Block until PostgreSQL accepts connections or raise after retries."""
    for attempt in range(1, retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            log.info("Database connection established.")
            return
        except Exception as e:
            log.warning(f"DB not ready (attempt {attempt}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to PostgreSQL after multiple retries.")


def create_tables():
    """Wait for DB then create all tables."""
    wait_for_db()
    Base.metadata.create_all(bind=engine)
    log.info("All tables created / verified.")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
