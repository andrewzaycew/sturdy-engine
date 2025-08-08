import sqlite3
from pathlib import Path
from time import time
from typing import Optional, Tuple
from loguru import logger

DB_PATH = Path("sessions.db")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_uuid TEXT PRIMARY KEY,
                android_id TEXT NOT NULL,
                auth_key_hex TEXT NOT NULL,
                dc_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.commit()
    logger.info("Database initialized at {}", DB_PATH.resolve())


def add_session(session_uuid: str, android_id: str, auth_key_hex: str, dc_id: int, user_id: int) -> None:
    created_at = int(time())
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (session_uuid, android_id, auth_key_hex, dc_id, user_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_uuid) DO UPDATE SET
                android_id=excluded.android_id,
                auth_key_hex=excluded.auth_key_hex,
                dc_id=excluded.dc_id,
                user_id=excluded.user_id,
                created_at=excluded.created_at
            ;
            """,
            (session_uuid, android_id, auth_key_hex, int(dc_id), int(user_id), created_at),
        )
        conn.commit()
    logger.debug("Session {} saved for user {} (dc {})", session_uuid, user_id, dc_id)


def get_session_data(session_uuid: str) -> Optional[Tuple[str, int, int]]:
    with _get_connection() as conn:
        cur = conn.execute(
            "SELECT auth_key_hex, dc_id, user_id FROM sessions WHERE session_uuid = ?",
            (session_uuid,),
        )
        row = cur.fetchone()
        if not row:
            return None
        auth_key_hex, dc_id, user_id = row
        return auth_key_hex, int(dc_id), int(user_id)


def remove_session_from_db(session_uuid: str) -> None:
    with _get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE session_uuid = ?", (session_uuid,))
        conn.commit()
    logger.info("Session {} removed from DB", session_uuid)