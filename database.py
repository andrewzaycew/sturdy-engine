import sqlite3
from pathlib import Path
from time import time
from typing import Optional, Tuple, List, Dict
from loguru import logger

DB_PATH = Path("sessions.db")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
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
                created_at INTEGER NOT NULL,
                twofa_password TEXT
            );
            """
        )
        # Migration: add twofa_password column if missing
        cur = conn.execute("PRAGMA table_info(sessions)")
        columns = {row[1] for row in cur.fetchall()}
        if "twofa_password" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN twofa_password TEXT")

        # Device sessions (active/expired list)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_model TEXT,
                system_version TEXT,
                app_name TEXT,
                app_version TEXT,
                ip TEXT,
                country TEXT,
                region TEXT,
                created_at INTEGER NOT NULL,
                last_active INTEGER,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        # Task queue for background jobs
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )

        conn.commit()
    logger.info("Database initialized at {}", DB_PATH.resolve())


def add_session(session_uuid: str, android_id: str, auth_key_hex: str, dc_id: int, user_id: int, twofa_password: Optional[str] = None) -> None:
    created_at = int(time())
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (session_uuid, android_id, auth_key_hex, dc_id, user_id, created_at, twofa_password)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_uuid) DO UPDATE SET
                android_id=excluded.android_id,
                auth_key_hex=excluded.auth_key_hex,
                dc_id=excluded.dc_id,
                user_id=excluded.user_id,
                created_at=excluded.created_at,
                twofa_password=excluded.twofa_password
            ;
            """,
            (session_uuid, android_id, auth_key_hex, int(dc_id), int(user_id), created_at, twofa_password),
        )
        conn.commit()
    logger.debug("Session {} saved for user {} (dc {})", session_uuid, user_id, dc_id)


def get_session_data(session_uuid: str) -> Optional[Tuple[str, int, int, Optional[str]]]:
    with _get_connection() as conn:
        cur = conn.execute(
            "SELECT auth_key_hex, dc_id, user_id, twofa_password FROM sessions WHERE session_uuid = ?",
            (session_uuid,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return row[0], int(row[1]), int(row[2]), row[3]


def remove_session_from_db(session_uuid: str) -> None:
    with _get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE session_uuid = ?", (session_uuid,))
        conn.commit()
    logger.info("Session {} removed from DB", session_uuid)


def set_session_twofa_password(session_uuid: str, twofa_password: Optional[str]) -> None:
    with _get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET twofa_password = ? WHERE session_uuid = ?",
            (twofa_password, session_uuid),
        )
        conn.commit()
    logger.debug("Updated 2FA password for session {}", session_uuid)


# Device sessions helpers

def save_device_sessions(user_id: int, sessions: List[Dict]) -> None:
    now = int(time())
    with _get_connection() as conn:
        for s in sessions:
            conn.execute(
                """
                INSERT INTO device_sessions (user_id, device_model, system_version, app_name, app_version, ip, country, region, created_at, last_active, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    s.get("device_model"),
                    s.get("system_version"),
                    s.get("app_name"),
                    s.get("app_version"),
                    s.get("ip"),
                    s.get("country"),
                    s.get("region"),
                    s.get("created_at", now),
                    s.get("last_active"),
                    int(s.get("revoked", 0)),
                ),
            )
        conn.commit()


def list_device_sessions(user_id: int) -> List[sqlite3.Row]:
    with _get_connection() as conn:
        cur = conn.execute(
            "SELECT id, device_model, system_version, app_name, app_version, ip, country, region, created_at, last_active, revoked FROM device_sessions WHERE user_id = ? ORDER BY revoked, last_active DESC NULLS LAST, created_at DESC",
            (user_id,),
        )
        return cur.fetchall()


def revoke_device_session(session_id: int) -> None:
    with _get_connection() as conn:
        conn.execute("UPDATE device_sessions SET revoked = 1 WHERE id = ?", (session_id,))
        conn.commit()


# Task queue helpers

def enqueue_task(task_id: str, task_type: str, payload_json: str) -> None:
    now = int(time())
    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO tasks (id, type, payload, status, progress, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (task_id, task_type, payload_json, "queued", 0, now, now),
        )
        conn.commit()


def update_task(task_id: str, status: str, progress: int) -> None:
    now = int(time())
    with _get_connection() as conn:
        conn.execute(
            "UPDATE tasks SET status = ?, progress = ?, updated_at = ? WHERE id = ?",
            (status, progress, now, task_id),
        )
        conn.commit()


def get_task(task_id: str) -> Optional[sqlite3.Row]:
    with _get_connection() as conn:
        cur = conn.execute("SELECT id, type, payload, status, progress, created_at, updated_at FROM tasks WHERE id = ?", (task_id,))
        return cur.fetchone()