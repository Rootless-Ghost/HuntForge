"""
HuntForge — SQLite storage layer
"""

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime

logger = logging.getLogger("huntforge.storage")


class PlaybookStorage:
    """Manages the SQLite database for saved playbooks."""

    def __init__(self, db_path: str = "./huntforge.db"):
        self.db_path = db_path
        self._init_db()

    # ── Schema ─────────────────────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbooks (
                    id            TEXT PRIMARY KEY,
                    technique_id  TEXT NOT NULL,
                    technique_name TEXT NOT NULL,
                    tactic        TEXT NOT NULL,
                    environment   TEXT NOT NULL DEFAULT 'windows',
                    log_sources   TEXT NOT NULL DEFAULT '[]',
                    playbook_json TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_technique_id
                ON playbooks (technique_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tactic
                ON playbooks (tactic)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at
                ON playbooks (created_at)
            """)
            conn.commit()
        logger.info("Storage initialised: %s", self.db_path)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_playbook(self, playbook: dict) -> dict:
        """Persist a playbook. Generates a new ID; returns the saved record."""
        playbook_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        log_sources = playbook.get("context", {}).get("log_sources", [])
        env = playbook.get("context", {}).get("environment", "windows")

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO playbooks
                    (id, technique_id, technique_name, tactic,
                     environment, log_sources, playbook_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    playbook_id,
                    playbook.get("technique_id", ""),
                    playbook.get("technique_name", ""),
                    playbook.get("tactic", ""),
                    env,
                    json.dumps(log_sources),
                    json.dumps(playbook),
                    now,
                ),
            )
            conn.commit()

        playbook["id"] = playbook_id
        playbook["created_at"] = now
        logger.info("Saved playbook %s (%s)", playbook_id, playbook.get("technique_id"))
        return playbook

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_playbook(self, playbook_id: str) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
        if row is None:
            return None
        data = json.loads(row["playbook_json"])
        data["id"] = row["id"]
        data["created_at"] = row["created_at"]
        return data

    def list_playbooks(
        self,
        page: int = 1,
        per_page: int = 50,
        tactic: str = "",
        technique_id: str = "",
        search: str = "",
    ) -> dict:
        conditions: list[str] = []
        params: list = []

        if tactic:
            conditions.append("LOWER(tactic) LIKE LOWER(?)")
            params.append(f"%{tactic}%")
        if technique_id:
            conditions.append("LOWER(technique_id) LIKE LOWER(?)")
            params.append(f"%{technique_id}%")
        if search:
            conditions.append(
                "(LOWER(technique_id) LIKE LOWER(?)"
                " OR LOWER(technique_name) LIKE LOWER(?)"
                " OR LOWER(tactic) LIKE LOWER(?))"
            )
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM playbooks {where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, technique_id, technique_name, tactic,
                       environment, log_sources, created_at
                FROM playbooks {where}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()

        items = []
        for r in rows:
            items.append({
                "id":             r["id"],
                "technique_id":   r["technique_id"],
                "technique_name": r["technique_name"],
                "tactic":         r["tactic"],
                "environment":    r["environment"],
                "log_sources":    json.loads(r["log_sources"]),
                "created_at":     r["created_at"],
            })

        return {
            "items":    items,
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_playbook(self, playbook_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM playbooks WHERE id = ?", (playbook_id,)
            )
            conn.commit()
        return cur.rowcount > 0

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM playbooks")
            conn.commit()
        return cur.rowcount
