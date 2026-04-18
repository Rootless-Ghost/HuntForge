"""
HuntForge — PostgreSQL storage layer.

Schema is managed externally via init-db/. Table expected: huntforge_playbooks
"""

import json
import logging
import os
import uuid
from datetime import datetime

import psycopg2
import psycopg2.extras

logger = logging.getLogger("huntforge.storage")


class PlaybookStorage:

    def __init__(self, db_path: str = "./huntforge.db"):
        self._url = os.environ.get("DATABASE_URL") or db_path

    def _get_conn(self):
        return psycopg2.connect(self._url)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_playbook(self, playbook: dict) -> dict:
        playbook_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        log_sources = playbook.get("context", {}).get("log_sources", [])
        env = playbook.get("context", {}).get("environment", "windows")

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO huntforge_playbooks
                        (id, technique_id, technique_name, tactic,
                         environment, log_sources, playbook_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM huntforge_playbooks WHERE id = %s", (playbook_id,)
                )
                row = cur.fetchone()
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
            conditions.append("LOWER(tactic) LIKE LOWER(%s)")
            params.append(f"%{tactic}%")
        if technique_id:
            conditions.append("LOWER(technique_id) LIKE LOWER(%s)")
            params.append(f"%{technique_id}%")
        if search:
            conditions.append(
                "(LOWER(technique_id) LIKE LOWER(%s)"
                " OR LOWER(technique_name) LIKE LOWER(%s)"
                " OR LOWER(tactic) LIKE LOWER(%s))"
            )
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) FROM huntforge_playbooks {where}", params)
                total = cur.fetchone()["count"]
                cur.execute(
                    f"""
                    SELECT id, technique_id, technique_name, tactic,
                           environment, log_sources, created_at
                    FROM huntforge_playbooks {where}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [per_page, offset],
                )
                rows = cur.fetchall()

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
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM huntforge_playbooks WHERE id = %s", (playbook_id,)
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM huntforge_playbooks")
                count = cur.rowcount
            conn.commit()
        return count
