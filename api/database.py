import aiosqlite
import json
import os

DB_PATH = os.environ.get("DB_PATH", "data/finguard.db")


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                repo        TEXT NOT NULL,
                branch      TEXT DEFAULT '',
                commit_sha  TEXT DEFAULT '',
                risk_score  INTEGER DEFAULT 0,
                decision    TEXT DEFAULT 'ALLOW',
                violations  TEXT DEFAULT '[]',
                summary     TEXT DEFAULT '{}',
                context     TEXT DEFAULT '{}',
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS rule_feedback (
                rule_id        TEXT PRIMARY KEY,
                fired          INTEGER DEFAULT 0,
                confirmed      INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0
            )
        """)
        await db.commit()


async def save_scan(
    repo: str, branch: str,
    commit_sha: str, result: dict
) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO scan_results
              (repo, branch, commit_sha, risk_score, decision,
               violations, summary, context)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            repo, branch, commit_sha,
            result.get("risk_score", 0),
            result.get("decision", "ALLOW"),
            json.dumps(result.get("violations", [])),
            json.dumps(result.get("summary", {})),
            json.dumps(result.get("context", {}))
        ))
        await db.commit()
        return cursor.lastrowid


async def get_recent_scans(limit: int = 20) -> list:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT id, repo, branch, commit_sha,
                   risk_score, decision, summary, created_at
            FROM scan_results
            ORDER BY created_at DESC LIMIT ?
        """, (limit,))
        rows = await cur.fetchall()
        result = []
        for r in rows:
            row = dict(r)
            # Parse summary JSON
            try:
                row["summary"] = json.loads(row["summary"])
            except Exception:
                row["summary"] = {}
            result.append(row)
        return result


async def get_dashboard_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT decision, COUNT(*) as count
            FROM scan_results
            GROUP BY decision
        """)
        rows = await cur.fetchall()
        return {r["decision"]: r["count"] for r in rows}


async def get_scan_by_id(scan_id: int) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
        )
        row = await cur.fetchone()
        if not row:
            return {}
        result = dict(row)
        for field in ("violations", "summary", "context"):
            try:
                result[field] = json.loads(result[field])
            except Exception:
                result[field] = {} if field != "violations" else []
        return result