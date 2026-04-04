"""CVE Knowledge Base with full-text search."""
import json
import aiosqlite
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CVEEntry:
    id: str
    description: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] | None = None
    affected_products: list[str] | None = None
    references: list[str] | None = None
    exploit_available: bool = False
    published_at: str | None = None


class CVEKnowledgeBase:
    """Local CVE database with FTS5 full-text search."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self):
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._init_tables()

    async def close(self):
        if self._db:
            await self._db.close()

    async def _init_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cwe_ids TEXT,
                affected_products TEXT,
                references_list TEXT,
                exploit_available BOOLEAN DEFAULT FALSE,
                published_at DATETIME
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                id, description, content=cves, content_rowid=rowid
            );
            CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                INSERT INTO cves_fts(rowid, id, description)
                VALUES (new.rowid, new.id, new.description);
            END;
            CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, id, description)
                VALUES('delete', old.rowid, old.id, old.description);
            END;
        """)
        await self._db.commit()

    async def search(self, query: str, limit: int = 10) -> list[CVEEntry]:
        """Full-text search across CVEs."""
        cursor = await self._db.execute(
            """SELECT c.* FROM cves c
               JOIN cves_fts f ON c.rowid = f.rowid
               WHERE cves_fts MATCH ?
               ORDER BY rank
               LIMIT ?""",
            (query, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    async def search_by_cvss(self, min_score: float = 7.0, limit: int = 20) -> list[CVEEntry]:
        cursor = await self._db.execute(
            "SELECT * FROM cves WHERE cvss_score >= ? ORDER BY cvss_score DESC LIMIT ?",
            (min_score, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    async def get(self, cve_id: str) -> CVEEntry | None:
        cursor = await self._db.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
        row = await cursor.fetchone()
        return self._row_to_entry(row) if row else None

    async def add(self, entry: CVEEntry):
        await self._db.execute(
            """INSERT OR REPLACE INTO cves
               (id, description, cvss_score, cvss_vector, cwe_ids, affected_products,
                references_list, exploit_available, published_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.id, entry.description, entry.cvss_score, entry.cvss_vector,
                json.dumps(entry.cwe_ids or []),
                json.dumps(entry.affected_products or []),
                json.dumps(entry.references or []),
                entry.exploit_available, entry.published_at,
            ),
        )
        await self._db.commit()

    async def bulk_import(self, entries: list[CVEEntry]):
        data = [
            (e.id, e.description, e.cvss_score, e.cvss_vector,
             json.dumps(e.cwe_ids or []), json.dumps(e.affected_products or []),
             json.dumps(e.references or []), e.exploit_available, e.published_at)
            for e in entries
        ]
        await self._db.executemany(
            """INSERT OR REPLACE INTO cves
               (id, description, cvss_score, cvss_vector, cwe_ids, affected_products,
                references_list, exploit_available, published_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            data,
        )
        await self._db.commit()

    async def count(self) -> int:
        cursor = await self._db.execute("SELECT COUNT(*) FROM cves")
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def update_from_nvd(self, data_dir: Path):
        """Import CVEs from NVD JSON feeds."""
        import glob
        for json_file in sorted(data_dir.glob("nvdcve-*.json")):
            with open(json_file) as f:
                data = json.load(f)
            entries = []
            for item in data.get("CVE_Items", data.get("vulnerabilities", [])):
                cve_data = item.get("cve", item)
                cve_id = cve_data.get("id", cve_data.get("CVE_data_meta", {}).get("ID", ""))
                desc_data = cve_data.get("descriptions", cve_data.get("description", {}).get("description_data", []))
                description = ""
                for d in desc_data:
                    if isinstance(d, dict) and d.get("lang", d.get("lang")) == "en":
                        description = d.get("value", "")
                        break
                metrics = item.get("metrics", item.get("impact", {}))
                cvss_score = None
                cvss_vector = None
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                elif "baseMetricV3" in metrics:
                    cvss_data = metrics["baseMetricV3"]["cvssV3"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                entries.append(CVEEntry(
                    id=cve_id, description=description,
                    cvss_score=cvss_score, cvss_vector=cvss_vector,
                    exploit_available=False, published_at=None,
                ))
            if entries:
                await self.bulk_import(entries)

    def _row_to_entry(self, row) -> CVEEntry:
        return CVEEntry(
            id=row["id"],
            description=row["description"],
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            cwe_ids=json.loads(row["cwe_ids"]) if row["cwe_ids"] else None,
            affected_products=json.loads(row["affected_products"]) if row["affected_products"] else None,
            references=json.loads(row["references_list"]) if row["references_list"] else None,
            exploit_available=bool(row["exploit_available"]),
            published_at=row["published_at"],
        )
