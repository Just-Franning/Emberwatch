"""Cases of the people search: searches, hits with profile data, and the link graph.

Graph: nodes (kind, ref) are unique per case, so the same website, e-mail address, display name or country named by
two accounts becomes one node - that is how relationships show up. Edges:
- username   search subject -> account found under the name (confirmed: found, hint: unsure)
- states     account -> what its profile states (name, place, company, e-mail, website)
- links_to   account -> another account or website its profile links to (both directions: "mutual")
- verified   account -> account/website the platform itself confirmed (Keybase proofs, verified Mastodon fields)
- local_part e-mail -> user name taken from it (hint); registered: e-mail -> account found by the address (Gravatar)
- manual     drawn by hand, with the strength confirmed or hint
A shared user name alone does not prove the same person; that is why accounts hang off the search subject and only
links and proofs connect accounts directly.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from ..db import DB, utcnow
from ..i18n import AppError
from .check import USERNAME_RE
from .profiles import norm_url

def local_part(email: str) -> str | None:
    """The part before the @ if it can be a user name (it is searched as one)."""
    local = email.split("@", 1)[0] if "@" in email else ""
    return local if len(local) >= 3 and USERNAME_RE.match(local) else None


NODE_KINDS = ("username", "email", "account", "name", "location", "org", "url", "person", "phone", "domain", "note")
MANUAL_KINDS = ("person", "account", "email", "phone", "domain", "url", "org", "location", "name", "username", "note")
STRENGTHS = ("confirmed", "hint")
MAX_NODES = 2000


class Store:
    def __init__(self, db: DB, retention_days: int) -> None:
        self.db = db
        self.retention_days = retention_days
        # searches that were running when the server stopped cannot continue
        db.execute("UPDATE osint_searches SET status='failed', error='interrupted', finished_at=? WHERE status IN ('queued', 'running')",
                   (utcnow(),))

    # --- cases ---------------------------------------------------------------------------------------------------
    def cases(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT c.id, c.name, c.note, c.created_by, c.created_at, c.updated_at, "
                             "(SELECT COUNT(*) FROM osint_searches s WHERE s.case_id = c.id) AS searches, "
                             "(SELECT COUNT(*) FROM osint_hits h JOIN osint_searches s ON s.id = h.search_id "
                             " WHERE s.case_id = c.id AND h.status = 'found') AS found, "
                             "(SELECT COUNT(*) FROM osint_nodes n WHERE n.case_id = c.id) AS nodes "
                             "FROM osint_cases c ORDER BY c.updated_at DESC")
        for r in rows:
            r["expires"] = self._expires(r["updated_at"])
        return rows

    def _expires(self, updated: str) -> str:
        t = datetime.fromisoformat(updated.replace("Z", "+00:00")) + timedelta(days=self.retention_days)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def case_row(self, cid: int) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM osint_cases WHERE id=?", (cid,))
        if not rows:
            raise AppError("err.osint.case", 404)
        return rows[0]

    def create_case(self, name: str, note: str | None, by: str | None) -> dict[str, Any]:
        now = utcnow()
        cid = self.db.insert("INSERT INTO osint_cases(name, note, created_by, created_at, updated_at) VALUES(?,?,?,?,?)",
                             (name, note, by, now, now))
        return self.case_row(cid)

    def update_case(self, cid: int, name: str | None, note: str | None) -> dict[str, Any]:
        row = self.case_row(cid)
        self.db.execute("UPDATE osint_cases SET name=?, note=?, updated_at=? WHERE id=?",
                        (name if name is not None else row["name"], note if note is not None else row["note"], utcnow(), cid))
        return self.case_row(cid)

    def delete_case(self, cid: int) -> dict[str, Any]:
        row = self.case_row(cid)
        self.db.transaction([  # explicit order (foreign keys cascade as well)
            ("DELETE FROM osint_edges WHERE case_id=?", (cid,)),
            ("DELETE FROM osint_nodes WHERE case_id=?", (cid,)),
            ("DELETE FROM osint_hits WHERE search_id IN (SELECT id FROM osint_searches WHERE case_id=?)", (cid,)),
            ("DELETE FROM osint_searches WHERE case_id=?", (cid,)),
            ("DELETE FROM osint_cases WHERE id=?", (cid,)),
        ])
        return row

    def touch(self, cid: int) -> None:
        self.db.execute("UPDATE osint_cases SET updated_at=? WHERE id=?", (utcnow(), cid))

    def prune(self) -> list[dict[str, Any]]:
        """Deletes cases without changes for retention_days. Returns the deleted cases."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        old = self.db.query("SELECT id, name FROM osint_cases WHERE updated_at < ? AND id NOT IN "
                            "(SELECT case_id FROM osint_searches WHERE status IN ('queued', 'running'))", (cutoff,))
        for r in old:
            self.delete_case(r["id"])
        return old

    # --- searches and hits ---------------------------------------------------------------------------------------
    def add_search(self, cid: int, kind: str, query: str, by: str | None) -> int:
        self.case_row(cid)
        sid = self.db.insert("INSERT INTO osint_searches(case_id, kind, query, status, started_at, created_by) VALUES(?,?,?,?,?,?)",
                             (cid, kind, query, "queued", utcnow(), by))
        self.touch(cid)
        return sid

    def search(self, sid: int) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM osint_searches WHERE id=?", (sid,))
        if not rows:
            raise AppError("err.osint.search", 404)
        return rows[0]

    def searches(self, cid: int) -> list[dict[str, Any]]:
        return self.db.query("SELECT * FROM osint_searches WHERE case_id=? ORDER BY id DESC", (cid,))

    def set_search(self, sid: int, **fields: Any) -> None:
        cols = [k for k in fields if k in ("status", "finished_at", "sites", "checked", "found", "unsure", "errors", "error")]
        if cols:
            self.db.execute(f"UPDATE osint_searches SET {', '.join(f'{c}=?' for c in cols)} WHERE id=?",  # fixed column names
                            (*[fields[c] for c in cols], sid))

    def add_hit(self, sid: int, site: str, host: str, source: str, cat: str, status: str, url: str, http: int | None,
                operator: str | None, operator_src: str | None) -> int:
        return self.db.insert("INSERT OR IGNORE INTO osint_hits(search_id, site, host, source, cat, status, url, http_status, "
                              "operator_cc, operator_src, checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                              (sid, site, host, source, cat, status, url, http, operator, operator_src, utcnow()))

    def set_profile(self, hit_id: int, profile: dict[str, Any]) -> None:
        self.db.execute("UPDATE osint_hits SET profile=? WHERE id=?", (json.dumps(profile, ensure_ascii=False)[:20000], hit_id))

    def hits(self, *, cid: int | None = None, sid: int | None = None, after: int = 0) -> list[dict[str, Any]]:
        if sid is not None:
            rows = self.db.query("SELECT * FROM osint_hits WHERE search_id=? AND id > ? ORDER BY id", (sid, after))
        else:
            rows = self.db.query("SELECT h.* FROM osint_hits h JOIN osint_searches s ON s.id = h.search_id WHERE s.case_id=? "
                                 "ORDER BY h.id", (cid,))
        for r in rows:
            try:
                r["profile"] = json.loads(r["profile"]) if r["profile"] else None
            except ValueError:
                r["profile"] = None
        return rows

    def delete_search(self, sid: int) -> None:
        s = self.search(sid)
        self.db.transaction([("DELETE FROM osint_hits WHERE search_id=?", (sid,)), ("DELETE FROM osint_searches WHERE id=?", (sid,))])
        self.touch(s["case_id"])

    # --- graph ---------------------------------------------------------------------------------------------------
    def node(self, cid: int, kind: str, ref: str, label: str, data: dict[str, Any] | None = None, manual: bool = False) -> int:
        ref, label = ref[:300], label[:160]
        self.db.execute("INSERT OR IGNORE INTO osint_nodes(case_id, kind, label, ref, data, manual, created_at) VALUES(?,?,?,?,?,?,?)",
                        (cid, kind, label, ref, json.dumps(data or {}, ensure_ascii=False)[:4000], int(manual), utcnow()))
        row = self.db.query("SELECT id, data FROM osint_nodes WHERE case_id=? AND kind=? AND ref=?", (cid, kind, ref))[0]
        if data and not manual:  # automatic nodes: keep the newest details (e.g. the status of an account)
            try:
                merged = {**json.loads(row["data"] or "{}"), **data}
            except ValueError:
                merged = data
            self.db.execute("UPDATE osint_nodes SET data=? WHERE id=?", (json.dumps(merged, ensure_ascii=False)[:4000], row["id"]))
        return int(row["id"])

    def edge(self, cid: int, src: int, dst: int, kind: str, strength: str, label: str | None = None,
             evidence: str | None = None, manual: bool = False) -> int:
        if src == dst:
            return 0
        self.db.execute("INSERT OR IGNORE INTO osint_edges(case_id, src, dst, kind, strength, label, evidence, manual, created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)", (cid, src, dst, kind, strength, (label or "")[:80] or None,
                                                      (evidence or "")[:300] or None, int(manual), utcnow()))
        row = self.db.query("SELECT id, strength FROM osint_edges WHERE case_id=? AND src=? AND dst=? AND kind=?", (cid, src, dst, kind))[0]
        if not manual and row["strength"] == "hint" and strength == "confirmed":
            self.db.execute("UPDATE osint_edges SET strength='confirmed' WHERE id=?", (row["id"],))
        return int(row["id"])

    def graph(self, cid: int) -> dict[str, Any]:
        nodes = self.db.query("SELECT id, kind, label, ref, data, manual, x, y, created_at FROM osint_nodes WHERE case_id=? ORDER BY id",
                              (cid,))
        for n in nodes:
            try:
                n["data"] = json.loads(n["data"] or "{}")
            except ValueError:
                n["data"] = {}
            n["manual"] = bool(n["manual"])
        edges = self.db.query("SELECT id, src, dst, kind, strength, label, evidence, manual FROM osint_edges WHERE case_id=? ORDER BY id",
                              (cid,))
        links = {(e["src"], e["dst"]) for e in edges if e["kind"] in ("links_to", "verified")}
        for e in edges:
            e["manual"] = bool(e["manual"])
            e["mutual"] = e["kind"] in ("links_to", "verified") and (e["dst"], e["src"]) in links
        return {"nodes": nodes, "edges": edges}

    def build(self, sid: int) -> None:
        """Adds the hits and profiles of a search to the graph of its case."""
        s = self.search(sid)
        cid = s["case_id"]
        subj = self.node(cid, s["kind"], s["query"].lower(), s["query"])
        anchor = subj  # accounts found under a user name hang off that name
        if s["kind"] == "email" and local_part(s["query"]):
            local = local_part(s["query"]) or ""
            anchor = self.node(cid, "username", local.lower(), local)
            self.edge(cid, subj, anchor, "local_part", "hint")
        hits = self.hits(sid=sid)
        accounts = {norm_url(r["data"]["url"]): r["id"] for r in self._account_nodes(cid)}
        for h in hits:
            acc = self.node(cid, "account", norm_url(h["url"]), h["site"],
                            {"url": h["url"], "site": h["site"], "cat": h["cat"], "status": h["status"], "hit": h["id"],
                             "operator": h["operator_cc"], "operator_src": h["operator_src"], "country": (h["profile"] or {}).get("country")})
            accounts[norm_url(h["url"])] = acc
            if h["source"] == "gravatar":  # found by the address itself
                self.edge(cid, subj, acc, "registered", "confirmed")
            else:
                self.edge(cid, anchor, acc, "username", "confirmed" if h["status"] == "found" else "hint")
        for h in hits:
            p = h["profile"] or {}
            if not p:
                continue
            acc = accounts[norm_url(h["url"])]
            if p.get("name"):
                self.edge(cid, acc, self.node(cid, "name", p["name"].lower(), p["name"]), "states", "confirmed", "name")
            if p.get("country"):
                self.edge(cid, acc, self.node(cid, "location", p["country"], p["country"]), "states", "confirmed", "location")
            if p.get("company"):
                self.edge(cid, acc, self.node(cid, "org", p["company"].lower(), p["company"]), "states", "confirmed", "company")
            for mail in p.get("emails") or []:
                self.edge(cid, acc, self.node(cid, "email", mail.lower(), mail), "states", "confirmed", "email")
            for kind, urls in (("verified", p.get("verified") or []), ("links_to", p.get("links") or [])):
                for u in urls:
                    target = accounts.get(norm_url(u))
                    if target is None:
                        target = self.node(cid, "url", norm_url(u), norm_url(u)[:160], {"url": u})
                    self.edge(cid, acc, target, kind, "confirmed")
        self.touch(cid)

    def _account_nodes(self, cid: int) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT id, data FROM osint_nodes WHERE case_id=? AND kind='account'", (cid,))
        out = []
        for r in rows:
            try:
                d = json.loads(r["data"] or "{}")
            except ValueError:
                continue
            if isinstance(d.get("url"), str):
                out.append({"id": r["id"], "data": d})
        return out

    # --- manual changes ------------------------------------------------------------------------------------------
    def _node_row(self, nid: int) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM osint_nodes WHERE id=?", (nid,))
        if not rows:
            raise AppError("err.osint.node", 404)
        return rows[0]

    def add_node(self, cid: int, kind: str, label: str, note: str | None) -> int:
        self.case_row(cid)
        if kind not in MANUAL_KINDS:
            raise AppError("err.bad_request")
        if self.db.query("SELECT COUNT(*) AS n FROM osint_nodes WHERE case_id=?", (cid,))[0]["n"] >= MAX_NODES:
            raise AppError("err.osint.full", max=MAX_NODES)
        nid = self.node(cid, kind, f"m:{secrets.token_hex(6)}", label, {"note": note} if note else {}, manual=True)
        self.touch(cid)
        return nid

    def update_node(self, nid: int, label: str | None, note: str | None) -> None:
        row = self._node_row(nid)
        try:
            data = json.loads(row["data"] or "{}")
        except ValueError:
            data = {}
        if note is not None:
            data["note"] = note
        self.db.execute("UPDATE osint_nodes SET label=?, data=? WHERE id=?",
                        ((label if label is not None else row["label"])[:160], json.dumps(data, ensure_ascii=False)[:4000], nid))
        self.touch(row["case_id"])

    def delete_node(self, nid: int) -> int:
        row = self._node_row(nid)
        self.db.transaction([("DELETE FROM osint_edges WHERE src=? OR dst=?", (nid, nid)), ("DELETE FROM osint_nodes WHERE id=?", (nid,))])
        self.touch(row["case_id"])
        return int(row["case_id"])

    def add_edge(self, cid: int, src: int, dst: int, strength: str, label: str | None) -> int:
        if strength not in STRENGTHS:
            raise AppError("err.bad_request")
        a, b = self._node_row(src), self._node_row(dst)
        if a["case_id"] != cid or b["case_id"] != cid or src == dst:
            raise AppError("err.osint.edge")
        eid = self.edge(cid, src, dst, "manual", strength, label, manual=True)
        self.db.execute("UPDATE osint_edges SET strength=?, label=? WHERE id=?", (strength, (label or "")[:80] or None, eid))
        self.touch(cid)
        return eid

    def update_edge(self, eid: int, strength: str | None, label: str | None) -> None:
        rows = self.db.query("SELECT * FROM osint_edges WHERE id=?", (eid,))
        if not rows:
            raise AppError("err.osint.edge", 404)
        if strength is not None and strength not in STRENGTHS:
            raise AppError("err.bad_request")
        e = rows[0]
        self.db.execute("UPDATE osint_edges SET strength=?, label=? WHERE id=?",
                        (strength or e["strength"], (label if label is not None else e["label"] or "")[:80] or None, eid))
        self.touch(e["case_id"])

    def delete_edge(self, eid: int) -> int:
        rows = self.db.query("SELECT case_id FROM osint_edges WHERE id=?", (eid,))
        if not rows:
            raise AppError("err.osint.edge", 404)
        self.db.execute("DELETE FROM osint_edges WHERE id=?", (eid,))
        self.touch(rows[0]["case_id"])
        return int(rows[0]["case_id"])

    def save_layout(self, cid: int, positions: list[tuple[int, float, float]]) -> int:
        self.case_row(cid)
        rows = [(round(x, 1), round(y, 1), nid, cid) for nid, x, y in positions[:MAX_NODES]]
        self.db.execmany("UPDATE osint_nodes SET x=?, y=? WHERE id=? AND case_id=?", rows)
        return len(rows)

    def export(self, cid: int) -> dict[str, Any]:
        row = self.case_row(cid)
        return {"case": row, "searches": self.searches(cid), "hits": self.hits(cid=cid), "graph": self.graph(cid), "exported_at": utcnow()}
