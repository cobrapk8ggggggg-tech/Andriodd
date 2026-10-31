"""Small on-worker state and bounded capture. Android payloads never enter iOS."""
import hashlib
import json
from pathlib import Path
import sqlite3
import os
import time


class State:
    def __init__(self, root, clock=time.time):
        self.root, self.clock = Path(root), clock
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / "state.sqlite3")
        os.chmod(self.root/'state.sqlite3',0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL; PRAGMA journal_size_limit=0;
        CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, bytes INTEGER NOT NULL, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS operations(scope TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(scope,id));
        CREATE TABLE IF NOT EXISTS timeline(id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT NOT NULL,bytes INTEGER NOT NULL,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS counters(scope TEXT NOT NULL,name TEXT NOT NULL,value INTEGER NOT NULL,PRIMARY KEY(scope,name));
        CREATE TABLE IF NOT EXISTS consents(scope TEXT NOT NULL,project TEXT NOT NULL,purpose TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(scope,project,purpose));
        """)
        self.db.commit()

    @staticmethod
    def scope(claims): return hashlib.sha256((claims["sub"] + ":" + claims["conversation"]).encode()).hexdigest()

    def load(self):
        row = self.db.execute("SELECT value FROM state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def save(self, value):
        self.db.execute("INSERT OR REPLACE INTO state VALUES(1,?)", (json.dumps(value),)); self.db.commit()

    def owned(self, claims, active=True):
        value = self.load()
        if not value or value["scope"] != self.scope(claims): raise KeyError("No laboratory session for this conversation")
        if active and value["status"] != "running": raise ValueError("Start the Android laboratory first")
        return value

    def capture(self, scope, event):
        raw = json.dumps(event, ensure_ascii=False)
        size = len(raw.encode())
        if size > 140000: raise ValueError("Network event too large")
        row = self.db.execute("INSERT INTO events(scope,bytes,value) VALUES(?,?,?)", (scope, size, raw))
        # Limits apply globally too; switching conversations cannot evade them.
        removed = self.db.execute("SELECT scope,COUNT(*) n FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000) GROUP BY scope").fetchall()
        for value in removed: self.count(value['scope'],'network_events_evicted',value['n'])
        self.db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")
        while self.db.execute("SELECT COALESCE(SUM(bytes),0) FROM events").fetchone()[0] > 8*1024*1024:
            dropped=self.db.execute('SELECT scope FROM events ORDER BY id LIMIT 1').fetchone()
            self.count(dropped['scope'],'network_events_evicted')
            self.db.execute("DELETE FROM events WHERE id=(SELECT MIN(id) FROM events)")
        self.db.commit()
        return row.lastrowid

    def events(self, scope, after=0, limit=50):
        rows = self.db.execute("SELECT id,value FROM events WHERE scope=? AND id>? ORDER BY id LIMIT ?", (scope, after, max(1, min(50, limit)))).fetchall()
        return [{"id": r[0], **json.loads(r[1])} for r in rows]

    def count(self, scope, name, amount=1):
        self.db.execute('INSERT INTO counters VALUES(?,?,?) ON CONFLICT(scope,name) DO UPDATE SET value=value+excluded.value',(scope,name,amount))

    def coverage(self, scope):
        return {r['name']:r['value'] for r in self.db.execute('SELECT name,value FROM counters WHERE scope=?',(scope,))}

    def record(self, scope, kind, details):
        event={**details,'timestamp':self.clock(),'kind':kind}
        raw=json.dumps(event,ensure_ascii=False)
        if len(raw.encode())>16000: raise ValueError('Timeline entry too large')
        row=self.db.execute('INSERT INTO timeline(scope,bytes,value) VALUES(?,?,?)',(scope,len(raw.encode()),raw))
        old=self.db.execute('SELECT scope,COUNT(*) n FROM timeline WHERE id NOT IN (SELECT id FROM timeline ORDER BY id DESC LIMIT 2000) GROUP BY scope').fetchall()
        for value in old:self.count(value['scope'],'timeline_events_evicted',value['n'])
        self.db.execute('DELETE FROM timeline WHERE id NOT IN (SELECT id FROM timeline ORDER BY id DESC LIMIT 2000)')
        while self.db.execute('SELECT COALESCE(SUM(bytes),0) FROM timeline').fetchone()[0]>4*1024*1024:
            value=self.db.execute('SELECT scope FROM timeline ORDER BY id LIMIT 1').fetchone();self.count(value['scope'],'timeline_events_evicted')
            self.db.execute('DELETE FROM timeline WHERE id=(SELECT MIN(id) FROM timeline)')
        self.db.commit();return row.lastrowid

    def history(self, scope, after=0, limit=100):
        return [{'id':r['id'],**json.loads(r['value'])} for r in self.db.execute('SELECT id,value FROM timeline WHERE scope=? AND id>? ORDER BY id LIMIT ?',(scope,max(0,after),min(200,max(1,limit))))]

    def consent(self,scope,project,purpose,details=None):
        if details is not None:
            value={**details,'expires':self.clock()+600}
            self.db.execute('INSERT OR REPLACE INTO consents VALUES(?,?,?,?)',(scope,project,purpose,json.dumps(value)));self.db.commit()
            return value
        row=self.db.execute('SELECT value FROM consents WHERE scope=? AND project=? AND purpose=?',(scope,project,purpose)).fetchone()
        if not row:return None
        value=json.loads(row['value']);return value if value['expires']>self.clock() else None

    def all_events(self, scope):
        return [{'id':r['id'],**json.loads(r['value'])} for r in self.db.execute('SELECT id,value FROM events WHERE scope=? ORDER BY id',(scope,))]

    def all_history(self,scope):
        return [{'id':r['id'],**json.loads(r['value'])} for r in self.db.execute('SELECT id,value FROM timeline WHERE scope=? ORDER BY id',(scope,))]

    def close(self): self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)"); self.db.close()
