"""Tiny Desk: notices, downloads and anonymous message threads.

Deployment notes
- Run exactly ONE gunicorn process (-w 1) with THREADS, so one slow or stalled
  client cannot block everyone, while the in-memory limits stay in one place:
      gunicorn -w 1 --worker-class gthread --threads 16 --timeout 60
               --graceful-timeout 15 --keep-alive 5 --limit-request-line 2048
               --limit-request-fields 50 -b 127.0.0.1:8000 app:app
  (one command line; do not add --access-logfile). Set ONION_WORKERS to the
  process count so the app can warn you if it is wrong.
- Tor-side DoS defenses, in the HiddenServiceDir block of torrc
  (PoW needs Tor 0.4.8+ built with it; tune the numbers):
      HiddenServicePoWDefensesEnabled 1
      HiddenServiceEnableIntroDoSDefense 1
      HiddenServiceEnableIntroDoSRatePerSec 25
      HiddenServiceEnableIntroDoSBurstPerSec 200
- First boot: `python app.py init`, then `python app.py setpass`, then start the service.
- Schedule `python app.py purge` daily (see deploy/onionsite-purge.timer).
- Schedule `python app.py check` to verify stored file hashes.
"""
from __future__ import annotations
import argparse, calendar, getpass, hashlib, hmac, logging, os, re, secrets, sqlite3, stat, sys, threading, time
from datetime import datetime
from pathlib import Path
from flask import Flask, Response, abort, g, redirect, render_template_string, request, send_file, session
from werkzeug.exceptions import HTTPException
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

os.umask(0o077)

NOW = lambda: int(time.time())
log = logging.getLogger("onionsite")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logging.getLogger("werkzeug").setLevel(logging.WARNING)  # request URLs are not logged
PH = PasswordHasher()

MB = 1024 * 1024
PUBLIC_BODY_LIMIT = 32 * 1024
ADMIN_BODY_LIMIT = 128 * 1024
MAX_PASSWORD_LEN = 256
CONV_TTL = 4 * 3600              # idle timeout for visitor threads
REVEAL_TTL = 600                 # seconds a freshly created Ticket and Key can be shown
FEED_SECONDS = 5
MAX_ATTACHMENTS = 10             # per upload request
MAX_ATTACHMENTS_PER_NOTICE = 50
THREAD_LIMIT = 500
MAX_PUBLIC_NOTICES = 100
PAGE_SIZE = 50
BLOB_OVERHEAD = 28
THREAD_OVERHEAD = 1024           # rough storage cost of a new thread beyond its first message
MAX_TIMER = 253402300799
TIMER_RE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}')
STALE_SECONDS = 3600
SQLITE_MAX_INT = 2 ** 63 - 1
PART_RE = re.compile(r'\.[0-9a-f]{32}\.part')
LOGIN_CONCURRENCY = 2            # simultaneous Argon2 verifications allowed

# Global ceilings (count, window in seconds). Per-visitor limits are session-based,
# because an onion site has no client IP, but a session lives in a cookie and can be
# discarded. The real protection against flooding is therefore (a) the weighted
# inbound byte budget below and (b) the per-thread limits stored in the database.
GLOBAL_NEW = (600, 3600)
GLOBAL_READ_FAIL = (5000, 3600)
GLOBAL_SEND = (300, 60)
# Total visitor message bytes accepted per window, across all visitors. Ordinary use
# is a tiny fraction of this. It bounds how fast anyone can fill CONV_QUOTA_MB.
GLOBAL_INBOUND = (8 * MB, 3600)

# Per-thread limits, enforced from the database so clearing cookies or resuming the
# thread in a new browser does not reset them. They apply to visitor messages only.
THREAD_RATE = (10, 60)           # messages per window
THREAD_HOURLY = 100
THREAD_MAX_MSGS = 300            # visitor messages per thread, in total
THREAD_MAX_BYTES = 512 * 1024    # stored (encrypted) visitor bytes per thread

ATT_TYPES = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'txt': 'text/plain',
}


def check_path(p, private, is_dir=False):
    try:
        st = p.lstat()
    except FileNotFoundError:
        raise RuntimeError(f"required path missing: {p.name}")
    kind = stat.S_ISDIR if is_dir else stat.S_ISREG
    if not kind(st.st_mode):
        raise RuntimeError(f"unexpected file type: {p.name}")
    if st.st_uid != os.geteuid():
        raise RuntimeError(f"wrong owner: {p.name}")
    if st.st_mode & (0o077 if private else 0o027):
        raise RuntimeError(f"permissions too broad: {p.name}")


def ensure_private_dir(p):
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = p.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"unexpected file type: {p.name}")
    if st.st_uid != os.geteuid():
        raise RuntimeError(f"wrong owner: {p.name}")
    if st.st_mode & 0o077:
        p.chmod(0o700)
    check_path(p, True, True)


class Config:
    def __init__(self):
        self.secret_dir = Path(os.getenv("ONION_SECRETS", "/etc/onionsite"))
        self.data_dir = Path(os.getenv("ONION_DATA", "/var/lib/onionsite"))
        # No default: a guessable admin path defeats the point of hiding it.
        self.admin_raw = os.getenv("ADMIN_PREFIX", "").strip("/")
        self.admin = "/" + self.admin_raw if self.admin_raw else ""
        self.max_file = self.mb("MAX_FILE_MB", 25)
        self.attach_max = min(self.max_file, self.mb("ATTACH_MB", 8))
        self.quota = self.mb("QUOTA_MB", 500)
        self.conv_quota = self.mb("CONV_QUOTA_MB", 200)
        self.retention = int(os.getenv("RETENTION_DAYS", "30")) * 86400
        # Secure by default. Set COOKIE_SECURE=0 only for local plain-HTTP development.
        self.cookie_secure = os.getenv("COOKIE_SECURE", "1") == "1"
        self.db = self.data_dir / "site.db"
        self.files = self.data_dir / "files"
        self.note = os.getenv("OWNER_NOTE", "Messages are encrypted at rest on the server. They are not end-to-end encrypted.")

    @staticmethod
    def mb(name, default):
        value = int(os.getenv(name, str(default)))
        if value <= 0:
            raise RuntimeError(f"invalid {name}")
        return value * MB

    def validate(self):
        if os.geteuid() == 0:
            raise RuntimeError("must not run as root")

        if (
            len(self.admin_raw) < 10
            or not re.fullmatch(r'[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*', self.admin_raw)
            or self.max_file > self.quota
            or self.retention < 0
        ):
            raise RuntimeError("invalid configuration: ADMIN_PREFIX must be 10+ URL-safe characters")

        check_path(self.secret_dir, True, True)

        for name, hexkey in (("session.key", False), ("msg.key", True)):
            p = self.secret_dir / name
            check_path(p, True)
            raw = bytes.fromhex(p.read_text().strip()) if hexkey else p.read_bytes()
            if len(raw) != 32:
                raise RuntimeError("invalid secret length")

        check_path(self.secret_dir / "admin.hash", True)

        ensure_private_dir(self.data_dir)
        ensure_private_dir(self.files)

        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.db) + suffix)
            if p.exists() or p.is_symlink():
                check_path(p, True)


C = Config()
UPLOAD_LIMIT = max(C.max_file, C.attach_max * MAX_ATTACHMENTS) + MB
UPLOAD_PATHS = (C.admin + "/downloads", C.admin + "/posts")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=C.cookie_secure,
    # __Host- requires Secure, Path=/ and no Domain. Flask sets the last two.
    SESSION_COOKIE_NAME="__Host-onionsite" if C.cookie_secure else "onionsite",
    MAX_CONTENT_LENGTH=UPLOAD_LIMIT,
    MAX_FORM_MEMORY_SIZE=ADMIN_BODY_LIMIT,
    MAX_FORM_PARTS=40,
)

RL = {}
RL_LOCK = threading.Lock()
LOGIN_SLOTS = threading.BoundedSemaphore(LOGIN_CONCURRENCY)
AEAD = None


def limited(name, count, window, hit=True):
    now = time.monotonic()
    with RL_LOCK:
        q = RL.setdefault(name, [])
        q[:] = [x for x in q if x > now - window]
        if len(q) >= count:
            return True
        if hit:
            q.append(now)
        return False


def limited_weight(name, weight, budget, window):
    """Sliding-window byte budget shared by every visitor. True means over budget.

    Entries are bounded because callers also pass the count-based `limited` check first.
    """
    now = time.monotonic()
    with RL_LOCK:
        q = RL.setdefault(name, [])
        q[:] = [(t, w) for t, w in q if t > now - window]
        if sum(w for _, w in q) + weight > budget:
            return True
        q.append((now, weight))
        return False


def session_limited(name, count, window):
    t = NOW()
    hits = [x for x in session.get(name, []) if x > t - window]
    if len(hits) >= count:
        return True
    hits.append(t)
    session[name] = hits
    return False


def database():
    if "db" not in g:
        g.db = sqlite3.connect(C.db, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=10000")
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA secure_delete=ON")
    return g.db


def discard_db_changes():
    db = g.get("db")
    if db is not None:
        db.rollback()


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        if error:
            db.rollback()
        else:
            db.commit()
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS convs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idhash TEXT UNIQUE NOT NULL,
    sechash TEXT NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    seen_id INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS msgs(
    id INTEGER PRIMARY KEY,
    conv INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    sender TEXT NOT NULL CHECK(sender IN ('v','o')),
    version INTEGER NOT NULL DEFAULT 1,
    blob BLOB NOT NULL,
    created INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS msgs_conv ON msgs(conv, id);

CREATE TABLE IF NOT EXISTS reveals(
    tokhash TEXT PRIMARY KEY,
    conv INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    blob BLOB NOT NULL,
    created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    descr TEXT NOT NULL,
    sha256 TEXT,
    created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notices(
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    published INTEGER NOT NULL DEFAULT 1,
    timer_until INTEGER,
    censored INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attachments(
    id TEXT PRIMARY KEY,
    notice INTEGER NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT,
    created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
    sidhash TEXT PRIMARY KEY,
    created INTEGER NOT NULL,
    last INTEGER NOT NULL,
    pwfp TEXT NOT NULL
);
"""

# (table, column, declaration). Columns added after the first release.
MIGRATIONS = (
    ("notices", "timer_until", "INTEGER"),
    ("notices", "censored", "INTEGER NOT NULL DEFAULT 0"),
    ("convs", "seen_id", "INTEGER NOT NULL DEFAULT 0"),
    ("files", "sha256", "TEXT"),
    ("attachments", "sha256", "TEXT"),
)


def migrate_db(db):
    for table, column, decl in MIGRATIONS:
        cols = {r['name'] for r in db.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    db.commit()


def init_db():
    db = database()
    db.executescript(SCHEMA)
    migrate_db(db)


def secret(name):
    p = C.secret_dir / name
    return p.read_bytes() if name == "session.key" else bytes.fromhex(p.read_text().strip())


def load_keys():
    """Read the message key once at startup instead of once per message."""
    global AEAD
    AEAD = AESGCM(secret("msg.key"))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def parse_id(value):
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdigit()
        or len(value) > 19
        or int(value) > SQLITE_MAX_INT
    ):
        abort(400)
    return int(value)


def page_number():
    try:
        return min(max(int(request.args.get('p', '1')), 1), 100000)
    except ValueError:
        return 1


def admin_hash():
    return (C.secret_dir / 'admin.hash').read_text().strip()


def pw_fingerprint():
    return digest(admin_hash())[:32]


def invalidate_admin_sessions():
    if not C.db.exists():
        return
    db = sqlite3.connect(C.db, timeout=10)
    try:
        db.execute("DELETE FROM sessions")
        db.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()


def admin_session_valid(touch=True):
    sid = session.get('sid')
    if not isinstance(sid, str) or not sid:
        return False

    t = NOW()
    db = database()
    sidhash = digest(sid)
    row = db.execute('SELECT * FROM sessions WHERE sidhash=?', (sidhash,)).fetchone()
    if not row:
        return False

    if (
        t - row['last'] > 900
        or t - row['created'] > 28800
        or not hmac.compare_digest(row['pwfp'], pw_fingerprint())
    ):
        db.execute('DELETE FROM sessions WHERE sidhash=?', (sidhash,))
        return False

    if touch:
        db.execute('UPDATE sessions SET last=? WHERE sidhash=?', (t, sidhash))
    return True


def open_conv(conv_id, idhash):
    """Sign this browser in to a thread.

    SQLite reuses the id of the newest row after it is deleted, so the numeric id
    alone is not a safe handle: a stale cookie could land on a different visitor's
    new thread. The session also carries part of the thread's secret hash, which
    is checked on every request in current_conv().
    """
    session['conv'] = conv_id
    session['conv_h'] = idhash[:16]
    session['conv_t'] = NOW()


def close_conv():
    session.pop('conv', None)
    session.pop('conv_h', None)
    session.pop('conv_t', None)


def current_conv(touch=True):
    """Return the visitor's open thread, or None.

    The idle timer restarts only when touch=True (page loads and sends), so a
    visitor who stops using the site for CONV_TTL is signed out. The feed polls
    with touch=False, so an open tab alone does not keep the session alive.
    """
    conv_id = session.get('conv')
    conv_h = session.get('conv_h')
    conv_t = session.get('conv_t', 0)

    if (
        not isinstance(conv_id, int)
        or isinstance(conv_id, bool)
        or not isinstance(conv_h, str)
        or not isinstance(conv_t, int)
        or NOW() - conv_t > CONV_TTL
    ):
        close_conv()
        return None

    row = database().execute('SELECT * FROM convs WHERE id=?', (conv_id,)).fetchone()
    if not row or not hmac.compare_digest(conv_h.encode(), row['idhash'][:16].encode()):
        close_conv()
        return None

    if touch:
        session['conv_t'] = NOW()
    return row


def has_unread(db, cid):
    return db.execute(
        "SELECT 1 FROM msgs WHERE conv=? AND sender='o' AND id>(SELECT seen_id FROM convs WHERE id=?) LIMIT 1",
        (cid, cid),
    ).fetchone() is not None


def mark_seen(db, row):
    """Record the newest message the visitor has seen. Writes only when something is new."""
    last = db.execute('SELECT coalesce(max(id),0) FROM msgs WHERE conv=?', (row['id'],)).fetchone()[0]
    if last > row['seen_id']:
        db.execute('UPDATE convs SET seen_id=? WHERE id=?', (last, row['id']))


def encrypt(cid, sender, text):
    nonce = secrets.token_bytes(12)
    return nonce + AEAD.encrypt(nonce, text.encode(), f"v1:{cid}:{sender}".encode())


def decrypt(cid, sender, blob):
    try:
        return AEAD.decrypt(blob[:12], blob[12:], f"v1:{cid}:{sender}".encode()).decode()
    except Exception:
        log.warning('message_decrypt_failed')
        return "[message unavailable]"


def stash_credentials(db, conv_id, cid, sec):
    """Store a new thread's Ticket and Key encrypted on the server. Return a one-time token.

    Only the token goes to the browser. The database keeps only its hash, and the
    credentials are encrypted with the message key, so a database dump does not
    expose them.
    """
    # Drop reveals that expired without being shown, so they don't linger until the daily purge.
    db.execute('DELETE FROM reveals WHERE created<?', (NOW() - REVEAL_TTL,))

    token = secrets.token_urlsafe(32)
    th = digest(token)
    nonce = secrets.token_bytes(12)
    blob = nonce + AEAD.encrypt(nonce, f"{cid}\n{sec}".encode(), f"reveal:v1:{th}".encode())
    db.execute(
        'INSERT INTO reveals(tokhash,conv,blob,created) VALUES(?,?,?,?)',
        (th, conv_id, blob, NOW()),
    )
    return token


def take_credentials(db):
    """Return (ticket, key) once, for the browser that created the thread. Otherwise None.

    The row is deleted on the first read, so a second load shows nothing.
    """
    token = session.pop('reveal', None)
    if not isinstance(token, str) or not token:
        return None

    th = digest(token)
    row = db.execute('SELECT * FROM reveals WHERE tokhash=?', (th,)).fetchone()
    if not row:
        return None

    db.execute('DELETE FROM reveals WHERE tokhash=?', (th,))
    db.commit()

    if (
        NOW() - row['created'] > REVEAL_TTL
        or session.get('conv') != row['conv']
    ):
        return None

    try:
        plain = AEAD.decrypt(
            row['blob'][:12], row['blob'][12:], f"reveal:v1:{th}".encode()
        ).decode()
    except Exception:
        log.warning('reveal_decrypt_failed')
        return None

    cid, sec = plain.split("\n", 1)
    return cid, sec


def thread(db, cid, me):
    out = []
    for x in db.execute('SELECT * FROM msgs WHERE conv=? ORDER BY id DESC LIMIT ?', (cid, THREAD_LIMIT)):
        w = x['sender']
        out.append({
            'who': 'You' if w == me else ('Operator' if w == 'o' else 'Guest'),
            'mine': w == me,
            'text': decrypt(cid, w, x['blob']),
            'when': fmt_dt(x['created']),
        })
    return out


def used_bytes(db):
    return db.execute(
        'SELECT (SELECT coalesce(sum(size),0) FROM files)'
        '+(SELECT coalesce(sum(size),0) FROM attachments)'
    ).fetchone()[0]


def conv_bytes(db):
    return db.execute('SELECT coalesce(sum(length(blob)),0) FROM msgs').fetchone()[0]


def begin_conv_write(db, m):
    db.commit()
    db.execute('BEGIN IMMEDIATE')
    if conv_bytes(db) + len(m.encode()) + BLOB_OVERHEAD > C.conv_quota:
        log.warning('conv_quota_exceeded')  # visible in the journal; also shown on the dashboard
        abort(503)


def thread_send_block(db, cid, incoming):
    """Per-thread limits for visitor messages, read from the database.

    Call inside the write transaction opened by begin_conv_write, so two concurrent
    requests cannot both slip under a limit. Returns None, 'rate' or 'full'.
    """
    t = NOW()
    minute, hour, total, size = db.execute(
        "SELECT coalesce(sum(created>?),0), coalesce(sum(created>?),0), count(*), "
        "coalesce(sum(length(blob)),0) FROM msgs WHERE conv=? AND sender='v'",
        (t - THREAD_RATE[1], t - 3600, cid),
    ).fetchone()
    if total >= THREAD_MAX_MSGS or size + incoming + BLOB_OVERHEAD > THREAD_MAX_BYTES:
        return 'full'
    if minute >= THREAD_RATE[0] or hour >= THREAD_HOURLY:
        return 'rate'
    return None


def is_expired(timer_until):
    return timer_until is not None and NOW() >= timer_until


def fmt_size(n):
    return f"{n/MB:.1f} MB" if n >= MB else f"{n/1024:.1f} KB"


def fmt_date(n):
    return time.strftime("%Y-%m-%d", time.gmtime(n))


def fmt_dt(n):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(n))


def fmt_remaining(secs):
    d, r = divmod(max(secs, 0), 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    parts = [f"{d}d"] if d else []
    if d or h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts) if (d or h or m) else "less than 1 minute"


def type_label(name):
    return (name.rsplit('.', 1)[-1] if '.' in name else 'file')[:4].upper()


CSS = """
:root{--bg:#fafafa;--card:#fff;--ink:#111;--mute:#666;--line:#e6e6e6;--acc:#4f46e5;--bad:#b91c1c;--ok:#15803d;--r:10px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,sans-serif}
a{color:var(--acc)}
h1{font-size:1.4rem;margin:.4rem 0 .6rem}
h2{font-size:1.1rem;margin:1.6rem 0 .6rem}
main{max-width:44rem;margin:0 auto;padding:1.4rem 1.1rem 3rem}
.top{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem 1.2rem;padding:.8rem 1.1rem;background:var(--card);border-bottom:1px solid var(--line)}
.top a{color:var(--mute);text-decoration:none}
.top a.on{color:var(--ink);font-weight:600}
.top .brand{color:var(--ink);font-weight:700;margin-right:auto}
.top nav{display:flex;flex-wrap:wrap;gap:1rem}
.top.sub{background:#f3f3f5;font-size:.9rem}
.inline{display:inline;margin:0}
.link{background:none;border:0;padding:0;color:var(--acc);font:inherit;cursor:pointer}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1rem 1.1rem;margin:.8rem 0}
a.card{display:flex;gap:1rem;align-items:center;color:var(--ink);text-decoration:none}
.composer{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:.8rem;margin:.8rem 0}
.post header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}
.post h2{margin:0;font-size:1.05rem;overflow-wrap:anywhere}
.post .body{white-space:pre-wrap;overflow-wrap:anywhere;margin:.5rem 0}
.post.late{border-left:4px solid var(--bad)}
.post.gone{opacity:.7}
.pill{font-size:.78rem;color:var(--mute);border:1px solid var(--line);border-radius:999px;padding:.05rem .6rem;white-space:nowrap}
.pill.ok{color:var(--ok);border-color:#bbf7d0;background:#f0fdf4}
.pill.bad{color:var(--bad);border-color:#fecaca;background:#fef2f2}
.mute,small{color:var(--mute)}
.none{color:var(--mute);text-align:center;border:1px dashed var(--line);border-radius:var(--r);padding:1rem}
.btn{display:inline-block;padding:.5rem 1rem;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit;cursor:pointer;text-decoration:none}
.btn.pri{background:var(--acc);border-color:var(--acc);color:#fff}
.btn.sm{padding:.3rem .7rem;font-size:.85rem}
.actions{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;justify-content:space-between;margin-top:.6rem}
label{display:block;font-weight:600;font-size:.9rem;margin:.7rem 0}
label.chk{font-weight:400;display:flex;align-items:center;gap:.4rem}
input,textarea{display:block;width:100%;font:inherit;font-weight:400;padding:.55rem .7rem;border:1px solid var(--line);border-radius:8px;margin-top:.3rem;background:#fff;color:var(--ink)}
input[type=checkbox]{display:inline;width:auto;margin:0}
details summary{cursor:pointer;font-weight:600}
details[open] summary{margin-bottom:.5rem}
details ul{padding-left:1.2rem;margin:.4rem 0}
.alert{color:var(--bad);background:#fef2f2;border:1px solid #fecaca;border-radius:var(--r);padding:.7rem 1rem;margin:.8rem 0}
.cred{font-family:ui-monospace,Menlo,Consolas,monospace;background:#111;color:#f5f5f5;padding:.6rem .8rem;border-radius:8px;margin:.5rem 0;overflow-wrap:anywhere;user-select:all}
.cred small{display:block;color:#aaa;font-family:system-ui,sans-serif;text-transform:uppercase;letter-spacing:.08em;font-size:.7rem}
.tabs{display:flex;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;border-bottom:1px solid var(--line);padding-bottom:.6rem}
.tabs a{color:var(--mute);text-decoration:none}
.tabs a.on{color:var(--ink);font-weight:600}
.feedbox{width:100%;height:50vh;min-height:16rem;border:1px solid var(--line);border-radius:var(--r);background:#fff;margin:.6rem 0}
.bub{max-width:82%;padding:.5rem .8rem;border-radius:12px;background:#f1f1f5;margin:.5rem 0}
.bub.me{margin-left:auto;background:var(--acc);color:#fff}
.bub .who{font-size:.75rem;opacity:.7}
.bub .txt{white-space:pre-wrap;overflow-wrap:anywhere}
body.feed{background:#fff;margin:0;padding:.6rem}
.gal{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.5rem}
img.att{max-width:100%;max-height:20rem;border-radius:8px;border:1px solid var(--line);display:block}
progress{width:100%}
.pager{display:flex;justify-content:space-between;margin:1rem 0}
.narrow{max-width:26rem}
.bigcode{font-size:3.5rem;font-weight:800;color:var(--acc);line-height:1}
.fi{flex:none;width:3rem;height:3rem;border-radius:10px;background:#eef0ff;color:var(--acc);display:grid;place-items:center;font-size:.75rem;font-weight:700}
.fm{flex:1;min-width:0;display:flex;flex-direction:column}
.fm b{overflow-wrap:anywhere}
.fs{font-size:.8rem;color:var(--mute);text-align:right;white-space:nowrap}
.back{display:inline-block;margin-bottom:.6rem}
@media (max-width:30rem){.fs{text-align:left}.bub{max-width:95%}}
"""

BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tiny Desk</title><link rel="stylesheet" href="/assets/style.css"></head><body>
<header class="top"><a class="brand" href="/">Tiny Desk</a>
<nav>
<a href="/" class="{{'on' if request.path=='/' else ''}}">Notices</a>
<a href="/downloads" class="{{'on' if request.path.startswith('/downloads') else ''}}">Downloads</a>
<a href="/contact" class="{{'on' if request.path.startswith(('/contact','/resume','/thread')) else ''}}">Contact</a>
</nav></header>
{% if is_admin %}
<nav class="top sub">
<a href="{{adm_root}}" class="{{'on' if request.path==adm_root else ''}}">Overview</a>
<a href="{{adm_root}}/posts" class="{{'on' if request.path.startswith(adm_root+'/posts') else ''}}">Posts</a>
<a href="{{adm_root}}/downloads" class="{{'on' if request.path.startswith(adm_root+'/downloads') else ''}}">Files</a>
<a href="{{adm_root}}/threads" class="{{'on' if request.path.startswith(adm_root+'/threads') else ''}}">Threads</a>
<form method="post" action="{{adm_root}}/signout" class="inline">
<input type="hidden" name="csrf" value="{{session.csrf}}"><button class="link">Sign out</button></form>
</nav>
{% endif %}
<main>"""
FOOT = "</main></body></html>"
FEED_HEAD = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             "<meta name='viewport' content='width=device-width,initial-scale=1'>")
FEED_MID = "<link rel='stylesheet' href='/assets/style.css'></head><body class=feed><main>"
CS = '<input type="hidden" name="csrf" value="{{session.csrf}}">'

FEED_BODY = (
    "{% for m in messages %}"
    "<div class='bub{{' me' if m.mine else ''}}'>"
    "<div class=who>{{m.who}} · {{m.when}}</div>"
    "<div class=txt>{{m.text}}</div></div>"
    "{% else %}<p class=none>No messages yet.</p>{% endfor %}"
)

ATT_HTML = (
    "{% if atts.get(n.nid) %}<div class=gal>"
    "{% for at in atts.get(n.nid,[]) %}"
    "{% if at.mime.startswith('image/') %}"
    "<a href='/att/{{at.id}}'><img class=att src='/att/{{at.id}}' alt='{{at.name}}' loading=lazy></a>"
    "{% else %}"
    "<a class='btn sm' href='/att/{{at.id}}'>{{at.name}} · {{sz(at.size)}}</a>"
    "{% endif %}{% endfor %}</div>{% endif %}"
)

HOME_BODY = (
    "<h1>Tiny Desk</h1>"
    "<p class=mute>{{note}}</p>"
    "<p><a class='btn pri' href='/contact'>Message the operator</a> "
    "<a class=btn href='/downloads'>Downloads</a></p>"
    "<h2>Notices</h2>"
    "{% for n in notices %}"
    "<article class='card post{% if n.expired %} late{% endif %}{% if n.censored %} gone{% endif %}'>"
    "<header><h2>{{n.title}}</h2><span class=pill>{{n.when}}</span></header>"
    "{% if n.censored %}<p class=mute>The operator removed this notice.</p>"
    "{% else %}<div class=body>{{n.content}}</div>" + ATT_HTML + "{% endif %}"
    "{% if n.timer_at %}<footer class=actions>"
    "{% if n.expired %}<span class='pill bad'>Timer ended {{n.timer_at}}</span>"
    "{% else %}<span class='pill ok'>Ends {{n.timer_at}} · {{n.timer_left}} left</span>{% endif %}"
    "</footer>{% endif %}"
    "</article>"
    "{% else %}<p class=none>Nothing posted yet.</p>{% endfor %}"
)

FILES_BODY = (
    "<h1>Downloads</h1><p class=mute>Files shared by the operator.</p>"
    "{% for f in rows %}"
    "<a class=card href='/downloads/{{f.id}}'>"
    "<span class=fi>{{ext(f.name)}}</span>"
    "<span class=fm><b>{{f.name}}</b><small>{{f.descr}}</small></span>"
    "<span class=fs>{{sz(f.size)}}<br>{{dt(f.created)}}</span></a>"
    "{% else %}<p class=none>No files yet.</p>{% endfor %}"
)

FILE_BODY = (
    "<p><a class=back href='/downloads'>← All downloads</a></p>"
    "<div class=card><span class=fi>{{ext(f.name)}}</span>"
    "<h1>{{f.name}}</h1><p class=mute>{{sz(f.size)}} · added {{dt(f.created)}}</p>"
    "{% if f.descr %}<p>{{f.descr}}</p>{% endif %}"
    "<a class='btn pri' href='/downloads/{{f.id}}/download'>Download file</a></div>"
)

TALK_BODY = (
    "<h1>Message the operator</h1>"
    "<p class=mute>Anonymous and simple. No account, e-mail or name.</p>"
    "<div class=actions><a class='btn pri' href='/contact/start'>Write a new message</a>"
    "<a class=btn href='/resume'>Resume a thread</a></div>"
    "<p>Writing a message gives you a Ticket and a Key. Save both. They are the only way back in.</p>"
    "<details class=card><summary>Things to know</summary><ul>"
    "<li>The Ticket and Key cannot be recovered or reset.</li>"
    "<li>Anyone holding both can read and write in your thread, so keep them private.</li>"
    "<li>Messages are encrypted at rest, but the operator can read them. This is not end-to-end encryption.</li>"
    "<li>Replies are not instant. The operator answers when available.</li>"
    "<li>Messages are limited to 4000 characters, threads have a message limit, and new threads per hour are limited.</li>"
    "{% if days %}<li>Threads with no activity for {{days}} days may be deleted.</li>{% endif %}"
    "</ul></details>"
)

NEW_BODY = (
    "<h1>Write a message</h1>"
    "<p class=mute>You will receive a Ticket and a Key right after sending.</p>"
    "<form method=post class=card>" + CS +
    "<label>Your message<textarea name=m maxlength=4000 rows=8 required></textarea></label>"
    "<button class='btn pri'>Send message</button></form>"
    "<p class=mute>Already have a thread? <a href='/resume'>Resume it</a>.</p>"
)

CREATED_BODY = (
    "<h1>Message sent</h1>"
    "<div class=alert>Copy these now. They are shown only once and cannot be recovered.</div>"
    "<div class=cred><small>Ticket</small><code>{{cid}}</code></div>"
    "<div class=cred><small>Key</small><code>{{sec}}</code></div>"
    "<p class=mute>This browser is signed in, so you can open your thread now. "
    "Use the Ticket and Key to return later or from another browser.</p>"
    "<p><a class='btn pri' href='/thread'>Open my thread</a></p>"
)

RESUME_FORM = (
    "<div class=narrow><h1>Resume a thread</h1>"
    "<p class=mute>Enter the Ticket and Key you saved after sending your first message.</p>"
)

THREAD_BODY = (
    "<h1>Your thread</h1>"
    "<form method=post class=composer>" + CS +
    "<textarea name=m maxlength=4000 rows=3 required placeholder='Write a reply…'></textarea>"
    "<div class=actions><span class=mute>Newest first · <a href='/thread'>refresh</a></span>"
    "<button class='btn pri'>Send</button></div></form>"
    "<iframe class=feedbox src='/thread/feed' title='Messages'></iframe>"
    "<form method=post action='/thread/leave'>" + CS +
    "<div class=actions><button class=btn>Close thread</button>"
    "<span class=mute>Only signs you out in this browser. Your messages stay.</span></div></form>"
)

ADMIN_LOGIN_BODY = (
    "<div class=narrow><h1>Operator sign-in</h1>"
    "<form method=post class=card>" + CS +
    "<label>Password<input name=pw type=password required autocomplete=current-password></label>"
    "<button class='btn pri'>Sign in</button></form></div>"
)

DASHBOARD_BODY = (
    "<h1>Overview</h1>"
    "<div class=card><p><b>{{n[0]}}</b> files · <b>{{n[1]}}</b> threads · "
    "<b>{{n[2]}}</b> awaiting reply</p>"
    "<progress value='{{used}}' max='{{qraw}}'></progress>"
    "<p class=mute>{{sz(used)}} of {{quota}} used by files</p>"
    "<progress value='{{cused}}' max='{{cqraw}}'></progress>"
    "<p class=mute>{{sz(cused)}} of {{cquota}} used by messages</p>"
    "{% if cused > cqraw * 0.8 %}<div class=alert>Message storage is above 80%. "
    "New threads and messages are refused at 100%. Delete old threads to free space.</div>{% endif %}"
    "</div>"
    "<h2>Manage</h2><ul>"
    "<li><a href='{{a}}/posts'>Posts</a>: notices, attachments and timers</li>"
    "<li><a href='{{a}}/downloads'>Files</a>: upload or remove downloads</li>"
    "<li><a href='{{a}}/threads'>Threads</a>: read and answer messages</li>"
    "</ul>"
)

ADMIN_POSTS_BODY = (
    "<h1>Posts</h1>"
    "<details class=card open><summary>New notice</summary>"
    "<form method=post enctype=multipart/form-data>" + CS +
    "<input type=hidden name=action value=create>"
    "<label>Title<input name=title maxlength=200 required></label>"
    "<label>Text<textarea name=content maxlength=10000 rows=8 required></textarea></label>"
    "<label>Attachments (png, jpg, gif, webp, txt)<input type=file name=att multiple accept='.png,.jpg,.jpeg,.gif,.webp,.txt'></label>"
    "<label class=chk><input type=checkbox name=published checked> Publish immediately</label>"
    "<label class=chk><input type=checkbox name=timer> Show a countdown timer</label>"
    "<label>Timer ends (UTC, not your local time)<input type=datetime-local name=timer_until></label>"
    "<button class='btn pri'>Create notice</button></form></details>"
    "<h2>All notices</h2>"
    "{% for n in rows %}"
    "<details class=card><summary><b>{{n.title}}</b> "
    "{% if not n.published %}<span class=pill>Draft</span>{% endif %}"
    "{% if n.censored %}<span class='pill bad'>Hidden</span>{% endif %}"
    "<span class='pill{% if n.expired %} bad{% endif %}'>{{n.timer_label}}</span></summary>"
    "<form method=post enctype=multipart/form-data>" + CS +
    "<input type=hidden name=action value=edit>"
    "<input type=hidden name=id value='{{n.id}}'>"
    "<label>Title<input name=title maxlength=200 value='{{n.title}}' required></label>"
    "<label>Text<textarea name=content maxlength=10000 rows=8 required>{{n.content}}</textarea></label>"
    "<label>Add attachments<input type=file name=att multiple accept='.png,.jpg,.jpeg,.gif,.webp,.txt'></label>"
    "<label class=chk><input type=checkbox name=published {% if n.published %}checked{% endif %}> Published</label>"
    "<label class=chk><input type=checkbox name=timer {% if n.timer_until is not none %}checked{% endif %}> Show a countdown timer</label>"
    "<label>Timer ends (UTC, not your local time)<input type=datetime-local name=timer_until value='{{n.timer_val}}'></label>"
    "<button class='btn pri'>Save changes</button></form>"
    "{% for at in atts.get(n.id,[]) %}"
    "<form method=post class=actions>" + CS +
    "<input type=hidden name=action value=rmatt><input type=hidden name=aid value='{{at.id}}'>"
    "<span>{% if at.mime.startswith('image/') %}<img class=att src='{{a}}/att/{{at.id}}' alt=''><br>{% endif %}"
    "<a href='{{a}}/att/{{at.id}}'>{{at.name}}</a> <small>{{sz(at.size)}}</small></span>"
    "<button class='btn sm'>Remove attachment</button></form>"
    "{% endfor %}"
    "<div class=actions>"
    "<form method=post>" + CS +
    "<input type=hidden name=action value='{% if n.censored %}uncensor{% else %}censor{% endif %}'>"
    "<input type=hidden name=id value='{{n.id}}'>"
    "<button class='btn sm'>{% if n.censored %}Restore{% else %}Hide content{% endif %}</button></form>"
    "<form method=post>" + CS +
    "<input type=hidden name=action value=delete><input type=hidden name=id value='{{n.id}}'>"
    "<button class='btn sm'>Delete notice</button></form>"
    "</div></details>"
    "{% else %}<p class=none>No notices yet.</p>{% endfor %}"
)

ADMIN_FILES_BODY = (
    "<h1>Files</h1>"
    "<p class=mute>Any file type is accepted. Never open uploads on a privileged machine.</p>"
    "<form method=post enctype=multipart/form-data class=card>" + CS +
    "<label>File<input type=file name=f required></label>"
    "<label>Description<input name=d maxlength=300></label>"
    "<button class='btn pri'>Upload</button></form>"
    "{% for f in rows %}"
    "<form method=post class=card>" + CS +
    "<input type=hidden name=del value='{{f.id}}'>"
    "<div class=actions><span class=fm><b>{{f.name}}</b><small>{{sz(f.size)}}</small></span>"
    "<button class='btn sm'>Delete</button></div></form>"
    "{% else %}<p class=none>No files yet.</p>{% endfor %}"
)

ADMIN_THREADS_BODY = (
    "<h1>Threads</h1>"
    "{% for c in rows %}"
    "<a class=card href='{{a}}/threads/{{c.id}}'>"
    "<span class=fi>#{{c.id}}</span>"
    "<span class=fm><b>Thread #{{c.id}}</b><small>Updated {{dt(c.updated)}}</small></span>"
    "<span class='pill{% if c.status==\"open\" %} ok{% endif %}'>{{c.status}}</span></a>"
    "{% else %}<p class=none>No threads yet.</p>{% endfor %}"
    "<div class=pager>"
    "{% if pno>1 %}<a href='{{a}}/threads?p={{pno-1}}'>← Newer</a>{% else %}<span></span>{% endif %}"
    "{% if has_more %}<a href='{{a}}/threads?p={{pno+1}}'>Older →</a>{% endif %}"
    "</div>"
)

ADMIN_CONV_BODY = (
    "<p><a href='{{a}}/threads'>← All threads</a></p>"
    "<h1>Thread #{{cid}}</h1>"
    "<form method=post class=composer>" + CS +
    "<textarea name=m maxlength=4000 rows=3 required placeholder='Write a reply…'></textarea>"
    "<div class=actions><span class=mute>Newest first</span><button class='btn pri'>Reply</button></div></form>"
    "<iframe class=feedbox src='{{a}}/threads/{{cid}}/feed' title='Messages'></iframe>"
    "<form method=post>" + CS +
    "<input type=hidden name=del value=1><button class=btn>Delete thread</button></form>"
)


def page(body, **ctx):
    return render_template_string(BASE + body + FOOT, adm_root=C.admin, is_admin=in_admin_area(), **ctx)


def feed_page(body, refresh=True, **ctx):
    meta = f"<meta http-equiv='refresh' content='{FEED_SECONDS}'>" if refresh else ""
    return render_template_string(FEED_HEAD + meta + FEED_MID + body + "</main></body></html>", **ctx)


def talk_nav(active):
    row = current_conv(touch=False)
    tabs = [
        ('how', '/contact', 'Overview'),
        ('new', '/contact/start', 'Write'),
        ('continue', '/resume', 'Resume'),
    ]
    if row:
        label = 'My thread'
        if has_unread(database(), row['id']):
            label += ' <span class="pill ok">New reply</span>'
        tabs.append(('chat', '/thread', label))

    return "<nav class=tabs>" + "".join(
        f"<a class='{'on' if k == active else ''}' href='{u}'>{t}</a>"
        for k, u, t in tabs
    ) + "</nav>"


def error_page(code, msg):
    return page(
        "<div class=narrow><div class=bigcode>{{c}}</div><h1>{{m}}</h1>"
        "<p class=mute>That request could not be completed.</p>"
        "<p><a class='btn pri' href='/'>Back to start</a></p></div>",
        c=code, m=msg,
    )


def in_admin_area():
    path = request.path
    if path == C.admin + "/signin" or request.endpoint == 'login':
        return False
    if path == C.admin or path.startswith(C.admin + "/"):
        return True
    rule = request.url_rule.rule if request.url_rule else ""
    return rule == C.admin or rule.startswith(C.admin + "/")


@app.before_request
def guard():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)

    admin_area = in_admin_area()

    if admin_area:
        feed = request.endpoint == 'admin_feed'
        if not admin_session_valid(touch=not feed):
            session.clear()
            if feed:
                return feed_page("<p class=none>Session expired. Reload the page.</p>", refresh=False), 401
            return redirect(C.admin + "/signin")
        # The session touch above is a write. Commit it now so the SQLite write lock is
        # not held while the request body (possibly a slow upload over Tor) is read below.
        # With several threads, holding it would stall every visitor's message.
        database().commit()

    if request.method == "POST":
        limit = PUBLIC_BODY_LIMIT
        if admin_area:
            limit = UPLOAD_LIMIT if request.path in UPLOAD_PATHS else ADMIN_BODY_LIMIT

        length = request.content_length
        if length is None or length > limit:
            abort(413)

        sent = request.form.get("csrf", "").encode()
        if not hmac.compare_digest(sent, session["csrf"].encode()):
            abort(403)


@app.after_request
def headers(response):
    framed = request.endpoint in ('chat_feed', 'admin_feed')
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; object-src 'none'; style-src 'self'; img-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors " + ("'self'" if framed else "'none'"),
        "X-Frame-Options": "SAMEORIGIN" if framed else "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(),geolocation=(),microphone=()",
        "Cache-Control": "no-store",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    })
    return response


ERRORS = {
    400: "Bad request",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    413: "Request too large",
    429: "Too many requests",
    500: "Internal error",
    503: "Service temporarily unavailable",
}


@app.errorhandler(HTTPException)
def http_error(e):
    code = e.code or 500
    if code < 400:
        return e
    discard_db_changes()
    return error_page(code, ERRORS.get(code, "Error")), code


@app.errorhandler(sqlite3.Error)
def db_error(e):
    discard_db_changes()
    log.error('database_error %s', type(e).__name__)
    code = 503 if isinstance(e, sqlite3.OperationalError) else 500
    return error_page(code, ERRORS[code]), code


@app.get('/assets/style.css')
def css():
    return Response(CSS, mimetype='text/css')


def public_notices(db):
    rows = db.execute(
        'SELECT * FROM notices WHERE published=1 ORDER BY created DESC, id DESC LIMIT ?',
        (MAX_PUBLIC_NOTICES,),
    ).fetchall()

    ids = [r['id'] for r in rows if not r['censored']]
    atts = {}
    if ids:
        marks = ','.join('?' * len(ids))
        for a in db.execute(f'SELECT * FROM attachments WHERE notice IN ({marks}) ORDER BY created', ids):
            atts.setdefault(a['notice'], []).append(a)

    views = []
    for r in rows:
        censored = bool(r['censored'])
        t = r['timer_until']
        timer_at = ''
        timer_left = ''
        if t is not None and not censored:
            try:
                timer_at = fmt_dt(t)
                timer_left = fmt_remaining(t - NOW())
            except (OverflowError, ValueError, OSError):
                timer_at = ''
        views.append({
            'nid': r['id'],
            'title': 'Removed' if censored else r['title'],
            'content': '' if censored else r['content'],
            'when': fmt_date(r['updated']),
            'expired': is_expired(t) and not censored,
            'censored': censored,
            'timer_at': timer_at,
            'timer_left': timer_left,
        })
    return views, atts


@app.get('/')
def home():
    notices, atts = public_notices(database())
    return page(HOME_BODY, note=C.note, notices=notices, atts=atts, sz=fmt_size)


def valid_id(value):
    return isinstance(value, str) and len(value) == 32 and all(c in '0123456789abcdef' for c in value)


def stored_path(fid):
    if not valid_id(fid):
        abort(404)
    return C.files / fid


def unlink_stored(ids):
    for fid in ids:
        if not valid_id(fid):
            log.warning('unlink_skipped_invalid_id')
            continue
        try:
            (C.files / fid).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            log.warning('unlink_failed')


def getfile(fid):
    if not valid_id(fid):
        abort(404)
    return database().execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone() or abort(404)


@app.get('/downloads')
def files():
    return page(
        FILES_BODY,
        rows=database().execute('SELECT * FROM files ORDER BY created DESC').fetchall(),
        sz=fmt_size, dt=fmt_date, ext=type_label,
    )


@app.get('/downloads/<fid>')
def fileview(fid):
    f = getfile(fid)
    return page(FILE_BODY, f=f, sz=fmt_size, dt=fmt_date, ext=type_label)


@app.get('/downloads/<fid>/download')
def download(fid):
    f = getfile(fid)
    p = stored_path(f['id'])
    if not p.is_file() or p.is_symlink():
        abort(404)
    return send_file(p, mimetype='application/octet-stream', as_attachment=True,
                     download_name=f['name'], conditional=True)


def attachment_row(aid, published_only):
    if not valid_id(aid):
        abort(404)
    sql = 'SELECT a.* FROM attachments a JOIN notices n ON n.id=a.notice WHERE a.id=?'
    if published_only:
        sql += ' AND n.published=1 AND n.censored=0'
    return database().execute(sql, (aid,)).fetchone() or abort(404)


def send_attachment(row):
    p = stored_path(row['id'])
    if not p.is_file() or p.is_symlink():
        abort(404)
    return send_file(p, mimetype=row['mime'], conditional=True)


@app.get('/att/<aid>')
def attachment(aid):
    return send_attachment(attachment_row(aid, True))


@app.get('/contact')
def talk():
    return page(talk_nav('how') + TALK_BODY, days=C.retention // 86400)


@app.route('/contact/start', methods=['GET', 'POST'])
def talk_new():
    if request.method == 'GET':
        return page(talk_nav('new') + NEW_BODY)

    if session_limited('new', 3, 3600) or limited('new', *GLOBAL_NEW):
        abort(429)

    m = request.form.get('m', '').strip()
    if not m or len(m) > 4000:
        abort(400)

    # Shared byte budget across all visitors: bounds how fast the message store can fill,
    # even when each request arrives with a fresh cookie.
    if limited_weight('inbound', len(m.encode()) + BLOB_OVERHEAD + THREAD_OVERHEAD, *GLOBAL_INBOUND):
        abort(429)

    db = database()
    begin_conv_write(db, m)

    cid, sec = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
    t = NOW()

    cur = db.execute(
        'INSERT INTO convs(idhash,sechash,created,updated) VALUES(?,?,?,?)',
        (digest(cid), digest(sec), t, t),
    )
    conv_id = cur.lastrowid
    db.execute(
        'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
        (conv_id, 'v', encrypt(conv_id, 'v', m), t),
    )

    # The credentials go into the database, not the cookie. Only the opaque token is kept in the session.
    token = stash_credentials(db, conv_id, cid, sec)
    db.commit()

    open_conv(conv_id, digest(cid))
    session['reveal'] = token
    log.info('conversation_created')
    return redirect('/contact/created', 303)


@app.get('/contact/created')
def talk_created():
    session.pop('fresh', None)  # discard any cookie written by the previous version
    creds = take_credentials(database())
    if not creds:
        return redirect('/contact', 303)
    return page(talk_nav('new') + CREATED_BODY, cid=creds[0], sec=creds[1])


@app.route('/resume', methods=['GET', 'POST'])
def conversation():
    if request.method == 'GET':
        resume = (
            '<p><a href="/thread">A thread is already open in this browser. Return to it →</a></p>'
            if current_conv(touch=False) else ''
        )
        return page(talk_nav('continue') + RESUME_FORM + resume +
                    "<form method=post class=card>" + CS +
                    "<label>Ticket<input name=cid required autocomplete=off></label>"
                    "<label>Key<input name=sec type=password required autocomplete=off></label>"
                    "<button class='btn pri'>Open thread</button></form>"
                    "<p class=mute>Lost them? They cannot be recovered. "
                    "<a href='/contact/start'>Write a new message</a>.</p></div>")

    if limited('read_fail', *GLOBAL_READ_FAIL, hit=False):
        abort(429)

    cid = request.form.get('cid', '').strip()
    sec = request.form.get('sec', '').strip()

    row = None
    if len(cid) <= 128 and len(sec) <= 128:
        row = database().execute('SELECT * FROM convs WHERE idhash=?', (digest(cid),)).fetchone()

    stored = row['sechash'] if row else digest('-')
    ok = hmac.compare_digest(stored, digest(sec)) and row is not None

    if not ok:
        limited('read_fail', *GLOBAL_READ_FAIL)
        return page(
            talk_nav('continue') +
            '<div class=narrow><div class=alert>The Ticket or Key does not match. '
            'Check for typos or extra spaces.</div>'
            '<p><a class="btn pri" href="/resume">Try again</a></p></div>'
        ), 403

    open_conv(row['id'], row['idhash'])
    return redirect('/thread', 303)


@app.route('/thread', methods=['GET', 'POST'])
def chat():
    db = database()
    row = current_conv()
    if not row:
        return redirect('/resume')

    if request.method == 'POST':
        m = request.form.get('m', '').strip()
        if m:
            if len(m) > 4000:
                abort(400)
            size = len(m.encode())
            if (
                session_limited('send', 10, 60)
                or limited('send', *GLOBAL_SEND)
                or limited_weight('inbound', size + BLOB_OVERHEAD, *GLOBAL_INBOUND)
            ):
                abort(429)

            begin_conv_write(db, m)
            if not db.execute('SELECT 1 FROM convs WHERE id=?', (row['id'],)).fetchone():
                abort(404)

            # Limits that clearing cookies cannot reset: they are counted from the thread's own rows.
            blocked = thread_send_block(db, row['id'], size)
            if blocked == 'full':
                return page(
                    talk_nav('chat') +
                    "<div class=narrow><div class=alert>This thread has reached its message limit. "
                    "Please start a new message if you still need help.</div>"
                    "<p><a class='btn pri' href='/contact/start'>Write a new message</a></p></div>"
                ), 429
            if blocked:
                abort(429)

            db.execute(
                'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
                (row['id'], 'v', encrypt(row['id'], 'v', m), NOW()),
            )
            # A visitor reply makes the thread open again for the operator.
            db.execute("UPDATE convs SET updated=?, status='open' WHERE id=?", (NOW(), row['id']))
            db.commit()

        return redirect('/thread', 303)

    mark_seen(db, row)
    return page(talk_nav('chat') + THREAD_BODY)


@app.get('/thread/feed')
def chat_feed():
    db = database()
    row = current_conv(touch=False)
    if not row:
        return feed_page("<p class=none>Thread closed or not found.</p>", refresh=False), 403
    mark_seen(db, row)
    return feed_page(FEED_BODY, messages=thread(db, row['id'], 'v'))


@app.post('/thread/leave')
def chat_leave():
    close_conv()
    return redirect('/contact', 303)


@app.route(C.admin + '/signin', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return page(ADMIN_LOGIN_BODY)

    pw = request.form.get('pw', '')
    ok = False

    if 0 < len(pw) <= MAX_PASSWORD_LEN:
        # Bound concurrent Argon2 work. This refuses excess attempts without locking
        # the operator out for minutes the way a time-window lockout would.
        if not LOGIN_SLOTS.acquire(blocking=False):
            abort(429)
        try:
            PH.verify(admin_hash(), pw)
            ok = True
        except Exception:
            ok = False
        finally:
            LOGIN_SLOTS.release()

    if not ok:
        log.warning('admin_login_failed')
        return page(
            "<div class=narrow><div class=alert>Invalid credentials.</div>"
            "<p><a class='btn' href='" + C.admin + "/signin'>Try again</a></p></div>"
        ), 401

    db = database()
    t = NOW()
    db.execute('DELETE FROM sessions WHERE created<? OR last<?', (t - 28800, t - 900))

    sid = secrets.token_urlsafe(32)
    db.execute(
        'INSERT INTO sessions(sidhash,created,last,pwfp) VALUES(?,?,?,?)',
        (digest(sid), t, t, pw_fingerprint()),
    )

    session.clear()
    session.update(sid=sid, csrf=secrets.token_urlsafe(24))
    log.info('admin_login_success')
    return redirect(C.admin)


@app.post(C.admin + '/signout')
def logout():
    sid = session.get('sid')
    if isinstance(sid, str):
        database().execute('DELETE FROM sessions WHERE sidhash=?', (digest(sid),))
    session.clear()
    return redirect('/')


@app.get(C.admin)
def dashboard():
    db = database()
    n = db.execute(
        'SELECT (SELECT count(*) FROM files),'
        '(SELECT count(*) FROM convs),'
        "(SELECT count(*) FROM convs WHERE status='open')"
    ).fetchone()
    return page(
        DASHBOARD_BODY,
        n=n, used=used_bytes(db), qraw=C.quota,
        cused=conv_bytes(db), cqraw=C.conv_quota, cquota=fmt_size(C.conv_quota),
        sz=fmt_size, quota=fmt_size(C.quota), a=C.admin,
    )


def safe_name(name):
    name = Path(name.replace('\\', '/')).name
    name = ''.join(ch for ch in name if ch.isprintable())[-120:].strip()
    return 'file' if name in ('', '.', '..') else name


def file_ext(name):
    return name.rsplit('.', 1)[-1].lower() if '.' in name else ''


def attachment_ok(ext, head):
    if ext == 'png':
        return head.startswith(b'\x89PNG\r\n\x1a\n')
    if ext in ('jpg', 'jpeg'):
        return head.startswith(b'\xff\xd8\xff')
    if ext == 'gif':
        return head[:4] == b'GIF8'
    if ext == 'webp':
        return head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    if ext == 'txt':
        return b'\x00' not in head
    return False


def parse_timer():
    if not request.form.get('timer'):
        return None

    raw = request.form.get('timer_until', '').strip()
    if not TIMER_RE.fullmatch(raw):
        abort(400)

    try:
        dt = datetime.strptime(raw, '%Y-%m-%dT%H:%M')
    except ValueError:
        abort(400)

    ts = calendar.timegm(dt.timetuple())
    if not 0 <= ts <= MAX_TIMER:
        abort(400)
    return ts


def admin_notice(r):
    d = dict(r)
    t = r['timer_until']
    d['expired'] = is_expired(t)
    try:
        d['timer_val'] = '' if t is None else time.strftime('%Y-%m-%dT%H:%M', time.gmtime(t))
        d['timer_label'] = (
            'Timer: off' if t is None
            else f'Timer: expired ({fmt_dt(t)})' if d['expired']
            else f'Timer: {fmt_dt(t)}'
        )
    except (OverflowError, ValueError, OSError, TypeError):
        d['timer_val'] = ''
        d['timer_label'] = 'Timer: invalid value (re-save to fix)'
    return d


def read_attachments():
    items = []
    for up in request.files.getlist('att'):
        if not up or not up.filename:
            continue
        if len(items) >= MAX_ATTACHMENTS:
            abort(400)

        name = safe_name(up.filename)
        ext = file_ext(name)
        if ext not in ATT_TYPES:
            abort(400)

        head = up.stream.read(512)
        up.stream.seek(0)
        if not attachment_ok(ext, head):
            abort(400)

        items.append((up, {'name': name, 'mime': ATT_TYPES[ext]}))
    return items


def attachment_count(db, nid):
    return db.execute('SELECT count(*) FROM attachments WHERE notice=?', (nid,)).fetchone()[0]


def stage_upload(up, limit):
    """Stream an upload to a private temp file, hashing as it goes."""
    fid = secrets.token_hex(16)
    tmp = C.files / ('.' + fid + '.part')
    total = 0
    h = hashlib.sha256()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    try:
        with os.fdopen(fd, 'wb') as out:
            while chunk := up.stream.read(65536):
                total += len(chunk)
                if total > limit:
                    raise ValueError
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    return fid, tmp, total, h.hexdigest()


def store(db, items, limit, prepare, insert):
    staged = []
    placed = []

    try:
        for up, meta in items:
            staged.append(stage_upload(up, limit) + (meta,))

        db.commit()
        db.execute('BEGIN IMMEDIATE')

        if used_bytes(db) + sum(s[2] for s in staged) > C.quota:
            raise ValueError

        prepare()

        for fid, tmp, total, sha, meta in staged:
            insert(fid, total, sha, meta)
            os.replace(tmp, stored_path(fid))
            placed.append(fid)

        db.commit()
    except BaseException:
        db.rollback()
        for fid in placed:
            stored_path(fid).unlink(missing_ok=True)
        raise
    finally:
        for s in staged:
            s[1].unlink(missing_ok=True)


def attachment_inserter(db, holder):
    def insert(fid, total, sha, meta):
        db.execute(
            'INSERT INTO attachments(id,notice,name,mime,size,sha256,created) VALUES(?,?,?,?,?,?,?)',
            (fid, holder['nid'], meta['name'], meta['mime'], total, sha, NOW()),
        )
    return insert


def sweep_store(db=None, delete=False):
    cutoff = time.time() - STALE_SECONDS
    known = set()
    if db is not None:
        known = {r[0] for r in db.execute('SELECT id FROM files UNION SELECT id FROM attachments')}

    present = set()
    parts = []
    orphans = []
    odd = 0

    with os.scandir(C.files) as it:
        for e in it:
            n = e.name
            if e.is_symlink() or not e.is_file(follow_symlinks=False):
                odd += 1
                continue
            try:
                old = e.stat(follow_symlinks=False).st_mtime < cutoff
            except OSError:
                continue

            if PART_RE.fullmatch(n):
                if old:
                    parts.append(n)
            elif valid_id(n):
                present.add(n)
                if db is not None and n not in known and old:
                    orphans.append(n)
            else:
                odd += 1

    if delete:
        for n in parts + orphans:
            try:
                (C.files / n).unlink()
            except OSError:
                log.warning('sweep_unlink_failed')

    return {
        'stale_parts': len(parts),
        'orphans': len(orphans),
        'missing': len(known - present) if db is not None else 0,
        'unexpected': odd,
    }


def verify_hashes(db):
    """Recompute SHA-256 for every stored file that has a recorded hash."""
    out = {'checked': 0, 'mismatch': 0, 'missing': 0}
    rows = db.execute(
        'SELECT id, sha256 FROM files WHERE sha256 IS NOT NULL '
        'UNION ALL SELECT id, sha256 FROM attachments WHERE sha256 IS NOT NULL'
    ).fetchall()

    for r in rows:
        if not valid_id(r['id']):
            out['mismatch'] += 1
            continue
        p = C.files / r['id']
        if not p.is_file() or p.is_symlink():
            out['missing'] += 1
            continue

        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        out['checked'] += 1
        if not hmac.compare_digest(h.hexdigest(), r['sha256']):
            out['mismatch'] += 1
    return out


@app.get(C.admin + '/att/<aid>')
def admin_attachment(aid):
    return send_attachment(attachment_row(aid, False))


@app.route(C.admin + '/posts', methods=['GET', 'POST'])
def admin_notices():
    db = database()

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action in ('create', 'edit'):
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            published = 1 if request.form.get('published') else 0

            if not title or not content or len(title) > 200 or len(content) > 10000:
                abort(400)

            edit_id = parse_id(request.form.get('id', '')) if action == 'edit' else None
            timer = parse_timer()
            items = read_attachments()
            holder = {}

            if edit_id is not None and attachment_count(db, edit_id) + len(items) > MAX_ATTACHMENTS_PER_NOTICE:
                abort(400)

            def prepare():
                t = NOW()
                if action == 'create':
                    holder['nid'] = db.execute(
                        'INSERT INTO notices(title,content,created,updated,published,timer_until) VALUES(?,?,?,?,?,?)',
                        (title, content, t, t, published, timer),
                    ).lastrowid
                else:
                    if attachment_count(db, edit_id) + len(items) > MAX_ATTACHMENTS_PER_NOTICE:
                        abort(400)
                    cur = db.execute(
                        'UPDATE notices SET title=?,content=?,updated=?,published=?,timer_until=? WHERE id=?',
                        (title, content, t, published, timer, edit_id),
                    )
                    if cur.rowcount == 0:
                        abort(404)
                    holder['nid'] = edit_id

            try:
                store(db, items, C.attach_max, prepare, attachment_inserter(db, holder))
            except ValueError:
                abort(413)

            log.info('notice_created' if action == 'create' else 'notice_updated')

        elif action == 'delete':
            nid = parse_id(request.form.get('id', ''))
            ids = [r['id'] for r in db.execute('SELECT id FROM attachments WHERE notice=?', (nid,))]
            cur = db.execute('DELETE FROM notices WHERE id=?', (nid,))
            if cur.rowcount == 0:
                abort(404)
            db.commit()
            unlink_stored(ids)
            log.info('notice_deleted')

        elif action in ('censor', 'uncensor'):
            nid = parse_id(request.form.get('id', ''))
            cur = db.execute(
                'UPDATE notices SET censored=? WHERE id=?',
                (1 if action == 'censor' else 0, nid),
            )
            if cur.rowcount == 0:
                abort(404)
            log.info('notice_censored' if action == 'censor' else 'notice_uncensored')

        elif action == 'rmatt':
            aid = request.form.get('aid', '')
            if not valid_id(aid):
                abort(400)
            cur = db.execute('DELETE FROM attachments WHERE id=?', (aid,))
            if cur.rowcount == 0:
                abort(404)
            db.commit()
            unlink_stored([aid])
            log.info('attachment_deleted')

        else:
            abort(400)

        return redirect(C.admin + '/posts', 303)

    rows = [admin_notice(r) for r in db.execute('SELECT * FROM notices ORDER BY created DESC, id DESC')]
    atts = {}
    for at in db.execute('SELECT * FROM attachments ORDER BY created'):
        atts.setdefault(at['notice'], []).append(at)

    return page(ADMIN_POSTS_BODY, rows=rows, atts=atts, sz=fmt_size, a=C.admin)


@app.route(C.admin + '/downloads', methods=['GET', 'POST'])
def admin_files():
    db = database()

    if request.method == 'POST':
        if request.form.get('del'):
            f = getfile(request.form.get('del', ''))
            cur = db.execute('DELETE FROM files WHERE id=?', (f['id'],))
            if cur.rowcount == 0:
                abort(404)
            db.commit()
            unlink_stored([f['id']])
            log.info('file_deleted')

        else:
            up = request.files.get('f')
            if not up or not up.filename:
                abort(400)

            name = safe_name(up.filename)
            descr = request.form.get('d', '')[:300]

            def insert(fid, total, sha, meta):
                db.execute(
                    'INSERT INTO files(id,name,size,descr,sha256,created) VALUES(?,?,?,?,?,?)',
                    (fid, meta['name'], total, descr, sha, NOW()),
                )

            try:
                store(db, [(up, {'name': name})], C.max_file, lambda: None, insert)
            except ValueError:
                abort(413)
            log.info('file_added')

        return redirect(C.admin + '/downloads', 303)

    return page(
        ADMIN_FILES_BODY,
        rows=db.execute('SELECT * FROM files ORDER BY created DESC').fetchall(),
        sz=fmt_size,
    )


@app.get(C.admin + '/threads')
def admin_convs():
    db = database()
    pno = page_number()
    rows = db.execute(
        "SELECT * FROM convs ORDER BY (status='answered'), updated DESC LIMIT ? OFFSET ?",
        (PAGE_SIZE + 1, (pno - 1) * PAGE_SIZE),
    ).fetchall()
    return page(
        ADMIN_THREADS_BODY,
        rows=rows[:PAGE_SIZE], has_more=len(rows) > PAGE_SIZE,
        pno=pno, a=C.admin, dt=fmt_date,
    )


def conv_or_404(db, cid):
    if not db.execute('SELECT 1 FROM convs WHERE id=?', (cid,)).fetchone():
        abort(404)


@app.route(C.admin + f'/threads/<int(max={SQLITE_MAX_INT}):cid>', methods=['GET', 'POST'])
def admin_conv(cid):
    db = database()
    conv_or_404(db, cid)

    if request.method == 'POST':
        if request.form.get('del'):
            db.execute('DELETE FROM convs WHERE id=?', (cid,))
            log.info('conversation_deleted')
            return redirect(C.admin + '/threads', 303)

        m = request.form.get('m', '').strip()
        if not m or len(m) > 4000:
            abort(400)

        try:
            db.execute(
                'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
                (cid, 'o', encrypt(cid, 'o', m), NOW()),
            )
        except sqlite3.IntegrityError:
            # The thread was deleted between the existence check and the insert.
            abort(404)

        db.execute("UPDATE convs SET updated=?, status='answered' WHERE id=?", (NOW(), cid))
        return redirect(C.admin + f'/threads/{cid}', 303)

    return page(ADMIN_CONV_BODY, cid=cid, a=C.admin)


@app.get(C.admin + f'/threads/<int(max={SQLITE_MAX_INT}):cid>/feed')
def admin_feed(cid):
    db = database()
    conv_or_404(db, cid)
    return feed_page(FEED_BODY, messages=thread(db, cid, 'o'))


def initialize():
    ensure_private_dir(C.secret_dir)
    ensure_private_dir(C.data_dir)
    ensure_private_dir(C.files)

    for name, value in (
        ("session.key", secrets.token_bytes(32)),
        ("msg.key", secrets.token_hex(32)),
    ):
        p = C.secret_dir / name
        if not p.exists():
            p.write_bytes(value) if isinstance(value, bytes) else p.write_text(value)
            p.chmod(0o600)

    with app.app_context():
        init_db()

    if C.db.exists():
        C.db.chmod(0o600)


def write_admin_hash(hashed):
    p = C.secret_dir / 'admin.hash'
    tmp = C.secret_dir / '.admin.hash.tmp'
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(hashed)
    os.replace(tmp, p)


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'setpass', 'check', 'purge', 'status', 'setup-tor'])
    args = parser.parse_args()

    if args.command == 'init':
        initialize()
        print('initialized')
        return

    if args.command == 'setpass':
        ensure_private_dir(C.secret_dir)
        pw = getpass.getpass('Admin password (14+ chars): ')
        confirm = getpass.getpass('Repeat: ')
        if (
            pw != confirm
            or not 14 <= len(pw) <= MAX_PASSWORD_LEN
            or not any(x.isupper() for x in pw)
            or not any(x.islower() for x in pw)
            or not any(x.isdigit() for x in pw)
        ):
            raise SystemExit('weak password or mismatch')
        write_admin_hash(PH.hash(pw))
        invalidate_admin_sessions()
        print('password updated; all admin sessions revoked')
        return

    C.validate()

    if args.command == 'setup-tor':
        print('Install tor and run scripts/setup-tor.sh as root.')
        return

    with app.app_context():
        init_db()

        if args.command == 'check':
            db = database()
            r = sweep_store(db)
            h = verify_hashes(db)
            print(
                f"store: orphans={r['orphans']} stale_parts={r['stale_parts']} "
                f"missing={r['missing']} unexpected={r['unexpected']}"
            )
            print(
                f"hashes: checked={h['checked']} mismatch={h['mismatch']} missing={h['missing']}"
            )
            if r['missing'] or h['mismatch'] or h['missing']:
                print('checks FAILED')
                raise SystemExit(1)
            print('checks passed')

        elif args.command == 'status':
            print(f'database={C.db}\nfiles={C.files}\nquota={C.quota}')

        elif args.command == 'purge':
            db = database()
            if C.retention > 0:
                db.execute('DELETE FROM convs WHERE updated<?', (NOW() - C.retention,))
            db.execute('DELETE FROM reveals WHERE created<?', (NOW() - REVEAL_TTL,))
            db.execute('DELETE FROM sessions WHERE created<? OR last<?', (NOW() - 28800, NOW() - 900))
            db.commit()
            r = sweep_store(db, delete=True)
            print(f"purged; removed orphans={r['orphans']} stale_parts={r['stale_parts']}; missing={r['missing']}")


def boot():
    C.validate()
    workers = int(os.getenv("ONION_WORKERS", "1"))
    if workers > 1:
        log.warning('rate_limits_are_per_process: run one worker process (use threads) or accept per-worker limits')
    app.secret_key = secret('session.key')
    load_keys()
    with app.app_context():
        init_db()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli()
    else:
        boot()
        app.run('127.0.0.1', 8000)
else:
    boot()
