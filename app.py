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
- First boot: python app.py init, then python app.py setpass, then start the service.
- Schedule python app.py purge (hourly is recommended, see
  deploy/onionsite-purge.timer). It removes old threads AND expired downloads.
- Expired downloads stop being served the moment they expire. The purge task then
  scrubs its metadata (name, description, size, hash), then securely shreds the stored file,
  leaving only a tiny tombstone (id + expiry time) so visitors with an old link see
  a clear "expired" page. Tombstones are removed after TOMBSTONE_SECONDS.
- Schedule python app.py check to verify stored file hashes.
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
logging.getLogger("werkzeug").setLevel(logging.WARNING)
PH = PasswordHasher()

MB = 1024 * 1024
PUBLIC_BODY_LIMIT = 32 * 1024
ADMIN_BODY_LIMIT = 128 * 1024
MAX_PASSWORD_LEN = 256
CONV_TTL = 4 * 3600
REVEAL_TTL = 600
FEED_SECONDS = 5
MAX_ATTACHMENTS = 10
MAX_ATTACHMENTS_PER_NOTICE = 50
THREAD_LIMIT = 500
MAX_PUBLIC_NOTICES = 100
PAGE_SIZE = 50
BLOB_OVERHEAD = 28
THREAD_OVERHEAD = 1024
MAX_TIMER = 253402300799
TIMER_RE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}')
STALE_SECONDS = 3600
TOMBSTONE_SECONDS = 30 * 86400
SHRED_CHUNK = 1024 * 1024
SQLITE_MAX_INT = 2 ** 63 - 1
PART_RE = re.compile(r'\.[0-9a-f]{32}\.part')
LOGIN_CONCURRENCY = 2
LOGIN_FAIL = (50, 300)
RESERVED_PATHS = ('assets', 'downloads', 'att', 'contact', 'resume', 'thread', 'burn', 'burned')

GLOBAL_NEW = (600, 3600)
GLOBAL_READ_FAIL = (5000, 3600)
GLOBAL_SEND = (300, 60)
GLOBAL_INBOUND = (8 * MB, 3600)

THREAD_RATE = (10, 60)
THREAD_HOURLY = 100
THREAD_MAX_MSGS = 300
THREAD_MAX_BYTES = 512 * 1024

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
        self.admin_raw = os.getenv("ADMIN_PREFIX", "").strip("/")
        self.admin = "/" + self.admin_raw if self.admin_raw else "/admin-prefix-not-set"
        self.max_file = self.mb("MAX_FILE_MB", 25)
        self.attach_max = min(self.max_file, self.mb("ATTACH_MB", 8))
        self.quota = self.mb("QUOTA_MB", 500)
        self.conv_quota = self.mb("CONV_QUOTA_MB", 200)
        self.retention = int(os.getenv("RETENTION_DAYS", "30")) * 86400
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
            or self.admin_raw.split('/')[0] in RESERVED_PATHS
            or self.max_file > self.quota
            or self.retention < 0
        ):
            raise RuntimeError(
                "invalid configuration: ADMIN_PREFIX must be 10+ URL-safe characters "
                "and must not start with a public path name"
            )

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


def clear_limit(name):
    with RL_LOCK:
        RL.pop(name, None)


def limited_weight(name, weight, budget, window, hit=True):
    now = time.monotonic()
    with RL_LOCK:
        q = RL.setdefault(name, [])
        q[:] = [(t, w) for t, w in q if t > now - window]
        if sum(w for _, w in q) + weight > budget:
            return True
        if hit:
            q.append((now, weight))
        return False


def session_limited(name, count, window, hit=True):
    t = NOW()
    hits = [x for x in session.get(name, []) if x > t - window]
    if len(hits) >= count:
        return True
    if hit:
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


def scrub_wal(db):
    try:
        db.commit()
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    except sqlite3.Error:
        log.warning('wal_checkpoint_failed')


def get_setting(db, key, default=''):
    row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default


def set_setting(db, key, value):
    db.execute(
        'INSERT INTO settings(key,value) VALUES(?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, value),
    )


def contact_paused(db):
    return get_setting(db, 'contact_paused', '0') == '1'


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
    seen_id INTEGER NOT NULL DEFAULT 0,
    sgen INTEGER NOT NULL DEFAULT 0
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
    created INTEGER NOT NULL,
    expires INTEGER,
    purged INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

MIGRATIONS = (
    ("notices", "timer_until", "INTEGER"),
    ("notices", "censored", "INTEGER NOT NULL DEFAULT 0"),
    ("convs", "seen_id", "INTEGER NOT NULL DEFAULT 0"),
    ("convs", "sgen", "INTEGER NOT NULL DEFAULT 0"),
    ("files", "sha256", "TEXT"),
    ("files", "expires", "INTEGER"),
    ("files", "purged", "INTEGER NOT NULL DEFAULT 0"),
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


def open_conv(conv_id, idhash, gen):
    session['conv'] = conv_id
    session['conv_h'] = idhash[:16]
    session['conv_t'] = NOW()
    session['conv_g'] = gen


def close_conv():
    session.pop('conv', None)
    session.pop('conv_h', None)
    session.pop('conv_t', None)
    session.pop('conv_g', None)


def current_conv(touch=True):
    conv_id = session.get('conv')
    conv_h = session.get('conv_h')
    conv_t = session.get('conv_t', 0)
    conv_g = session.get('conv_g')

    if (
        not isinstance(conv_id, int)
        or isinstance(conv_id, bool)
        or not isinstance(conv_h, str)
        or not isinstance(conv_t, int)
        or not isinstance(conv_g, int)
        or isinstance(conv_g, bool)
        or NOW() - conv_t > CONV_TTL
    ):
        close_conv()
        return None

    row = database().execute('SELECT * FROM convs WHERE id=?', (conv_id,)).fetchone()
    if (
        not row
        or not hmac.compare_digest(conv_h.encode(), row['idhash'][:16].encode())
        or conv_g != row['sgen']
    ):
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
        log.warning('conv_quota_exceeded')
        abort(503)


def thread_send_block(db, cid, incoming):
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


def file_gone(f):
    """True when a download must no longer be served (expired or already purged)."""
    return bool(f['purged']) or is_expired(f['expires'])


def fmt_size(n):
    return f"{n/MB:.1f} MB" if n >= MB else f"{n/1024:.1f} KB"


def fmt_date(n):
    return time.strftime("%Y-%m-%d", time.gmtime(n))


def fmt_dt(n):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(n))


def fmt_remaining(secs):
    d, r = divmod(max(int(secs), 0), 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if not (d or h or m):
        return "less than 1 minute"
    parts = [f"{d}d"] if d else []
    if d or h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


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
<a href="/contact" class="{{'on' if request.path.startswith(('/contact','/resume','/thread','/burn')) else ''}}">Contact</a>
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
    "<h1>Downloads</h1><p class=mute>Files shared by the operator. "
    "Some files are temporary and disappear when they expire.</p>"
    "{% for f in rows %}"
    "<a class=card href='/downloads/{{f.id}}'>"
    "<span class=fi>{{ext(f.name)}}</span>"
    "<span class=fm><b>{{f.name}}</b><small>{{f.descr}}</small>"
    "{% if f.expires is not none %}<small>Expires {{dtm(f.expires)}}</small>{% endif %}</span>"
    "<span class=fs>{{sz(f.size)}}<br>{{dt(f.created)}}</span></a>"
    "{% else %}<p class=none>No files yet.</p>{% endfor %}"
)

FILE_BODY = (
    "<p><a class=back href='/downloads'>← All downloads</a></p>"
    "<div class=card><span class=fi>{{ext(f.name)}}</span>"
    "<h1>{{f.name}}</h1><p class=mute>{{sz(f.size)}} · added {{dt(f.created)}}</p>"
    "{% if f.descr %}<p>{{f.descr}}</p>{% endif %}"
    "{% if f.expires is not none %}<p><span class='pill ok'>Available until {{dtm(f.expires)}} · {{left}} left</span></p>{% endif %}"
    "<a class='btn pri' href='/downloads/{{f.id}}/download'>Download file</a></div>"
)

EXPIRED_BODY = (
    "<div class=narrow><div class=bigcode>410</div><h1>This file has expired</h1>"
    "<p>The operator set this download to expire"
    "{% if when %} on <b>{{when}}</b>{% endif %}. "
    "It is no longer available and its contents have been or will shortly be deleted from the server.</p>"
    "<p class=mute>If you still need it, <a href='/contact'>message the operator</a> and ask them to share it again.</p>"
    "<p><a class='btn pri' href='/downloads'>All downloads</a></p></div>"
)

TALK_BODY = (
    "<h1>Message the operator</h1>"
    "<p class=mute>Anonymous and simple. No account, e-mail or name.</p>"
    "{% if paused %}<div class=card><b>New messages are paused for now.</b> "
    "The operator is not accepting new threads at the moment. Please check back later. "
    "If you already have a thread, you can still resume it.</div>{% endif %}"
    "<div class=actions>{% if not paused %}<a class='btn pri' href='/contact/start'>Write a new message</a>{% endif %}"
    "<a class=btn href='/resume'>Resume a thread</a></div>"
    "<p>Writing a message gives you a Ticket and a Key. Save both. They are the only way back in.</p>"
    "<details class=card><summary>Things to know</summary><ul>"
    "<li>The Ticket and Key cannot be recovered or reset.</li>"
    "<li>Anyone holding both can read and write in your thread, so keep them private.</li>"
    "<li>Messages are encrypted at rest, but the operator can read them. This is not end-to-end encryption.</li>"
    "<li>Replies are not instant. The operator answers when available.</li>"
    "<li>You can permanently delete your thread at any time with your Ticket and Key: "
    "<a href='/burn'>delete a thread</a>.</li>"
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

PAUSED_BODY = (
    "<h1>New messages are paused</h1>"
    "<div class=card><p>The operator has temporarily stopped accepting new threads. "
    "Nothing is wrong on your side, and no message was sent.</p>"
    "<p class=mute>Please try again later. If you already have a thread, "
    "you can still <a href='/resume'>resume it</a>.</p></div>"
    "<p><a class='btn pri' href='/contact'>Back to contact</a></p>"
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

BURN_BODY = (
    "<div class=narrow><h1>Delete a thread</h1>"
    "{% if err %}<div class=alert>{{err}}</div>{% endif %}"
    "<p class=mute>This permanently deletes the thread and every message in it from the server, "
    "for you and for the operator. It cannot be undone.</p>"
    "<form method=post class=card>" + CS +
    "<label>Ticket<input name=cid required autocomplete=off></label>"
    "<label>Key<input name=sec type=password required autocomplete=off></label>"
    "<label class=chk><input type=checkbox name=sure value=1 required> I understand this is permanent</label>"
    "<button class='btn pri'>Delete thread permanently</button></form>"
    "<p class=mute>The operator may already have read or copied your messages, and deleting cannot undo that. "
    "Your Ticket and Key are required even if this browser is already signed in.</p></div>"
)

BURNED_BODY = (
    "<div class=narrow><h1>Thread deleted</h1>"
    "<p>The thread and all its messages were removed from the server. "
    "The Ticket and Key no longer work.</p>"
    "<p class=mute>If you want to talk to the operator again, you can start a new thread.</p>"
    "<p><a class='btn pri' href='/contact'>Back to contact</a></p></div>"
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
    "<span class=mute>Signs you out of this thread everywhere and clears this browser's cookie. Your messages stay.</span></div></form>"
    "<p class=mute><a href='/burn'>Permanently delete this thread…</a></p>"
)

ADMIN_LOGIN_BODY = (
    "<div class=narrow><h1>Operator sign-in</h1>"
    "<form method=post class=card>" + CS +
    "<label>Password<input name=pw type=password required autocomplete=current-password></label>"
    "<button class='btn pri'>Sign in</button></form></div>"
)

DASHBOARD_BODY = (
    "<h1>Overview</h1>"
    "<div class=card><p>New threads: "
    "{% if paused %}<span class='pill bad'>Paused</span>{% else %}<span class='pill ok'>Open</span>{% endif %}</p>"
    "<p class=mute>While paused, visitors cannot start new threads and see a friendly notice. "
    "Existing threads keep working.</p>"
    "<form method=post action='{{a}}/pause'>" + CS +
    "<input type=hidden name=state value='{% if paused %}open{% else %}paused{% endif %}'>"
    "<button class='btn{% if not paused %} pri{% endif %}'>"
    "{% if paused %}Resume new threads{% else %}Pause new threads{% endif %}</button></form></div>"
    "<div class=card><p><b>{{n[0]}}</b> files · <b>{{n[1]}}</b> threads · "
    "<b>{{n[2]}}</b> awaiting reply</p>"
    "{% if n[3] %}<p class=mute><b>{{n[3]}}</b> expired file(s) waiting for the next purge run.</p>{% endif %}"
    "<progress value='{{used}}' max='{{qraw}}'></progress>"
    "<p class=mute>{{sz(used)}} of {{quota}} used by files</p>"
    "<progress value='{{cused}}' max='{{cqraw}}'></progress>"
    "<p class=mute>{{sz(cused)}} of {{cquota}} used by messages</p>"
    "{% if cused > cqraw * 0.8 %}<div class=alert>Message storage is above 80%. "
    "New threads and messages are refused at 100%. Delete old threads to free space.</div>{% endif %}"
    "</div>"
    "<h2>Manage</h2><ul>"
    "<li><a href='{{a}}/posts'>Posts</a>: notices, attachments and timers</li>"
    "<li><a href='{{a}}/downloads'>Files</a>: upload or remove downloads, set expiry</li>"
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
    "<label class=chk><input type=checkbox name=expire> Expire this download</label>"
    "<label>Expires (UTC, not your local time)<input type=datetime-local name=expires_at></label>"
    "<p class=mute>Expired files are hidden and blocked immediately. The scheduled purge task then "
    "deletes the stored file and its details from the server.</p>"
    "<button class='btn pri'>Upload</button></form>"
    "{% for f in rows %}"
    "<div class=card>"
    "<div class=fm><b>{{f.name or 'Purged file'}}</b>"
    "<small>{% if not f.purged %}{{sz(f.size)}} · {% endif %}"
    "<span class='pill{{f.pill}}'>{{f.label}}</span></small></div>"
    "{% if not f.purged %}"
    "<form method=post>" + CS +
    "<input type=hidden name=setexp value='{{f.id}}'>"
    "<label class=chk><input type=checkbox name=expire {% if f.expires is not none %}checked{% endif %}> Expires</label>"
    "<label>Expires (UTC, not your local time)<input type=datetime-local name=expires_at value='{{f.exp_val}}'></label>"
    "<button class='btn sm'>Save expiry</button></form>"
    "{% endif %}"
    "<form method=post>" + CS +
    "<input type=hidden name=del value='{{f.id}}'>"
    "<div class=actions><span></span><button class='btn sm'>Delete</button></div></form>"
    "</div>"
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

CONFIRM_BODY = (
    "<div class=narrow><h1>{{title}}</h1>"
    "<p class=mute>This cannot be undone.</p>"
    "<form method=post class=card>" + CS +
    "{% for k, v in fields %}<input type=hidden name='{{k}}' value='{{v}}'>{% endfor %}"
    "<input type=hidden name=confirm value=1>"
    "<div class=actions><a class=btn href='{{back}}'>Cancel</a>"
    "<button class='btn pri'>Yes, delete</button></div></form></div>"
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


def secure_unlink(path, missing_ok=False):
    """Best-effort secure delete: overwrite with random bytes, fsync, truncate, unlink.

    Never follows symlinks and never overwrites a file that has other hard links.
    If the overwrite fails the file is still unlinked. Note: on copy-on-write or
    wear-levelled storage (SSD, btrfs, ZFS) an in-place overwrite cannot be
    guaranteed; use full-disk encryption as the real protection.
    """
    path = Path(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    except OSError:
        fd = None

    if fd is not None:
        try:
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                left = st.st_size
                while left > 0:
                    view = memoryview(os.urandom(min(left, SHRED_CHUNK)))
                    while view:
                        n = os.write(fd, view)
                        view = view[n:]
                        left -= n
                os.fsync(fd)
                os.ftruncate(fd, 0)
                os.fsync(fd)
        except OSError:
            log.warning('shred_failed')
        finally:
            os.close(fd)

    try:
        os.unlink(path)
    except FileNotFoundError:
        if not missing_ok:
            raise

    try:
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


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
            secure_unlink(C.files / fid)
        except FileNotFoundError:
            pass
        except OSError:
            log.warning('unlink_failed')


def getfile(fid):
    if not valid_id(fid):
        abort(404)
    return database().execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone() or abort(404)


def expired_page(f):
    """Clear 410 page. Deliberately shows nothing but the expiry time (no name/description)."""
    when = ''
    if f['expires'] is not None:
        try:
            when = fmt_dt(f['expires'])
        except (OverflowError, ValueError, OSError):
            when = ''
    return page(EXPIRED_BODY, when=when), 410


@app.get('/downloads')
def files():
    rows = database().execute(
        'SELECT * FROM files WHERE purged=0 AND (expires IS NULL OR expires>?) ORDER BY created DESC',
        (NOW(),),
    ).fetchall()
    return page(
        FILES_BODY,
        rows=rows,
        sz=fmt_size, dt=fmt_date, dtm=fmt_dt, ext=type_label,
    )


@app.get('/downloads/<fid>')
def fileview(fid):
    f = getfile(fid)
    if file_gone(f):
        return expired_page(f)
    left = fmt_remaining(f['expires'] - NOW()) if f['expires'] is not None else ''
    return page(FILE_BODY, f=f, left=left, sz=fmt_size, dt=fmt_date, dtm=fmt_dt, ext=type_label)


@app.get('/downloads/<fid>/download')
def download(fid):
    f = getfile(fid)
    if file_gone(f):
        return expired_page(f)
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
    return page(talk_nav('how') + TALK_BODY, days=C.retention // 86400, paused=contact_paused(database()))


@app.route('/contact/start', methods=['GET', 'POST'])
def talk_new():
    db = database()
    if contact_paused(db):
        return page(talk_nav('new') + PAUSED_BODY), (503 if request.method == 'POST' else 200)

    if request.method == 'GET':
        return page(talk_nav('new') + NEW_BODY)

    m = request.form.get('m', '').strip()
    if not m or len(m) > 4000:
        abort(400)

    weight = len(m.encode()) + BLOB_OVERHEAD + THREAD_OVERHEAD
    if (
        session_limited('new', 3, 3600, hit=False)
        or limited('new', *GLOBAL_NEW, hit=False)
        or limited_weight('inbound', weight, *GLOBAL_INBOUND, hit=False)
    ):
        abort(429)
    session_limited('new', 3, 3600)
    limited('new', *GLOBAL_NEW)
    limited_weight('inbound', weight, *GLOBAL_INBOUND)

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

    token = stash_credentials(db, conv_id, cid, sec)
    db.commit()

    open_conv(conv_id, digest(cid), 0)
    session['reveal'] = token
    log.info('conversation_created')
    return redirect('/contact/created', 303)


@app.get('/contact/created')
def talk_created():
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

    open_conv(row['id'], row['idhash'], row['sgen'])
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
            weight = size + BLOB_OVERHEAD
            if (
                session_limited('send', 10, 60, hit=False)
                or limited('send', *GLOBAL_SEND, hit=False)
                or limited_weight('inbound', weight, *GLOBAL_INBOUND, hit=False)
            ):
                abort(429)
            session_limited('send', 10, 60)
            limited('send', *GLOBAL_SEND)
            limited_weight('inbound', weight, *GLOBAL_INBOUND)

            begin_conv_write(db, m)
            if not db.execute('SELECT 1 FROM convs WHERE id=?', (row['id'],)).fetchone():
                abort(404)

            blocked = thread_send_block(db, row['id'], size)
            if blocked == 'full':
                db.rollback()
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
    row = current_conv(touch=False)
    if row:
        # Server-side revocation: any copy of the old cookie stops working.
        db = database()
        db.execute('UPDATE convs SET sgen=sgen+1 WHERE id=?', (row['id'],))
        db.commit()
    session.clear()
    resp = redirect('/contact', 303)
    resp.delete_cookie(
        app.config['SESSION_COOKIE_NAME'], path='/',
        secure=C.cookie_secure, httponly=True, samesite='Strict',
    )
    return resp


@app.route('/burn', methods=['GET', 'POST'])
def burn():
    if request.method == 'GET':
        return page(talk_nav(None) + BURN_BODY, err='')

    if (
        limited('read_fail', *GLOBAL_READ_FAIL, hit=False)
        or session_limited('burn', 10, 600, hit=False)
    ):
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
        session_limited('burn', 10, 600)
        return page(
            talk_nav(None) + BURN_BODY,
            err='The Ticket or Key does not match. Check for typos or extra spaces.',
        ), 403

    if request.form.get('sure') != '1':
        return page(
            talk_nav(None) + BURN_BODY,
            err='Tick the box to confirm that you want to delete this thread permanently.',
        ), 400

    db = database()
    db.commit()
    db.execute('BEGIN IMMEDIATE')
    cur = db.execute(
        'DELETE FROM convs WHERE id=? AND idhash=? AND sechash=?',
        (row['id'], row['idhash'], row['sechash']),
    )
    db.commit()
    if cur.rowcount == 0:
        abort(404)

    if session.get('conv') == row['id']:
        close_conv()
    session.pop('reveal', None)

    scrub_wal(db)
    log.info('conversation_burned')
    return redirect('/burned', 303)


@app.get('/burned')
def burned():
    return page(talk_nav(None) + BURNED_BODY)


@app.route(C.admin + '/signin', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return page(ADMIN_LOGIN_BODY)

    pw = request.form.get('pw', '')
    ok = False

    if limited('login_fail', *LOGIN_FAIL, hit=False):
        abort(429)

    if 0 < len(pw) <= MAX_PASSWORD_LEN:
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
        limited('login_fail', *LOGIN_FAIL)
        log.warning('admin_login_failed')
        return page(
            "<div class=narrow><div class=alert>Invalid credentials.</div>"
            "<p><a class='btn' href='" + C.admin + "/signin'>Try again</a></p></div>"
        ), 401

    clear_limit('login_fail')
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
        'SELECT (SELECT count() FROM files WHERE purged=0),'
        '(SELECT count() FROM convs),'
        "(SELECT count(*) FROM convs WHERE status='open'),"
        '(SELECT count() FROM files WHERE purged=0 AND expires IS NOT NULL AND expires<=?)',
        (NOW(),),
    ).fetchone()
    return page(
        DASHBOARD_BODY,
        n=n, used=used_bytes(db), qraw=C.quota,
        cused=conv_bytes(db), cqraw=C.conv_quota, cquota=fmt_size(C.conv_quota),
        sz=fmt_size, quota=fmt_size(C.quota), a=C.admin, paused=contact_paused(db),
    )


@app.post(C.admin + '/pause')
def admin_pause():
    state = request.form.get('state', '')
    if state not in ('paused', 'open'):
        abort(400)
    db = database()
    set_setting(db, 'contact_paused', '1' if state == 'paused' else '0')
    db.commit()
    log.info('contact_paused' if state == 'paused' else 'contact_resumed')
    return redirect(C.admin, 303)


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


def parse_when(flag, field, future=False):
    """Parse an optional UTC datetime-local form field gated by a checkbox.

    Returns a unix timestamp, or None when the checkbox is off. With future=True
    the moment must still lie ahead (used for download expiry).
    """
    if not request.form.get(flag):
        return None

    raw = request.form.get(field, '').strip()
    if not TIMER_RE.fullmatch(raw):
        abort(400)

    try:
        dt = datetime.strptime(raw, '%Y-%m-%dT%H:%M')
    except ValueError:
        abort(400)

    ts = calendar.timegm(dt.timetuple())
    if not 0 <= ts <= MAX_TIMER:
        abort(400)
    if future and ts <= NOW():
        abort(400)
    return ts


def parse_timer():
    return parse_when('timer', 'timer_until')


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


def admin_file(r):
    d = dict(r)
    t = r['expires']
    d['exp_val'] = ''
    try:
        if t is not None:
            d['exp_val'] = time.strftime('%Y-%m-%dT%H:%M', time.gmtime(t))
        if r['purged']:
            d['label'], d['pill'] = f'Expired · contents purged ({fmt_dt(t)})', ' bad'
        elif t is None:
            d['label'], d['pill'] = 'No expiry', ''
        elif is_expired(t):
            d['label'], d['pill'] = f'Expired {fmt_dt(t)} · purge pending', ' bad'
        else:
            d['label'], d['pill'] = f'Expires {fmt_dt(t)} · {fmt_remaining(t - NOW())} left', ' ok'
    except (OverflowError, ValueError, OSError, TypeError):
        d['exp_val'] = ''
        d['label'], d['pill'] = 'Expiry: invalid value (re-save to fix)', ' bad'
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
        secure_unlink(tmp, missing_ok=True)
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

        if staged and used_bytes(db) + sum(s[2] for s in staged) > C.quota:
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
            secure_unlink(stored_path(fid), missing_ok=True)
        raise
    finally:
        for s in staged:
            secure_unlink(s[1], missing_ok=True)


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
        # Purged downloads keep a metadata tombstone but no file on disk.
        known = {r[0] for r in db.execute(
            'SELECT id FROM files WHERE purged=0 UNION SELECT id FROM attachments'
        )}

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
                secure_unlink(C.files / n, missing_ok=True)
            except OSError:
                log.warning('sweep_unlink_failed')

    return {
        'stale_parts': len(parts),
        'orphans': len(orphans),
        'missing': len(known - present) if db is not None else 0,
        'unexpected': odd,
    }


def purge_expired_files(db):
    """Scrub expired downloads' metadata, then securely delete their stored contents.

    Under the write lock (so an admin extending an expiry cannot race it) the rows are
    turned into tombstones (id + expiry time only) and committed. The files are shredded
    AFTER the commit so the lock is never held during slow disk I/O. If a shred fails the
    file is no longer referenced, so the orphan sweep that follows in `purge` retries it.
    Tombstones are deleted after TOMBSTONE_SECONDS.
    """
    t = NOW()

    db.commit()
    db.execute('BEGIN IMMEDIATE')

    ids = [
        r['id'] for r in db.execute(
            'SELECT id FROM files WHERE purged=0 AND expires IS NOT NULL AND expires<=?', (t,)
        )
    ]
    for fid in ids:
        db.execute(
            "UPDATE files SET name='', descr='', sha256=NULL, size=0, created=expires, purged=1 WHERE id=?",
            (fid,),
        )

    cur = db.execute(
        'DELETE FROM files WHERE purged=1 AND expires<?', (t - TOMBSTONE_SECONDS,)
    )
    tombstones = cur.rowcount
    db.commit()

    unlink_stored(ids)
    return len(ids), tombstones


def verify_hashes(db):
    out = {'checked': 0, 'mismatch': 0, 'missing': 0}
    rows = db.execute(
        'SELECT id, sha256 FROM files WHERE purged=0 AND sha256 IS NOT NULL '
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
            if not request.form.get('confirm'):
                return page(
                    CONFIRM_BODY,
                    title='Delete this notice and its attachments?',
                    fields=[('action', 'delete'), ('id', str(nid))],
                    back=C.admin + '/posts',
                )
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
            if not request.form.get('confirm'):
                return page(
                    CONFIRM_BODY,
                    title=f"Delete file {f['name'] or '(purged)'}?",
                    fields=[('del', f['id'])],
                    back=C.admin + '/downloads',
                )
            cur = db.execute('DELETE FROM files WHERE id=?', (f['id'],))
            if cur.rowcount == 0:
                abort(404)
            db.commit()
            unlink_stored([f['id']])
            log.info('file_deleted')

        elif request.form.get('setexp'):
            f = getfile(request.form.get('setexp', ''))
            if f['purged']:
                abort(404)
            expires = parse_when('expire', 'expires_at', future=True)
            cur = db.execute(
                'UPDATE files SET expires=? WHERE id=? AND purged=0', (expires, f['id'])
            )
            if cur.rowcount == 0:
                abort(404)
            db.commit()
            log.info('file_expiry_updated')

        else:
            up = request.files.get('f')
            if not up or not up.filename:
                abort(400)

            name = safe_name(up.filename)
            descr = request.form.get('d', '')[:300]
            expires = parse_when('expire', 'expires_at', future=True)

            def insert(fid, total, sha, meta):
                db.execute(
                    'INSERT INTO files(id,name,size,descr,sha256,created,expires) VALUES(?,?,?,?,?,?,?)',
                    (fid, meta['name'], total, descr, sha, NOW(), expires),
                )

            try:
                store(db, [(up, {'name': name})], C.max_file, lambda: None, insert)
            except ValueError:
                abort(413)
            log.info('file_added')

        return redirect(C.admin + '/downloads', 303)

    return page(
        ADMIN_FILES_BODY,
        rows=[admin_file(r) for r in db.execute('SELECT * FROM files ORDER BY created DESC')],
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
            if not request.form.get('confirm'):
                return page(
                    CONFIRM_BODY,
                    title=f'Delete thread #{cid}?',
                    fields=[('del', '1')],
                    back=C.admin + f'/threads/{cid}',
                )
            db.execute('DELETE FROM convs WHERE id=?', (cid,))
            scrub_wal(db)
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
            pending = db.execute(
                'SELECT count() FROM files WHERE purged=0 AND expires IS NOT NULL AND expires<=?',
                (NOW(),),
            ).fetchone()[0]
            print(
                f"store: orphans={r['orphans']} stale_parts={r['stale_parts']} "
                f"missing={r['missing']} unexpected={r['unexpected']}"
            )
            print(
                f"hashes: checked={h['checked']} mismatch={h['mismatch']} missing={h['missing']}"
            )
            print(f"expired files awaiting purge={pending}")
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
            expired, tombstones = purge_expired_files(db)
            scrub_wal(db)
            r = sweep_store(db, delete=True)
            print(
                f"purged; expired files removed={expired} tombstones removed={tombstones}; "
                f"removed orphans={r['orphans']} stale_parts={r['stale_parts']}; missing={r['missing']}"
            )


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
