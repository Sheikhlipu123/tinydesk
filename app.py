from __future__ import annotations
import argparse, calendar, getpass, hashlib, hmac, logging, os, re, secrets, sqlite3, stat, sys, threading, time
from datetime import datetime
from pathlib import Path
from flask import Flask, Response, abort, g, redirect, render_template_string, request, send_file, session
from werkzeug.exceptions import HTTPException
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

os.umask(0o077)

NOW=lambda: int(time.time())
log=logging.getLogger("onionsite")
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"), format="%(message)s")
PH=PasswordHasher()

PUBLIC_BODY_LIMIT=32*1024
ADMIN_BODY_LIMIT=128*1024
MAX_PASSWORD_LEN=256
CONV_TTL=4*3600
FEED_SECONDS=5
MAX_ATTACHMENTS=10
MAX_ATTACHMENTS_PER_NOTICE=50
THREAD_LIMIT=500
MAX_PUBLIC_NOTICES=100
BLOB_OVERHEAD=28
MAX_TIMER=253402300799
TIMER_RE=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}')
STALE_SECONDS=3600
SQLITE_MAX_INT=2**63-1
PART_RE=re.compile(r'\.[0-9a-f]{32}\.part')

ATT_TYPES={
    'png':'image/png',
    'jpg':'image/jpeg',
    'jpeg':'image/jpeg',
    'gif':'image/gif',
    'webp':'image/webp',
    'txt':'text/plain'
}


def check_path(p,private,is_dir=False):
    try:
        st=p.lstat()
    except FileNotFoundError:
        raise RuntimeError(f"required path missing: {p.name}")
    kind=stat.S_ISDIR if is_dir else stat.S_ISREG
    if not kind(st.st_mode):
        raise RuntimeError(f"unexpected file type: {p.name}")
    if st.st_uid!=os.geteuid():
        raise RuntimeError(f"wrong owner: {p.name}")
    if st.st_mode&(0o077 if private else 0o027):
        raise RuntimeError(f"permissions too broad: {p.name}")


def ensure_private_dir(p):
    p.mkdir(parents=True,exist_ok=True,mode=0o700)
    st=p.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"unexpected file type: {p.name}")
    if st.st_uid!=os.geteuid():
        raise RuntimeError(f"wrong owner: {p.name}")
    if st.st_mode&0o077:
        p.chmod(0o700)
    check_path(p,True,True)


class Config:
    def __init__(self):
        self.secret_dir=Path(os.getenv("ONION_SECRETS","/etc/onionsite"))
        self.data_dir=Path(os.getenv("ONION_DATA","/var/lib/onionsite"))
        raw=os.getenv("ADMIN_PREFIX","admin").strip("/")
        self.admin="/"+raw
        self.max_file=self.mb("MAX_FILE_MB",25)
        self.attach_max=min(self.max_file,self.mb("ATTACH_MB",8))
        self.quota=self.mb("QUOTA_MB",500)
        self.conv_quota=self.mb("CONV_QUOTA_MB",200)
        self.retention=int(os.getenv("RETENTION_DAYS","30"))*86400
        self.cookie_secure=os.getenv("COOKIE_SECURE","0")=="1"
        self.db=self.data_dir/"site.db"
        self.files=self.data_dir/"files"
        self.note=os.getenv("OWNER_NOTE","Messages are encrypted at rest on the server. They are not end-to-end encrypted.")

    @staticmethod
    def mb(name,default):
        value=int(os.getenv(name,str(default)))
        if value<=0:
            raise RuntimeError(f"invalid {name}")
        return value*1024*1024

    def validate(self):
        if os.geteuid()==0:
            raise RuntimeError("must not run as root")

        if (
            len(self.admin)<10
            or not re.fullmatch(r'/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*',self.admin)
            or self.max_file>self.quota
            or self.retention<0
        ):
            raise RuntimeError("invalid configuration")

        check_path(self.secret_dir,True,True)

        for name,hexkey in (("session.key",False),("msg.key",True)):
            p=self.secret_dir/name
            check_path(p,True)
            raw=bytes.fromhex(p.read_text().strip()) if hexkey else p.read_bytes()
            if len(raw)!=32:
                raise RuntimeError("invalid secret length")

        check_path(self.secret_dir/"admin.hash",True)

        ensure_private_dir(self.data_dir)
        ensure_private_dir(self.files)

        for suffix in ("","-wal","-shm"):
            p=Path(str(self.db)+suffix)
            if p.exists() or p.is_symlink():
                check_path(p,True)


C=Config()
UPLOAD_PATHS=(C.admin+"/downloads",C.admin+"/posts")

app=Flask(__name__)
app.config.update(
    SECRET_KEY=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=C.cookie_secure,
    SESSION_COOKIE_NAME="onionsite",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=C.max_file+1024*1024,
    MAX_FORM_MEMORY_SIZE=ADMIN_BODY_LIMIT,
    MAX_FORM_PARTS=40
)

RL={}
RL_LOCK=threading.Lock()


def limited(name,count,window,hit=True):
    now=time.monotonic()
    with RL_LOCK:
        q=RL.setdefault(name,[])
        q[:]=[x for x in q if x>now-window]
        if len(q)>=count:
            return True
        if hit:
            q.append(now)
        return False


def session_limited(name,count,window):
    t=NOW()
    hits=[x for x in session.get(name,[]) if x>t-window]
    if len(hits)>=count:
        return True
    hits.append(t)
    session[name]=hits
    return False


def database():
    if "db" not in g:
        g.db=sqlite3.connect(C.db,timeout=10)
        g.db.row_factory=sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=10000")
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA secure_delete=ON")
    return g.db


def discard_db_changes():
    db=g.get("db")
    if db is not None:
        db.rollback()


@app.teardown_appcontext
def close_db(error):
    db=g.pop("db",None)
    if db:
        if error:
            db.rollback()
        else:
            db.commit()
        db.close()


def init_db():
    database().executescript("""
    CREATE TABLE IF NOT EXISTS convs(
        id INTEGER PRIMARY KEY,
        idhash TEXT UNIQUE NOT NULL,
        sechash TEXT NOT NULL,
        created INTEGER NOT NULL,
        updated INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'open'
    );

    CREATE TABLE IF NOT EXISTS msgs(
        id INTEGER PRIMARY KEY,
        conv INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
        sender TEXT NOT NULL CHECK(sender IN ('v','o')),
        version INTEGER NOT NULL DEFAULT 1,
        blob BLOB NOT NULL,
        created INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files(
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        size INTEGER NOT NULL,
        descr TEXT NOT NULL,
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
        created INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions(
        sidhash TEXT PRIMARY KEY,
        created INTEGER NOT NULL,
        last INTEGER NOT NULL,
        pwfp TEXT NOT NULL
    );
    """)
    migrate_db(database())


NOTICE_COLUMNS=(
    ("timer_until","INTEGER"),
    ("censored","INTEGER NOT NULL DEFAULT 0")
)


def migrate_db(db):
    def have():
        return {r['name'] for r in db.execute("PRAGMA table_info(notices)")}

    for name,decl in NOTICE_COLUMNS:
        if name in have():
            continue

        try:
            db.execute(f"ALTER TABLE notices ADD COLUMN {name} {decl}")
        except sqlite3.OperationalError:
            if name not in have():
                raise

    db.commit()


def secret(name):
    return (C.secret_dir/name).read_bytes() if name=="session.key" else bytes.fromhex((C.secret_dir/name).read_text().strip())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def parse_id(value):
    if (
        not isinstance(value,str)
        or not value.isascii()
        or not value.isdigit()
        or len(value)>19
        or int(value)>SQLITE_MAX_INT
    ):
        abort(400)
    return int(value)


def admin_hash():
    return (C.secret_dir/'admin.hash').read_text().strip()


def pw_fingerprint():
    return digest(admin_hash())[:32]


def invalidate_admin_sessions():
    if not C.db.exists():
        return

    db=sqlite3.connect(C.db,timeout=10)

    try:
        db.execute("DELETE FROM sessions")
        db.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()


def admin_session_valid(touch=True):
    sid=session.get('sid')
    if not isinstance(sid,str) or not sid:
        return False

    t=NOW()
    db=database()
    sidhash=digest(sid)
    row=db.execute('SELECT * FROM sessions WHERE sidhash=?',(sidhash,)).fetchone()

    if not row:
        return False

    if (
        t-row['last']>900
        or t-row['created']>28800
        or not hmac.compare_digest(row['pwfp'],pw_fingerprint())
    ):
        db.execute('DELETE FROM sessions WHERE sidhash=?',(sidhash,))
        return False

    if touch:
        db.execute('UPDATE sessions SET last=? WHERE sidhash=?',(t,sidhash))

    return True


def open_conv(conv_id):
    session['conv']=conv_id
    session['conv_t']=NOW()


def close_conv():
    session.pop('conv',None)
    session.pop('conv_t',None)


def current_conv():
    conv_id=session.get('conv')
    conv_t=session.get('conv_t',0)

    if (
        not isinstance(conv_id,int)
        or isinstance(conv_id,bool)
        or not isinstance(conv_t,int)
        or NOW()-conv_t>CONV_TTL
    ):
        close_conv()
        return None

    row=database().execute('SELECT * FROM convs WHERE id=?',(conv_id,)).fetchone()

    if not row:
        close_conv()

    return row


def encrypt(cid,sender,text):
    nonce=secrets.token_bytes(12)
    return nonce+AESGCM(secret("msg.key")).encrypt(
        nonce,
        text.encode(),
        f"v1:{cid}:{sender}".encode()
    )


def decrypt(cid,sender,blob):
    try:
        return AESGCM(secret("msg.key")).decrypt(
            blob[:12],
            blob[12:],
            f"v1:{cid}:{sender}".encode()
        ).decode()
    except Exception:
        return "[message unavailable]"


def thread(db,cid,me):
    out=[]

    for x in db.execute('SELECT * FROM msgs WHERE conv=? ORDER BY id DESC LIMIT ?',(cid,THREAD_LIMIT)):
        w=x['sender']
        out.append({
            'who':'You' if w==me else ('Operator' if w=='o' else 'Guest'),
            'mine':w==me,
            'text':decrypt(cid,w,x['blob']),
            'when':fmt_dt(x['created'])
        })

    return out


def used_bytes(db):
    return db.execute(
        'SELECT (SELECT coalesce(sum(size),0) FROM files)'
        '+(SELECT coalesce(sum(size),0) FROM attachments)'
    ).fetchone()[0]


def conv_bytes(db):
    return db.execute('SELECT coalesce(sum(length(blob)),0) FROM msgs').fetchone()[0]


def begin_conv_write(db,m):
    db.commit()
    db.execute('BEGIN IMMEDIATE')

    if conv_bytes(db)+len(m.encode())+BLOB_OVERHEAD>C.conv_quota:
        abort(503)


def is_expired(timer_until):
    return timer_until is not None and NOW()>=timer_until


def fmt_size(n):
    return f"{n/1048576:.1f} MB" if n>=1048576 else f"{n/1024:.1f} KB"


def fmt_date(n):
    return time.strftime("%Y-%m-%d",time.gmtime(n))


def fmt_dt(n):
    return time.strftime("%Y-%m-%d %H:%M UTC",time.gmtime(n))


def fmt_remaining(secs):
    d,r=divmod(max(secs,0),86400)
    h,r=divmod(r,3600)
    m=r//60
    parts=[f"{d}d"] if d else []
    if d or h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts) if (d or h or m) else "less than 1 minute"


CSS="""
:root{--bg:#f4f5fb;--card:#fff;--ink:#1f2340;--mute:#6b7090;--line:#e3e5f2;--side:#1e1b4b;--side2:#2d2a6e;--pri:#6d5dfc;--pri2:#4f46e5;--soft:#eeecff;--bad:#e11d48;--badbg:#fff1f4;--ok:#0d9f6e;--okbg:#e8f8f1;--r:14px}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;min-height:100vh;color:var(--ink);font:15px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
a{color:var(--pri2);text-decoration:none}
a:hover{text-decoration:underline}
.shell{display:grid;grid-template-columns:15.5rem minmax(0,1fr);min-height:100vh}
.side{background:var(--side);color:#c9c7f5;padding:1.5rem 1rem;position:sticky;top:0;height:100vh;overflow:auto}
.brand{font-size:1.25rem;font-weight:700;color:#fff;margin:0 .5rem}
.tag{font-size:.78rem;color:#9a98d6;margin:.1rem .5rem 1.6rem}
.side h4{font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;color:#8280c4;margin:1.4rem .6rem .4rem}
.side nav{display:flex;flex-direction:column;gap:.2rem}
.side form{margin:0}
.nv{display:block;width:100%;text-align:left;padding:.55rem .75rem;border-radius:10px;color:#c9c7f5;background:transparent;border:0;font:inherit;cursor:pointer;margin:0}
.nv:hover{background:var(--side2);color:#fff;text-decoration:none}
.nv.on{background:var(--pri);color:#fff}
.content{padding:2rem 2.4rem 3rem;max-width:58rem;width:100%}
.ttl{font-size:1.7rem;line-height:1.25;margin:.2rem 0 .4rem;overflow-wrap:anywhere}
.sec{font-size:1.05rem;margin:2rem 0 .8rem}
.mute,small{color:var(--mute)}
.none{color:var(--mute);background:var(--card);border:2px dashed var(--line);border-radius:var(--r);padding:1.2rem;text-align:center}
.hero{background:linear-gradient(135deg,#6d5dfc,#8b5cf6 60%,#c084fc);color:#fff;border-radius:20px;padding:1.8rem;margin-bottom:.5rem}
.hero h1{margin:0 0 .4rem;font-size:2rem}
.hero p{margin:0 0 1.1rem;max-width:36rem;opacity:.95}
.hero-actions{display:flex;gap:.6rem;flex-wrap:wrap}
.btn,button{font:inherit;cursor:pointer;display:inline-block;border-radius:999px;padding:.55rem 1.3rem;border:1px solid var(--line);background:var(--card);color:var(--ink);margin:.3rem 0}
.btn:hover,button:hover{text-decoration:none;border-color:var(--pri)}
.btn.pri{background:var(--pri);border-color:var(--pri);color:#fff}
.btn.pri:hover{background:var(--pri2);border-color:var(--pri2)}
.btn.line{background:transparent}
.btn.sm{padding:.3rem .9rem;font-size:.85rem}
.btn.ghost-l{background:rgba(255,255,255,.18);border-color:rgba(255,255,255,.45);color:#fff}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1.1rem 1.2rem;margin:1rem 0;box-shadow:0 2px 10px rgba(31,35,64,.05)}
.fld{display:block;font-weight:600;font-size:.88rem;margin:.7rem 0}
.chk{display:block;margin:.5rem 0}
input,textarea{font:inherit;color:var(--ink);width:100%;max-width:100%;margin:.3rem 0 0;padding:.6rem .8rem;border:1px solid var(--line);border-radius:10px;background:#fbfbff;font-weight:400}
input[type=checkbox]{width:auto;margin-right:.4rem}
input:focus,textarea:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(109,93,252,.2)}
.post{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--pri);border-radius:var(--r);margin:1rem 0;box-shadow:0 2px 10px rgba(31,35,64,.05);overflow:hidden}
.post header{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.9rem 1.2rem 0}
.post h3{margin:0;font-size:1.1rem;overflow-wrap:anywhere}
.post .body{padding:.6rem 1.2rem;white-space:pre-wrap;overflow-wrap:anywhere}
.post p{padding:.6rem 1.2rem;margin:0}
.post footer{padding:.2rem 1.2rem 1rem}
.post.late{border-top-color:var(--bad)}
.post.gone{border-top-color:var(--line);opacity:.85}
.pill{display:inline-block;background:var(--soft);color:var(--pri2);border-radius:999px;padding:.1rem .7rem;font-size:.78rem;white-space:nowrap}
.pill.bad{background:var(--badbg);color:var(--bad)}
.pill.ok{background:var(--okbg);color:var(--ok)}
.gal{display:flex;flex-wrap:wrap;gap:.6rem;padding:.4rem 1.2rem}
img.att{max-width:100%;max-height:22rem;height:auto;border-radius:10px;border:1px solid var(--line);display:block}
.chip{display:inline-block;background:var(--soft);border-radius:10px;padding:.4rem .8rem}
.frows{display:grid;gap:.6rem;margin:1rem 0}
.frow,.frow2{display:flex;align-items:center;gap:1rem;background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:.8rem 1rem;color:var(--ink)}
.frow:hover{border-color:var(--pri);text-decoration:none}
.fi{flex:none;min-width:3rem;height:3rem;border-radius:12px;background:var(--soft);color:var(--pri2);display:grid;place-items:center;font-weight:700;font-size:.78rem;padding:0 .4rem}
.fi.lg{min-width:4rem;height:4rem;font-size:.95rem}
.fm{flex:1;min-width:0;display:flex;flex-direction:column}
.fm b{overflow-wrap:anywhere}
.fs{text-align:right;font-size:.8rem;color:var(--mute);white-space:nowrap}
.filehead{display:flex;gap:1rem;align-items:center;margin-bottom:.8rem}
.back{display:inline-block;margin-bottom:.4rem;color:var(--mute)}
.seg{display:inline-flex;flex-wrap:wrap;gap:.2rem;background:var(--card);border:1px solid var(--line);border-radius:999px;padding:.25rem;margin:0 0 1.2rem}
.seg a{padding:.35rem .95rem;border-radius:999px;color:var(--mute);font-size:.88rem}
.seg a:hover{text-decoration:none;color:var(--ink)}
.seg a.on{background:var(--pri);color:#fff}
.tiles{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));margin:1.2rem 0}
.tile{display:flex;flex-direction:column;gap:.3rem;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:1.2rem;color:var(--mute);box-shadow:0 2px 10px rgba(31,35,64,.05)}
.tile:hover{border-color:var(--pri);text-decoration:none}
.tile b{color:var(--ink);font-size:1.05rem}
.ico{width:2.4rem;height:2.4rem;border-radius:12px;background:var(--soft);color:var(--pri2);display:grid;place-items:center;font-size:1.2rem}
.steps{display:grid;gap:.8rem;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr))}
.steps div{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1rem;display:flex;flex-direction:column;gap:.2rem}
.steps i{font-style:normal;width:1.8rem;height:1.8rem;border-radius:50%;background:var(--pri);color:#fff;display:grid;place-items:center;font-weight:700}
.steps span{color:var(--mute);font-size:.9rem}
summary{cursor:pointer;font-weight:600}
details.card>summary{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
details[open]>summary{margin-bottom:.6rem}
.faq ul{padding-left:1.2rem;color:var(--mute);margin:.4rem 0 0}
.faq li{margin:.35rem 0}
.cred{background:#14123a;color:#e7e5ff;border-radius:var(--r);padding:.8rem 1rem;margin:.7rem 0}
.cred small{color:#9a98d6;display:block;text-transform:uppercase;letter-spacing:.1em;font-size:.7rem}
.cred code{font:15px/1.5 ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere;user-select:all}
.alert{background:var(--badbg);color:var(--bad);border:1px solid #fbc2cf;border-radius:var(--r);padding:.8rem 1rem;margin:.8rem 0}
.narrow{max-width:26rem;margin:1.5rem auto}
.bigcode{font-size:4rem;font-weight:800;color:var(--pri);line-height:1}
.composer{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:.6rem .8rem;margin:.6rem 0}
.composer textarea{border:0;background:transparent;box-shadow:none;resize:vertical}
.crow{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.feedbox{display:block;width:100%;height:50vh;min-height:16rem;border:1px solid var(--line);border-radius:var(--r);background:#fff;margin:.6rem 0 1rem}
body.feed{display:block;padding:.8rem;background:#fff;min-height:0}
.bub{max-width:85%;background:var(--soft);border-radius:16px 16px 16px 4px;padding:.55rem .85rem;margin:.6rem 0}
.bub.me{margin-left:auto;background:var(--pri);color:#fff;border-radius:16px 16px 4px 16px}
.bub .who{font-size:.75rem;opacity:.75}
.bub .txt{white-space:pre-wrap;overflow-wrap:anywhere}
.stats{display:grid;gap:.8rem;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));margin:1rem 0}
.stats div{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1rem;display:flex;flex-direction:column}
.stats b{font-size:1.6rem}
.stats span{color:var(--mute);font-size:.85rem}
progress{width:100%;height:.6rem;accent-color:var(--pri)}
@media (max-width:52rem){.shell{grid-template-columns:1fr}.side{position:static;height:auto;padding:1rem}.side nav{flex-direction:row;flex-wrap:wrap}.tag{margin-bottom:.8rem}.side h4{margin:.8rem 0 .2rem}.nv{width:auto}.content{padding:1.2rem 1rem 2rem}}
@media (max-width:30rem){.frow{flex-wrap:wrap}.fs{text-align:left}.bub{max-width:95%}}
"""

BASE="""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tiny Desk</title><link rel="stylesheet" href="/assets/style.css"></head><body><div class="shell"><aside class="side"><div class="brand">◈ Tiny Desk</div><div class="tag">notes · files · messages</div><nav>
<a class="nv{{' on' if request.path=='/' else ''}}" href="/">Notices</a>
<a class="nv{{' on' if request.path.startswith('/downloads') else ''}}" href="/downloads">Downloads</a>
<a class="nv{{' on' if request.path.startswith(('/contact','/resume','/thread')) else ''}}" href="/contact">Contact</a>
</nav>{% if is_admin %}<h4>Operator</h4><nav>
<a class="nv{{' on' if request.path==adm_root else ''}}" href="{{adm_root}}">Overview</a>
<a class="nv{{' on' if request.path.startswith(adm_root+'/posts') else ''}}" href="{{adm_root}}/posts">Posts</a>
<a class="nv{{' on' if request.path.startswith(adm_root+'/downloads') else ''}}" href="{{adm_root}}/downloads">Files</a>
<a class="nv{{' on' if request.path.startswith(adm_root+'/threads') else ''}}" href="{{adm_root}}/threads">Threads</a>
<form method="post" action="{{adm_root}}/signout"><input type="hidden" name="csrf" value="{{session.csrf}}"><button class="nv">Sign out</button></form>
</nav>{% endif %}</aside><main class="content">"""
FOOT="</main></div></body></html>"
FEED_A="<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
FEED_B="<link rel='stylesheet' href='/assets/style.css'></head><body class=feed><main>"
CS='<input type="hidden" name="csrf" value="{{session.csrf}}">'

FEED_BODY=(
    "{% for m in messages %}"
    "<div class='bub{{' me' if m.mine else ''}}'>"
    "<div class=who>{{m.who}} · {{m.when}}</div>"
    "<div class=txt>{{m.text}}</div>"
    "</div>"
    "{% else %}"
    "<p class=none>No messages yet.</p>"
    "{% endfor %}"
)

ATT_HTML=(
    "{% if atts.get(n.nid) %}<div class=gal>"
    "{% for at in atts.get(n.nid,[]) %}"
    "{% if at.mime.startswith('image/') %}"
    "<a href='/att/{{at.id}}'><img class=att src='/att/{{at.id}}' alt='{{at.name}}' loading=lazy></a>"
    "{% else %}"
    "<a class=chip href='/att/{{at.id}}'>{{at.name}} <small>{{sz(at.size)}}</small></a>"
    "{% endif %}"
    "{% endfor %}"
    "</div>{% endif %}"
)


def page(body,**ctx):
    return render_template_string(BASE+body+FOOT,adm_root=C.admin,is_admin=in_admin_area(),**ctx)


def feed_page(body,refresh=True,**ctx):
    meta=f"<meta http-equiv='refresh' content='{FEED_SECONDS}'>" if refresh else ""
    return render_template_string(FEED_A+meta+FEED_B+body+"</main></body></html>",**ctx)


def talk_nav(active):
    tabs=[
        ('how','/contact','Overview'),
        ('new','/contact/start','Write'),
        ('continue','/resume','Resume')
    ]

    if session.get('conv'):
        tabs.append(('chat','/thread','My thread'))

    return "<div class=seg>"+"".join(
        f"<a class='{'on' if k==active else ''}' href='{u}'>{t}</a>"
        for k,u,t in tabs
    )+"</div>"


def error_page(code,msg):
    return page(
        "<div class=narrow><div class=bigcode>{{c}}</div>"
        "<h1 class=ttl>{{m}}</h1>"
        "<p class=mute>That request could not be completed.</p>"
        "<p><a class='btn pri' href='/'>Back to start</a></p></div>",
        c=code,m=msg
    )


def in_admin_area():
    path=request.path
    if path==C.admin+"/signin" or request.endpoint=='login':
        return False
    if path==C.admin or path.startswith(C.admin+"/"):
        return True
    rule=request.url_rule.rule if request.url_rule else ""
    return rule==C.admin or rule.startswith(C.admin+"/")


@app.before_request
def guard():
    if "csrf" not in session:
        session["csrf"]=secrets.token_urlsafe(24)

    admin_area=in_admin_area()

    if admin_area:
        feed=request.endpoint=='admin_feed'

        if not admin_session_valid(touch=not feed):
            session.clear()
            if feed:
                return feed_page("<p class=none>Session expired. Reload the page.</p>",refresh=False),401
            return redirect(C.admin+"/signin")

    if request.method=="POST":
        limit=PUBLIC_BODY_LIMIT
        if admin_area:
            limit=C.max_file+1024*1024 if request.path in UPLOAD_PATHS else ADMIN_BODY_LIMIT

        length=request.content_length
        if length is None or length>limit:
            abort(413)

        sent=request.form.get("csrf","").encode()
        if not hmac.compare_digest(sent,session["csrf"].encode()):
            abort(403)


@app.after_request
def headers(response):
    framed=request.endpoint in ('chat_feed','admin_feed')
    response.headers.update({
        "Content-Security-Policy":"default-src 'none'; object-src 'none'; style-src 'self'; img-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors "+("'self'" if framed else "'none'"),
        "X-Frame-Options":"SAMEORIGIN" if framed else "DENY",
        "X-Content-Type-Options":"nosniff",
        "Referrer-Policy":"no-referrer",
        "Permissions-Policy":"camera=(),geolocation=(),microphone=()",
        "Cache-Control":"no-store",
        "Cross-Origin-Opener-Policy":"same-origin"
    })
    return response


ERRORS={
    400:"Bad request",
    403:"Forbidden",
    404:"Not found",
    405:"Method not allowed",
    413:"Request too large",
    429:"Too many requests",
    500:"Internal error",
    503:"Service temporarily unavailable"
}


@app.errorhandler(HTTPException)
def http_error(e):
    code=e.code or 500

    if code<400:
        return e

    discard_db_changes()
    return error_page(code,ERRORS.get(code,"Error")),code


@app.errorhandler(sqlite3.Error)
def db_error(e):
    discard_db_changes()
    log.error('database_error %s',type(e).__name__)
    code=503 if isinstance(e,sqlite3.OperationalError) else 500
    return error_page(code,ERRORS[code]),code


@app.get('/assets/style.css')
def css():
    return Response(CSS,mimetype='text/css')


def public_notices(db):
    rows=db.execute(
        'SELECT * FROM notices WHERE published=1 ORDER BY created DESC, id DESC LIMIT ?',
        (MAX_PUBLIC_NOTICES,)
    ).fetchall()

    ids=[r['id'] for r in rows if not r['censored']]
    atts={}

    if ids:
        marks=','.join('?'*len(ids))
        for a in db.execute(
            f'SELECT * FROM attachments WHERE notice IN ({marks}) ORDER BY created',
            ids
        ):
            atts.setdefault(a['notice'],[]).append(a)

    views=[]
    for r in rows:
        censored=bool(r['censored'])
        t=r['timer_until']
        timer_at=''
        timer_left=''
        if t is not None and not censored:
            try:
                timer_at=fmt_dt(t)
                timer_left=fmt_remaining(t-NOW())
            except (OverflowError,ValueError,OSError):
                timer_at=''
        views.append({
            'nid':r['id'],
            'title':'' if censored else r['title'],
            'content':'' if censored else r['content'],
            'when':fmt_date(r['updated']),
            'expired':is_expired(t) and not censored,
            'censored':censored,
            'timer_at':timer_at,
            'timer_left':timer_left
        })

    return views,atts


@app.get('/')
def home():
    notices,atts=public_notices(database())

    return page(
        "<section class=hero><h1>Tiny Desk</h1><p>{{note}}</p>"
        "<div class=hero-actions>"
        "<a class='btn pri' href='/contact'>Message the operator</a>"
        "<a class='btn ghost-l' href='/downloads'>Browse downloads</a>"
        "</div></section>"
        "<h2 class=sec>Latest notices</h2>"
        "{% for n in notices %}"
        "<article class='post{% if n.expired %} late{% endif %}{% if n.censored %} gone{% endif %}'>"
        "{% if n.censored %}"
        "<header><h3>Removed</h3><span class=pill>{{n.when}}</span></header>"
        "<p class=mute>The operator removed this notice.</p>"
        "{% else %}"
        "<header><h3>{{n.title}}</h3><span class=pill>{{n.when}}</span></header>"
        "<div class=body>{{n.content}}</div>"
        +ATT_HTML+
        "{% endif %}"
        "{% if n.timer_at %}<footer>"
        "{% if n.expired %}<span class='pill bad'>Timer ended {{n.timer_at}}</span>"
        "{% else %}<span class='pill ok'>Ends {{n.timer_at}} · {{n.timer_left}} left</span>{% endif %}"
        "</footer>{% endif %}"
        "</article>"
        "{% else %}"
        "<p class=none>Nothing posted yet.</p>"
        "{% endfor %}",
        note=C.note,
        notices=notices,
        atts=atts,
        sz=fmt_size
    )


@app.get('/downloads')
def files():
    return page(
        "<h1 class=ttl>Downloads</h1>"
        "<p class=mute>Files shared by the operator.</p>"
        "<div class=frows>"
        "{% for f in rows %}"
        "<a class=frow href='/downloads/{{f.id}}'>"
        "<span class=fi>{{(f.name.rsplit('.',1)[-1] if '.' in f.name else 'file')[:4]|upper}}</span>"
        "<span class=fm><b>{{f.name}}</b><small>{{f.descr}}</small></span>"
        "<span class=fs>{{sz(f.size)}}<br>{{dt(f.created)}}</span></a>"
        "{% else %}"
        "<p class=none>No files yet.</p>"
        "{% endfor %}"
        "</div>",
        rows=database().execute(
            'SELECT * FROM files ORDER BY created DESC'
        ).fetchall(),
        sz=fmt_size,
        dt=fmt_date
    )


def valid_id(value):
    return isinstance(value,str) and len(value)==32 and all(c in '0123456789abcdef' for c in value)


def stored_path(fid):
    if not valid_id(fid):
        abort(404)
    return C.files/fid


def unlink_stored(ids):
    for fid in ids:
        if not valid_id(fid):
            log.warning('unlink_skipped_invalid_id')
            continue

        try:
            (C.files/fid).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            log.warning('unlink_failed')


def getfile(fid):
    if not valid_id(fid):
        abort(404)

    return database().execute(
        'SELECT * FROM files WHERE id=?',
        (fid,)
    ).fetchone() or abort(404)


@app.get('/downloads/<fid>')
def fileview(fid):
    f=getfile(fid)

    return page(
        "<a class=back href='/downloads'>← All downloads</a>"
        "<div class=card>"
        "<div class=filehead>"
        "<span class='fi lg'>{{(f.name.rsplit('.',1)[-1] if '.' in f.name else 'file')[:4]|upper}}</span>"
        "<div><h1 class=ttl>{{f.name}}</h1>"
        "<p class=mute>{{sz(f.size)}} · added {{dt(f.created)}}</p></div></div>"
        "{% if f.descr %}<p>{{f.descr}}</p>{% endif %}"
        "<a class='btn pri' href='/downloads/{{f.id}}/download'>Download file</a>"
        "</div>",
        f=f,
        sz=fmt_size,
        dt=fmt_date
    )


@app.get('/downloads/<fid>/download')
def download(fid):
    f=getfile(fid)
    p=stored_path(f['id'])

    if not p.is_file() or p.is_symlink():
        abort(404)

    return send_file(
        p,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f['name'],
        conditional=True
    )


def attachment_row(aid,published_only):
    if not valid_id(aid):
        abort(404)

    sql='SELECT a.* FROM attachments a JOIN notices n ON n.id=a.notice WHERE a.id=?'

    if published_only:
        sql+=' AND n.published=1 AND n.censored=0'

    return database().execute(sql,(aid,)).fetchone() or abort(404)


def send_attachment(row):
    p=stored_path(row['id'])

    if not p.is_file() or p.is_symlink():
        abort(404)

    return send_file(p,mimetype=row['mime'],conditional=True)


@app.get('/att/<aid>')
def attachment(aid):
    return send_attachment(attachment_row(aid,True))


@app.get('/contact')
def talk():
    return page(
        talk_nav('how')+
        "<h1 class=ttl>Message the operator</h1>"
        "<p class=mute>Anonymous and simple. No account, e-mail or name.</p>"
        "<div class=tiles>"
        "<a class=tile href='/contact/start'><span class=ico>✎</span><b>Write a new message</b>"
        "<span>First visit? Send a message and get your Ticket and Key.</span></a>"
        "<a class=tile href='/resume'><span class=ico>↺</span><b>Resume a thread</b>"
        "<span>Already have a Ticket and Key? Pick up where you left off.</span></a>"
        "</div>"
        "<h2 class=sec>Three steps</h2>"
        "<div class=steps>"
        "<div><i>1</i><b>Write</b><span>Send your first message.</span></div>"
        "<div><i>2</i><b>Save</b><span>Store the Ticket and Key you receive.</span></div>"
        "<div><i>3</i><b>Return</b><span>Resume any time and read the reply.</span></div>"
        "</div>"
        "<details class='card faq'><summary>Things to know</summary><ul>"
        "<li>The Ticket and Key are the only way back in. They cannot be recovered or reset.</li>"
        "<li>Anyone holding both can read and write in your thread, so keep them private.</li>"
        "<li>Messages are stored encrypted, but the operator can read them. This is not end-to-end encryption.</li>"
        "<li>Replies are not instant. The operator answers when available.</li>"
        "<li>Messages are limited to 4000 characters, and the number of new threads per hour is limited.</li>"
        "{% if days %}<li>Threads with no activity for {{days}} days may be deleted.</li>{% endif %}"
        "</ul></details>",
        days=C.retention//86400
    )


@app.route('/contact/start',methods=['GET','POST'])
def talk_new():
    if request.method=='GET':
        return page(
            talk_nav('new')+
            '<h1 class=ttl>Write a message</h1>'
            '<p class=mute>You will receive a Ticket and a Key right after sending.</p>'
            '<form method=post class=card>'+CS+
            '<label class=fld>Your message'
            '<textarea name=m maxlength=4000 rows=8 required placeholder="Say what you need to say (max 4000 characters)"></textarea></label>'
            '<button class="btn pri">Send message</button></form>'
            '<p class=mute>Already have a thread? <a href="/resume">Resume it</a>.</p>'
        )

    if session_limited('new',3,3600) or limited('new',600,3600):
        abort(429)

    m=request.form.get('m','').strip()

    if not m or len(m)>4000:
        abort(400)

    db=database()
    begin_conv_write(db,m)

    cid,sec=secrets.token_urlsafe(16),secrets.token_urlsafe(32)
    t=NOW()

    cur=db.execute(
        'INSERT INTO convs(idhash,sechash,created,updated) VALUES(?,?,?,?)',
        (digest(cid),digest(sec),t,t)
    )

    db.execute(
        'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
        (cur.lastrowid,'v',encrypt(cur.lastrowid,'v',m),t)
    )

    db.commit()
    open_conv(cur.lastrowid)

    log.info('conversation_created')

    return page(
        talk_nav('new')+
        '<h1 class=ttl>Message sent ✓</h1>'
        '<div class=alert>Copy these now. They are shown only once and cannot be recovered or reset.</div>'
        '<div class=cred><small>Ticket</small><code>{{cid}}</code></div>'
        '<div class=cred><small>Key</small><code>{{sec}}</code></div>'
        '<p class=mute>This browser is already signed in, so you can open your thread right away. '
        'Use the Ticket and Key to return later or from another browser.</p>'
        '<p><a class="btn pri" href="/thread">Open my thread</a></p>',
        cid=cid,
        sec=sec
    )


@app.route('/resume',methods=['GET','POST'])
def conversation():
    if request.method=='GET':
        resume=(
            '<p><a href="/thread">A thread is already open in this browser. Return to it →</a></p>'
            if current_conv() else ''
        )

        return page(
            talk_nav('continue')+
            '<div class=narrow>'
            '<h1 class=ttl>Resume a thread</h1>'
            '<p class=mute>Enter the Ticket and Key you saved after sending your first message.</p>'
            +resume+
            '<form method=post class=card>'+CS+
            '<label class=fld>Ticket<input name=cid required autocomplete=off></label>'
            '<label class=fld>Key<input name=sec type=password required autocomplete=off></label>'
            '<button class="btn pri">Open thread</button></form>'
            '<p class=mute>Lost them? They cannot be recovered. '
            '<a href="/contact/start">Write a new message</a>.</p>'
            '</div>'
        )

    if limited('read_fail',1200,60,hit=False):
        abort(429)

    cid=request.form.get('cid','').strip()
    sec=request.form.get('sec','').strip()

    row=None
    if len(cid)<=128 and len(sec)<=128:
        row=database().execute(
            'SELECT * FROM convs WHERE idhash=?',
            (digest(cid),)
        ).fetchone()

    stored=row['sechash'] if row else digest('-')
    ok=hmac.compare_digest(stored,digest(sec)) and row is not None

    if not ok:
        limited('read_fail',1200,60)
        return page(
            talk_nav('continue')+
            '<div class=narrow>'
            '<div class=alert>The Ticket or Key does not match. Check for typos or extra spaces.</div>'
            '<p><a class="btn pri" href="/resume">Try again</a></p>'
            '</div>'
        ),403

    open_conv(row['id'])

    return redirect('/thread',303)


@app.route('/thread',methods=['GET','POST'])
def chat():
    row=current_conv()

    if not row:
        return redirect('/resume')

    if request.method=='POST':
        m=request.form.get('m','').strip()

        if m:
            if len(m)>4000:
                abort(400)

            if session_limited('send',10,60) or limited('send',1200,60):
                abort(429)

            db=database()
            begin_conv_write(db,m)

            if not db.execute('SELECT 1 FROM convs WHERE id=?',(row['id'],)).fetchone():
                abort(404)

            db.execute(
                'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
                (row['id'],'v',encrypt(row['id'],'v',m),NOW())
            )

            db.execute(
                'UPDATE convs SET updated=? WHERE id=?',
                (NOW(),row['id'])
            )

            db.commit()

        return redirect('/thread',303)

    return page(
        talk_nav('chat')+
        "<h1 class=ttl>Your thread</h1>"
        "<form method=post class=composer>"+CS+
        "<textarea name=m maxlength=4000 rows=3 required placeholder='Write a reply…'></textarea>"
        "<div class=crow><span class=mute>Newest first · refreshes every few seconds</span>"
        "<button class='btn pri'>Send</button></div></form>"
        "<iframe class=feedbox src='/thread/feed' title='Messages'></iframe>"
        "<form method=post action='/thread/leave'>"+CS+
        "<button class='btn line'>Close thread</button> "
        "<span class=mute>Only signs you out in this browser. Your messages stay.</span></form>"
    )


@app.get('/thread/feed')
def chat_feed():
    row=current_conv()

    if not row:
        return feed_page("<p class=none>Thread closed or not found.</p>",refresh=False),403

    return feed_page(FEED_BODY,messages=thread(database(),row['id'],'v'))


@app.post('/thread/leave')
def chat_leave():
    close_conv()
    return redirect('/contact',303)


@app.route(C.admin+'/signin',methods=['GET','POST'])
def login():
    if request.method=='GET':
        return page(
            '<div class=narrow>'
            '<h1 class=ttl>Operator sign-in</h1>'
            '<form method=post class=card>'+CS+
            '<label class=fld>Password'
            '<input name=pw type=password required autocomplete=current-password></label>'
            '<button class="btn pri">Sign in</button></form></div>'
        )

    if limited('login_fail',50,300,hit=False):
        abort(429)

    pw=request.form.get('pw','')
    ok=False

    if 0<len(pw)<=MAX_PASSWORD_LEN:
        try:
            PH.verify(admin_hash(),pw)
            ok=True
        except Exception:
            ok=False

    if not ok:
        limited('login_fail',50,300)
        log.warning('admin_login_failed')
        return page("<div class=narrow><div class=alert>Invalid credentials.</div>"
                    "<p><a class='btn line' href='{{l}}'>Try again</a></p></div>",l=C.admin+'/signin'),401

    db=database()
    t=NOW()

    db.execute(
        'DELETE FROM sessions WHERE created<? OR last<?',
        (t-28800,t-900)
    )

    sid=secrets.token_urlsafe(32)

    db.execute(
        'INSERT INTO sessions(sidhash,created,last,pwfp) VALUES(?,?,?,?)',
        (digest(sid),t,t,pw_fingerprint())
    )

    session.clear()
    session.update(sid=sid,csrf=secrets.token_urlsafe(24))

    log.info('admin_login_success')

    return redirect(C.admin)


@app.post(C.admin+'/signout')
def logout():
    sid=session.get('sid')

    if isinstance(sid,str):
        database().execute(
            'DELETE FROM sessions WHERE sidhash=?',
            (digest(sid),)
        )

    session.clear()
    return redirect('/')


@app.get(C.admin)
def dashboard():
    db=database()
    n=db.execute(
        'SELECT '
        '(SELECT count(*) FROM files),'
        '(SELECT count(*) FROM convs)'
    ).fetchone()

    return page(
        "<h1 class=ttl>Overview</h1>"
        "<div class=stats>"
        "<div><b>{{n[0]}}</b><span>Files</span></div>"
        "<div><b>{{n[1]}}</b><span>Threads</span></div>"
        "<div><b>{{sz(used)}}</b><span>of {{quota}} used</span></div>"
        "</div>"
        "<progress value='{{used}}' max='{{qraw}}'></progress>"
        "<h2 class=sec>Manage</h2>"
        "<div class=tiles>"
        "<a class=tile href='{{a}}/posts'><span class=ico>✎</span><b>Posts</b><span>Notices, attachments and timers.</span></a>"
        "<a class=tile href='{{a}}/downloads'><span class=ico>⇩</span><b>Files</b><span>Upload or remove downloads.</span></a>"
        "<a class=tile href='{{a}}/threads'><span class=ico>✉</span><b>Threads</b><span>Read and answer messages.</span></a>"
        "</div>",
        n=n,
        used=used_bytes(db),
        qraw=C.quota,
        sz=fmt_size,
        quota=fmt_size(C.quota),
        a=C.admin
    )


def safe_name(name):
    name=Path(name.replace('\\','/')).name
    name=''.join(ch for ch in name if ch.isprintable())[-120:].strip()
    return 'file' if name in ('','.','..') else name


def file_ext(name):
    return name.rsplit('.',1)[-1].lower() if '.' in name else ''


def attachment_ok(ext,head):
    if ext=='png':
        return head.startswith(b'\x89PNG\r\n\x1a\n')
    if ext in ('jpg','jpeg'):
        return head.startswith(b'\xff\xd8\xff')
    if ext=='gif':
        return head[:4]==b'GIF8'
    if ext=='webp':
        return head[:4]==b'RIFF' and head[8:12]==b'WEBP'
    if ext=='txt':
        return b'\x00' not in head
    return False


def parse_timer():
    if not request.form.get('timer'):
        return None

    raw=request.form.get('timer_until','').strip()

    if not TIMER_RE.fullmatch(raw):
        abort(400)

    try:
        dt=datetime.strptime(raw,'%Y-%m-%dT%H:%M')
    except ValueError:
        abort(400)

    ts=calendar.timegm(dt.timetuple())

    if not 0<=ts<=MAX_TIMER:
        abort(400)

    return ts


def admin_notice(r):
    d=dict(r)
    t=r['timer_until']
    d['expired']=is_expired(t)
    try:
        d['timer_val']='' if t is None else time.strftime('%Y-%m-%dT%H:%M',time.gmtime(t))
        d['timer_label']=(
            'Timer: off' if t is None
            else f'Timer: expired ({fmt_dt(t)})' if d['expired']
            else f'Timer: {fmt_dt(t)}'
        )
    except (OverflowError,ValueError,OSError,TypeError):
        d['timer_val']=''
        d['timer_label']='Timer: invalid value (re-save to fix)'
    return d


def read_attachments():
    items=[]

    for up in request.files.getlist('att'):
        if not up or not up.filename:
            continue

        if len(items)>=MAX_ATTACHMENTS:
            abort(400)

        name=safe_name(up.filename)
        ext=file_ext(name)

        if ext not in ATT_TYPES:
            abort(400)

        head=up.stream.read(512)
        up.stream.seek(0)

        if not attachment_ok(ext,head):
            abort(400)

        items.append((up,{'name':name,'mime':ATT_TYPES[ext]}))

    return items


def attachment_count(db,nid):
    return db.execute('SELECT count(*) FROM attachments WHERE notice=?',(nid,)).fetchone()[0]


def stage_upload(up,limit):
    fid=secrets.token_hex(16)
    tmp=C.files/('.'+fid+'.part')
    total=0
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)

    try:
        with os.fdopen(fd,'wb') as out:
            while chunk:=up.stream.read(65536):
                total+=len(chunk)

                if total>limit:
                    raise ValueError

                out.write(chunk)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    return fid,tmp,total


def store(db,items,limit,prepare,insert):
    staged=[]
    placed=[]

    try:
        for up,meta in items:
            staged.append(stage_upload(up,limit)+(meta,))

        db.commit()
        db.execute('BEGIN IMMEDIATE')

        if used_bytes(db)+sum(s[2] for s in staged)>C.quota:
            raise ValueError

        prepare()

        for fid,tmp,total,meta in staged:
            insert(fid,total,meta)
            os.replace(tmp,stored_path(fid))
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


def attachment_inserter(db,holder):
    def insert(fid,total,meta):
        db.execute(
            'INSERT INTO attachments(id,notice,name,mime,size,created) VALUES(?,?,?,?,?,?)',
            (fid,holder['nid'],meta['name'],meta['mime'],total,NOW())
        )
    return insert


def sweep_store(db=None,delete=False):
    cutoff=time.time()-STALE_SECONDS
    known=set()

    if db is not None:
        known={r[0] for r in db.execute('SELECT id FROM files UNION SELECT id FROM attachments')}

    present=set()
    parts=[]
    orphans=[]
    odd=0

    with os.scandir(C.files) as it:
        for e in it:
            n=e.name

            if e.is_symlink() or not e.is_file(follow_symlinks=False):
                odd+=1
                continue

            try:
                old=e.stat(follow_symlinks=False).st_mtime<cutoff
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
                odd+=1

    if delete:
        for n in parts+orphans:
            try:
                (C.files/n).unlink()
            except OSError:
                log.warning('sweep_unlink_failed')

    return {
        'stale_parts':len(parts),
        'orphans':len(orphans),
        'missing':len(known-present) if db is not None else 0,
        'unexpected':odd
    }


@app.get(C.admin+'/att/<aid>')
def admin_attachment(aid):
    return send_attachment(attachment_row(aid,False))


@app.route(C.admin+'/posts',methods=['GET','POST'])
def admin_notices():
    db=database()

    if request.method=='POST':
        action=request.form.get('action','')

        if action in ('create','edit'):
            title=request.form.get('title','').strip()
            content=request.form.get('content','').strip()
            published=1 if request.form.get('published') else 0

            if not title or not content or len(title)>200 or len(content)>10000:
                abort(400)

            edit_id=parse_id(request.form.get('id','')) if action=='edit' else None
            timer=parse_timer()

            items=read_attachments()
            holder={}

            if edit_id is not None and attachment_count(db,edit_id)+len(items)>MAX_ATTACHMENTS_PER_NOTICE:
                abort(400)

            def prepare():
                t=NOW()

                if action=='create':
                    holder['nid']=db.execute(
                        'INSERT INTO notices(title,content,created,updated,published,timer_until) VALUES(?,?,?,?,?,?)',
                        (title,content,t,t,published,timer)
                    ).lastrowid
                else:
                    if attachment_count(db,edit_id)+len(items)>MAX_ATTACHMENTS_PER_NOTICE:
                        abort(400)

                    cur=db.execute(
                        'UPDATE notices SET title=?,content=?,updated=?,published=?,timer_until=? WHERE id=?',
                        (title,content,t,published,timer,edit_id)
                    )

                    if cur.rowcount==0:
                        abort(404)

                    holder['nid']=edit_id

            try:
                store(db,items,C.attach_max,prepare,attachment_inserter(db,holder))
            except ValueError:
                abort(413)

            log.info('notice_created' if action=='create' else 'notice_updated')

        elif action=='delete':
            nid=parse_id(request.form.get('id',''))

            ids=[r['id'] for r in db.execute('SELECT id FROM attachments WHERE notice=?',(nid,))]

            cur=db.execute('DELETE FROM notices WHERE id=?',(nid,))

            if cur.rowcount==0:
                abort(404)

            db.commit()
            unlink_stored(ids)

            log.info('notice_deleted')

        elif action in ('censor','uncensor'):
            nid=parse_id(request.form.get('id',''))

            cur=db.execute(
                'UPDATE notices SET censored=? WHERE id=?',
                (1 if action=='censor' else 0,nid)
            )

            if cur.rowcount==0:
                abort(404)

            log.info('notice_censored' if action=='censor' else 'notice_uncensored')

        elif action=='rmatt':
            aid=request.form.get('aid','')

            if not valid_id(aid):
                abort(400)

            cur=db.execute('DELETE FROM attachments WHERE id=?',(aid,))

            if cur.rowcount==0:
                abort(404)

            db.commit()
            unlink_stored([aid])

            log.info('attachment_deleted')

        else:
            abort(400)

        return redirect(C.admin+'/posts',303)

    rows=[admin_notice(r) for r in db.execute(
        'SELECT * FROM notices ORDER BY created DESC, id DESC'
    )]

    atts={}
    for at in db.execute('SELECT * FROM attachments ORDER BY created'):
        atts.setdefault(at['notice'],[]).append(at)

    return page(
        """
        <h1 class="ttl">Posts</h1>

        <details class="card" open>
        <summary>＋ New notice</summary>
        <form method="post" enctype="multipart/form-data">
        """+CS+"""
        <input type="hidden" name="action" value="create">
        <label class="fld">Title<input name="title" maxlength="200" required></label>
        <label class="fld">Text<textarea name="content" maxlength="10000" rows="8" required></textarea></label>
        <label class="fld">Attachments (png, jpg, gif, webp, txt)
        <input type="file" name="att" multiple accept=".png,.jpg,.jpeg,.gif,.webp,.txt"></label>
        <label class="chk"><input type="checkbox" name="published" checked> Publish immediately</label>
        <label class="chk"><input type="checkbox" name="timer"> Show a countdown timer</label>
        <label class="fld">Timer ends (UTC, not your local time)
        <input type="datetime-local" name="timer_until"></label>
        <button class="btn pri">Create notice</button>
        </form>
        </details>

        <h2 class="sec">All notices</h2>

        {% for n in rows %}
        <details class="card">
        <summary><b>{{n.title}}</b>
        {% if not n.published %}<span class="pill">Draft</span>{% endif %}
        {% if n.censored %}<span class="pill bad">Hidden</span>{% endif %}
        <span class="pill{% if n.expired %} bad{% endif %}">{{n.timer_label}}</span></summary>

        <form method="post" enctype="multipart/form-data">
        """+CS+"""
        <input type="hidden" name="action" value="edit">
        <input type="hidden" name="id" value="{{n.id}}">
        <label class="fld">Title<input name="title" maxlength="200" value="{{n.title}}" required></label>
        <label class="fld">Text<textarea name="content" maxlength="10000" rows="8" required>{{n.content}}</textarea></label>
        <label class="fld">Add attachments
        <input type="file" name="att" multiple accept=".png,.jpg,.jpeg,.gif,.webp,.txt"></label>
        <label class="chk"><input type="checkbox" name="published" {% if n.published %}checked{% endif %}> Published</label>
        <label class="chk"><input type="checkbox" name="timer" {% if n.timer_until is not none %}checked{% endif %}> Show a countdown timer</label>
        <label class="fld">Timer ends (UTC, not your local time)
        <input type="datetime-local" name="timer_until" value="{{n.timer_val}}"></label>
        <button class="btn pri">Save changes</button>
        </form>

        {% for at in atts.get(n.id,[]) %}
        <form method="post" class="crow">
        """+CS+"""
        <input type="hidden" name="action" value="rmatt">
        <input type="hidden" name="aid" value="{{at.id}}">
        <span>
        {% if at.mime.startswith('image/') %}<img class="att" src="{{a}}/att/{{at.id}}" alt="{{at.name}}">{% endif %}
        <a href="{{a}}/att/{{at.id}}">{{at.name}}</a> <small>{{sz(at.size)}}</small></span>
        <button class="btn line sm">Remove</button>
        </form>
        {% endfor %}

        <div class="crow">
        <form method="post">
        """+CS+"""
        <input type="hidden" name="action" value="{% if n.censored %}uncensor{% else %}censor{% endif %}">
        <input type="hidden" name="id" value="{{n.id}}">
        <button class="btn line sm">{% if n.censored %}Restore{% else %}Hide content{% endif %}</button>
        </form>
        <form method="post">
        """+CS+"""
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="id" value="{{n.id}}">
        <button class="btn line sm">Delete notice</button>
        </form>
        </div>
        </details>
        {% else %}
        <p class="none">No notices yet.</p>
        {% endfor %}
        """,
        rows=rows,
        atts=atts,
        sz=fmt_size,
        a=C.admin
    )


@app.route(C.admin+'/downloads',methods=['GET','POST'])
def admin_files():
    db=database()

    if request.method=='POST':
        if request.form.get('del'):
            f=getfile(request.form.get('del',''))

            cur=db.execute(
                'DELETE FROM files WHERE id=?',
                (f['id'],)
            )

            if cur.rowcount==0:
                abort(404)

            db.commit()
            unlink_stored([f['id']])

            log.info('file_deleted')

        else:
            up=request.files.get('f')

            if not up or not up.filename:
                abort(400)

            name=safe_name(up.filename)
            descr=request.form.get('d','')[:300]

            def insert(fid,total,meta):
                db.execute(
                    'INSERT INTO files VALUES(?,?,?,?,?)',
                    (fid,meta['name'],total,descr,NOW())
                )

            try:
                store(db,[(up,{'name':name})],C.max_file,lambda:None,insert)
            except ValueError:
                abort(413)

            log.info('file_added')

    return page(
        "<h1 class=ttl>Files</h1>"
        "<p class=mute>Any file type is accepted. Never open uploads on a privileged machine.</p>"
        "<form method=post enctype=multipart/form-data class=card>"+CS+
        '<label class=fld>File<input type=file name=f required></label>'
        '<label class=fld>Description<input name=d maxlength=300></label>'
        '<button class="btn pri">Upload</button>'
        '</form>'
        "<div class=frows>"
        "{% for f in rows %}"
        "<form method=post class=frow2>"+CS+
        "<input type=hidden name=del value='{{f.id}}'>"
        "<span class=fm><b>{{f.name}}</b><small>{{sz(f.size)}}</small></span>"
        "<button class='btn line sm'>Delete</button>"
        "</form>"
        "{% else %}"
        "<p class=none>No files yet.</p>"
        "{% endfor %}"
        "</div>",
        rows=db.execute(
            'SELECT * FROM files ORDER BY created DESC'
        ).fetchall(),
        sz=fmt_size
    )


@app.route(C.admin+'/threads',methods=['GET','POST'])
def admin_convs():
    db=database()

    if request.method=='POST':
        cid=parse_id(request.form.get('del',''))

        cur=db.execute(
            'DELETE FROM convs WHERE id=?',
            (cid,)
        )

        if cur.rowcount==0:
            abort(404)

        db.commit()
        log.info('conversation_deleted')

    return page(
        "<h1 class=ttl>Threads</h1>"
        "<div class=frows>"
        "{% for c in rows %}"
        "<a class=frow href='{{a}}/threads/{{c.id}}'>"
        "<span class=fi>#{{c.id}}</span>"
        "<span class=fm><b>Thread #{{c.id}}</b><small>Updated {{dt(c.updated)}}</small></span>"
        "<span class='pill{% if c.status==\"open\" %} ok{% endif %}'>{{c.status}}</span></a>"
        "{% else %}"
        "<p class=none>No threads yet.</p>"
        "{% endfor %}"
        "</div>",
        rows=db.execute(
            'SELECT * FROM convs ORDER BY updated DESC'
        ).fetchall(),
        a=C.admin,
        dt=fmt_date
    )


def conv_or_404(db,cid):
    if not db.execute('SELECT 1 FROM convs WHERE id=?',(cid,)).fetchone():
        abort(404)


@app.route(C.admin+f'/threads/<int(max={SQLITE_MAX_INT}):cid>',methods=['GET','POST'])
def admin_conv(cid):
    db=database()
    conv_or_404(db,cid)

    if request.method=='POST':
        if request.form.get('del'):
            db.execute(
                'DELETE FROM convs WHERE id=?',
                (cid,)
            )
            return redirect(C.admin+'/threads',303)

        m=request.form.get('m','').strip()

        if not m or len(m)>4000:
            abort(400)

        db.execute(
            'INSERT INTO msgs(conv,sender,blob,created) VALUES(?,?,?,?)',
            (cid,'o',encrypt(cid,'o',m),NOW())
        )

        db.execute(
            "UPDATE convs SET updated=?,status='answered' WHERE id=?",
            (NOW(),cid)
        )

        return redirect(C.admin+f'/threads/{cid}',303)

    return page(
        "<a class=back href='{{a}}/threads'>← All threads</a>"
        "<h1 class=ttl>Thread #{{cid}}</h1>"
        "<form method=post class=composer>"+CS+
        "<textarea name=m maxlength=4000 rows=3 required placeholder='Write a reply…'></textarea>"
        "<div class=crow><span class=mute>Newest first · refreshes every few seconds</span>"
        "<button class='btn pri'>Reply</button></div></form>"
        "<iframe class=feedbox src='{{a}}/threads/{{cid}}/feed' title='Messages'></iframe>"
        "<form method=post>"+CS+
        "<input type=hidden name=del value=1>"
        "<button class='btn line'>Delete thread</button>"
        "</form>",
        cid=cid,
        a=C.admin
    )


@app.get(C.admin+f'/threads/<int(max={SQLITE_MAX_INT}):cid>/feed')
def admin_feed(cid):
    db=database()
    conv_or_404(db,cid)
    return feed_page(FEED_BODY,messages=thread(db,cid,'o'))


def initialize():
    ensure_private_dir(C.secret_dir)
    ensure_private_dir(C.data_dir)
    ensure_private_dir(C.files)

    for name,value in (
        ("session.key",secrets.token_bytes(32)),
        ("msg.key",secrets.token_hex(32))
    ):
        p=C.secret_dir/name

        if not p.exists():
            p.write_bytes(value) if isinstance(value,bytes) else p.write_text(value)
            p.chmod(0o600)

    with app.app_context():
        init_db()

    if C.db.exists():
        C.db.chmod(0o600)


def write_admin_hash(hashed):
    p=C.secret_dir/'admin.hash'
    tmp=C.secret_dir/'.admin.hash.tmp'
    tmp.unlink(missing_ok=True)
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)

    with os.fdopen(fd,'w') as out:
        out.write(hashed)

    os.replace(tmp,p)


def cli():
    parser=argparse.ArgumentParser()
    parser.add_argument(
        'command',
        choices=['init','setpass','check','purge','status','setup-tor']
    )

    args=parser.parse_args()

    if args.command=='init':
        initialize()
        print('initialized')
        return

    if args.command=='setpass':
        ensure_private_dir(C.secret_dir)

        pw=getpass.getpass('Admin password (14+ chars): ')
        confirm=getpass.getpass('Repeat: ')

        if (
            pw!=confirm
            or not 14<=len(pw)<=MAX_PASSWORD_LEN
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

    if args.command=='setup-tor':
        print('Install tor and run scripts/setup-tor.sh as root.')
        return

    with app.app_context():
        init_db()

        if args.command=='check':
            r=sweep_store(database())
            print(
                f"store: orphans={r['orphans']} stale_parts={r['stale_parts']} "
                f"missing={r['missing']} unexpected={r['unexpected']}"
            )
            print('checks passed')

        elif args.command=='status':
            print(
                f'database={C.db}\n'
                f'files={C.files}\n'
                f'quota={C.quota}'
            )

        elif args.command=='purge':
            db=database()

            if C.retention>0:
                db.execute(
                    'DELETE FROM convs WHERE updated<?',
                    (NOW()-C.retention,)
                )

            db.execute(
                'DELETE FROM sessions WHERE created<? OR last<?',
                (NOW()-28800,NOW()-900)
            )
            db.commit()

            r=sweep_store(db,delete=True)
            print(f"purged; removed orphans={r['orphans']} stale_parts={r['stale_parts']}; missing={r['missing']}")


def boot():
    C.validate()
    app.secret_key=secret('session.key')

    with app.app_context():
        init_db()

        try:
            sweep_store(database(),delete=True)
        except (OSError,sqlite3.Error):
            log.warning('sweep_failed')


if __name__=='__main__':
    if len(sys.argv)>1:
        cli()
    else:
        boot()
        app.run('127.0.0.1',8000)
else:
    boot()
