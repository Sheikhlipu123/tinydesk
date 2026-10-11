<h1 align="center">◈ Tiny Desk</h1>
<p align="center">
  <b>Minimal, JavaScript-free notice board and anonymous message desk for Tor onion services.</b><br>
  Flask · SQLite · AES-256-GCM · one file
</p>
<p align="center">
  <a href="https://sheikhlipu123.github.io/tinydesk/">Website</a> ·
  <a href="#install">Install</a> ·
  <a href="#security-notes">Security</a>
</p>
<p align="center">
  <img src="https://img.shields.io/github/stars/Sheikhlipu123/tinydesk?style=social" alt="GitHub stars">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license">
  <img src="https://img.shields.io/badge/no-JavaScript-orange" alt="No JavaScript">
</p>

## Features

- **Notices:** public posts with image or `.txt` attachments, optional countdown timers, draft and hide controls
- **Downloads:** operator-uploaded files of any type, served as attachments
- **Anonymous messaging:** visitors write a message and get a Ticket and Key. No account, e-mail or name. Messages are stored AES-256-GCM encrypted
- **No JavaScript:** server-rendered pages. Message threads refresh through a meta-refresh iframe
- **Hardening:** strict CSP, CSRF tokens on every POST, Argon2 admin password, short-lived admin sessions, request size limits, rate limits, strict permission checks on secrets and data directories, magic-byte checks on attachments
- **Housekeeping:** storage quotas, retention-based purge, orphan file sweep

## Requirements

- Python 3.10+
- A non-root user
- Tor, to publish it as an onion service

```
pip install -r requirements.txt
```

## Setup

Pick your own directories and a hard-to-guess admin prefix:

```
export ONION_SECRETS=/etc/tinydesk
export ONION_DATA=/var/lib/tinydesk
export ADMIN_PREFIX=$(python3 -c "import secrets;print(secrets.token_hex(8))")

python app.py init
python app.py setpass
python app.py status
```

`init` creates the private directories, the session and message keys, and the database. `setpass` asks for the admin password (14+ characters with upper case, lower case and a digit) and revokes existing admin sessions. Both `ONION_SECRETS` and `ONION_DATA` must be owned by the running user with no group or other access, and the app refuses to start as root.

The admin login is at `/<ADMIN_PREFIX>/signin`. The prefix must be at least 9 characters, using only letters, digits, `_` and `-`.

## Run

Development:

```
python app.py
```

This listens on `127.0.0.1:8000`.

Production, with a single worker because the rate limiter lives in memory:

```
gunicorn -w 1 --threads 4 -b 127.0.0.1:8000 --access-logfile /dev/null app:app
```

Keep the same environment variables set for the service.

## Tor

Add this to `torrc`, then restart Tor and read your address from the `hostname` file in the service directory:

```
HiddenServiceDir /var/lib/tor/tinydesk/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8000
```

Leave `COOKIE_SECURE=0` when serving over plain HTTP on an onion address.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ONION_SECRETS` | `/etc/onionsite` | Directory for `session.key`, `msg.key`, `admin.hash` |
| `ONION_DATA` | `/var/lib/onionsite` | Database and uploaded files |
| `ADMIN_PREFIX` | `admin` | URL prefix of the admin area. Set your own, as the default is too short and rejected |
| `OWNER_NOTE` | built-in text | Text on the home page |
| `MAX_FILE_MB` | `25` | Largest upload |
| `ATTACH_MB` | `8` | Largest notice attachment |
| `QUOTA_MB` | `500` | Total space for files and attachments |
| `CONV_QUOTA_MB` | `200` | Total space for messages |
| `RETENTION_DAYS` | `30` | Delete threads idle this long on `purge`. `0` keeps everything |
| `COOKIE_SECURE` | `0` | Set `1` only behind HTTPS |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Commands

```
python app.py init       create keys, directories and database
python app.py setpass    set or change the admin password
python app.py check      report orphaned, stale or missing files
python app.py purge      delete old threads and sessions, sweep orphans
python app.py status     print database path, file path and quota
```

Run `purge` regularly, for example from cron.

## Public pages

| Path | Purpose |
|---|---|
| `/` | Notices |
| `/downloads` | File list |
| `/contact` | How messaging works |
| `/contact/start` | Write a first message |
| `/resume` | Return with a Ticket and Key |
| `/thread` | Your open thread |

## Security notes

- Tor protects the transport. Messages are encrypted at rest, but the operator can read them. This is not end-to-end encryption.
- A Ticket and Key cannot be recovered or reset. Anyone holding both can read and write in that thread.
- The app never identifies clients, so rate limits are global flood ceilings, not per-user protection. Admin security rests on Argon2 and a strong password.
- Uploaded downloads can be any file type. Never open or run them on a privileged machine.
- Back up `ONION_SECRETS`. Losing `msg.key` makes stored messages unreadable.
- Do not commit anything from your secrets or data directories.
