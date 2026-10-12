<h1 align="center">◈ Tiny Desk</h1>
<p align="center">
  <b>Minimal, JavaScript-free notice board and anonymous message desk for Tor onion services.</b><br>
  Flask · SQLite · AES-256-GCM · one file
</p>
<p align="center">
  <a href="https://sheikhlipu123.github.io/tinydesk/">Website</a> ·
  <a href="#setup">Setup</a> ·
  <a href="#security-notes">Security</a>
</p>
<p align="center">
  <img src="https://img.shields.io/github/stars/Sheikhlipu123/tinydesk?style=social" alt="GitHub stars">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license">
  <img src="https://img.shields.io/badge/no-JavaScript-orange" alt="No JavaScript">
</p>

## Features

- **Notices:** public posts with image or `.txt` attachments (up to 10 per upload, 50 per notice), optional countdown timers (set in UTC), draft and hide controls
- **Downloads:** operator-uploaded files of any type, served as attachments
- **Anonymous messaging:** visitors write a message and get a Ticket and Key. No account, e-mail or name. Messages are stored AES-256-GCM encrypted. A "New reply" marker shows when the operator has answered
- **Thread deletion:** anyone with the Ticket and Key can permanently delete their thread at `/burn`
- **Pause switch:** the operator can pause new threads from the dashboard while existing threads keep working
- **No JavaScript:** server-rendered pages. Message threads refresh through a meta-refresh iframe
- **Hardening:** strict CSP, CSRF tokens on every POST, Argon2 admin password, short-lived admin sessions, request size limits, rate limits, strict permission checks on secrets and data directories, admin prefix requirement, magic-byte checks on attachments
- **Housekeeping:** storage quotas, retention-based purge, orphan file sweep, SHA-256 verification of stored files

## Requirements

- Python 3.10+
- A non-root user (the app refuses to run as root)
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

`init` creates the private directories, the session and message keys, and the database. `setpass` asks for the admin password (14+ characters with upper case, lower case and a digit) and revokes all admin sessions.

`ADMIN_PREFIX` is required and has no default. It must be at least 10 characters, using only letters, digits, `_` and `-` (segments separated by `/` are allowed), and must not start with a public path name such as `downloads` or `contact`. The admin login is at `/<ADMIN_PREFIX>/signin`.

The app checks ownership and permissions at startup. The secrets and data directories must belong to the running user and not be accessible to others, otherwise it refuses to start.

Keep the same environment variables set for every command and for the service.

## Admin area

Sign in at `/<ADMIN_PREFIX>/signin`. Sessions end after 15 minutes of inactivity or 8 hours in total.

| Page | Purpose |
|---|---|
| Overview | Storage use, thread counts, pause or resume new threads |
| Posts | Create, edit, hide, delete notices. Manage attachments and timers |
| Files | Upload or delete downloads |
| Threads | Read and answer messages, delete threads |

## Deployment notes

Run exactly one Gunicorn process with threads, so one slow or stalled client cannot block everyone else while the in-memory limits stay in one place:

```
export ONION_WORKERS=1

gunicorn -w 1 --worker-class gthread --threads 16 --timeout 60 \
         --graceful-timeout 15 --keep-alive 5 --limit-request-line 2048 \
         --limit-request-fields 50 -b 127.0.0.1:8000 app:app
```

Do not enable Gunicorn access logging. Set `ONION_WORKERS` to the process count so the app can warn you if it is wrong.

Tor-side DoS defenses, in the `HiddenServiceDir` block of `torrc` (proof-of-work needs Tor 0.4.8+ built with it; tune the numbers):

```
HiddenServicePoWDefensesEnabled 1
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceEnableIntroDoSRatePerSec 25
HiddenServiceEnableIntroDoSBurstPerSec 200
```

Schedule the maintenance commands with a systemd timer or cron: `purge` daily and `check` regularly.

## Run

Development, listening on `127.0.0.1:8000`:

```
export COOKIE_SECURE=0
python app.py
```

For production, use the Gunicorn command above.

## Tor

Add this to `torrc`, then restart Tor and read your address from the `hostname` file in the service directory:

```
HiddenServiceDir /var/lib/tor/tinydesk/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8000
```

`COOKIE_SECURE` defaults to `1`. When serving plain HTTP, such as an onion address without HTTPS or local testing, set `COOKIE_SECURE=0`, otherwise browsers may drop the session cookie and you cannot stay signed in.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ONION_SECRETS` | `/etc/onionsite` | Directory for `session.key`, `msg.key`, `admin.hash` |
| `ONION_DATA` | `/var/lib/onionsite` | Database and uploaded files |
| `ADMIN_PREFIX` | none (required) | URL prefix of the admin area, 10+ characters. The app will not start without it |
| `OWNER_NOTE` | built-in text | Text on the home page |
| `MAX_FILE_MB` | `25` | Largest upload. Must not exceed `QUOTA_MB` |
| `ATTACH_MB` | `8` | Largest notice attachment |
| `QUOTA_MB` | `500` | Total space for files and attachments |
| `CONV_QUOTA_MB` | `200` | Total space for messages |
| `RETENTION_DAYS` | `30` | Delete threads idle this long on `purge`. `0` keeps everything |
| `COOKIE_SECURE` | `1` | Set `0` only when serving plain HTTP |
| `ONION_WORKERS` | `1` | Number of server processes, used to warn about per-process rate limits |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Commands

```
python app.py init       create keys, directories and database
python app.py setpass    set or change the admin password
python app.py check      report orphaned, stale or missing files and verify SHA-256 hashes
python app.py purge      delete old threads, expired sessions and orphans
python app.py status     print database path, file path and quota
```

`check` exits with an error if a file is missing or a hash does not match, so it works well in cron or monitoring. `purge` also scrubs the database write-ahead log after deleting threads.

## Public pages

| Path | Purpose |
|---|---|
| `/` | Notices |
| `/downloads` | File list |
| `/contact` | How messaging works |
| `/contact/start` | Write a first message |
| `/resume` | Return with a Ticket and Key |
| `/thread` | Your open thread |
| `/burn` | Permanently delete a thread |

## Limits

- Messages: up to 4000 characters
- Threads: up to 300 visitor messages and 512 KB of visitor text, with per-minute and per-hour send limits
- New threads: limited per browser session and globally per hour
- A thread stays open in a browser for 4 hours, then needs the Ticket and Key again
- Global ceilings apply to new threads, sends, failed logins and inbound data

## Security notes

- Tor protects the transport. Messages are encrypted at rest, but the operator can read them. This is not end-to-end encryption.
- A Ticket and Key cannot be recovered or reset. Anyone holding both can read and write in that thread, or delete it.
- Deleting a thread removes it from the server, but cannot undo anything the operator already read or copied.
- The app never identifies clients, so rate limits are flood ceilings, not per-user protection. Per-session limits depend on cookies and are easy to bypass. Admin security rests on Argon2 and a strong password.
- Uploaded downloads can be any file type. Never open or run them on a privileged machine.
- Back up `ONION_SECRETS`. Losing `msg.key` makes stored messages unreadable.
- Do not commit anything from your secrets or data directories.
