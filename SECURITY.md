# Security Policy

Tiny Desk handles anonymous messages and admin credentials, so security reports are taken seriously. Thank you for helping keep it and its users safe.

## Supported versions

Only the latest release on the `main` branch receives security fixes.

| Version        | Supported          |
| -------------- | ------------------ |
| `main` (latest) | :white_check_mark: |
| Older releases  | :x:                |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security problem.** Public reports can expose operators and visitors before a fix exists.

Report privately using one of these methods:

1. **GitHub private vulnerability reporting (preferred).** Go to the repository's **Security** tab and choose **Report a vulnerability**.
2. **Contact the maintainer directly** through the GitHub profile at https://github.com/Sheikhlipu123 if private reporting is unavailable.

Please include:

- A description of the issue and its impact
- Steps to reproduce, with the smallest example you can make
- The affected version or commit hash
- The configuration involved (for example, `COOKIE_SECURE`, `ADMIN_PREFIX`, or reverse proxy setup), with any secrets removed
- Whether you have already shared the details with anyone else

Do not include real Ticket and Key pairs, `msg.key`, `session.key`, `admin.hash`, or any real visitor messages in a report. If you need to show a message was read or altered, use test data you created.

## What to expect

- **Acknowledgement:** within 7 days of your report.
- **Assessment:** we will confirm whether the issue is valid and how severe it is, and keep you updated.
- **Fix and disclosure:** we aim to release a fix within 90 days. We will agree a disclosure date with you and credit you in the release notes if you wish.

If a report is declined, we will explain why.

## Scope

In scope:

- Authentication and session handling for the admin area
- CSRF, XSS, injection, and Content-Security-Policy bypasses
- Encryption of stored messages and the handling of key files
- File upload, download, and attachment validation, including bypasses of the magic-byte checks
- Path traversal or access to files outside the data directory
- Privilege or permission issues, such as the app running as root or unsafe file permissions
- Denial of service that a single client can trigger, and bypasses of the rate limits

Out of scope:

- Issues that require access to the server, the secrets directory, or the database that the operator already controls
- The operator reading messages. This is documented: messages are encrypted at rest, not end-to-end encrypted
- Loss of a Ticket and Key pair, which cannot be recovered by design
- Malicious files that the operator chose to upload. Downloads can be any file type, and the README warns against opening them on privileged machines
- Missing rate limits as a per-user protection. The app identifies no clients, so its limits are global flood ceilings
- Findings from automated scanners with no demonstrated impact
- Problems in Tor, Flask, Python, or other dependencies. Report those upstream, and tell us if the issue affects Tiny Desk specifically


## Hardening guidance for operators

- Run as a dedicated non-root user, and keep `ONION_SECRETS` and `ONION_DATA` readable only by that user.
- Back up `ONION_SECRETS`. Losing `msg.key` makes stored messages unreadable.
- Use a long, random `ADMIN_PREFIX`.
- Keep Python dependencies up to date, and run `gunicorn` as shown in the README rather than the development server.
- Run `purge` regularly so old threads are deleted.
