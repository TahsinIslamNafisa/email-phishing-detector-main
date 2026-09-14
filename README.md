# Email Phishing Detector (Multi-User)

A multi-user web app: each person registers, logs in, and connects their own
email inbox (Gmail app password, etc). The system then continuously scans
*only that user's* connected inbox(es) for phishing, in the background —
completely isolated from every other user's data.

## Features

- **Multi-user accounts**: register/login (hashed passwords), each user only
  ever sees their own scans, alerts, whitelist/blacklist, and connected inboxes
- **Bring-your-own-inbox**: users connect one or more email accounts (any
  IMAP provider) via the dashboard; app passwords are encrypted at rest
  (Fernet/AES via the `cryptography` package)
- **Background auto-scanning**: every connected account is scanned on a
  timer automatically, independent of anyone being logged in; there's also
  a "Scan now" button for on-demand checks
- **URL reputation checks** via VirusTotal (existing reports + new submissions)
- **Hidden link mismatch detection** (visible link text vs actual href)
- **Sender authenticity checks**: SPF / DKIM / DMARC verdicts (from Gmail's
  `Authentication-Results` header) + look-alike/typosquat domain detection
- **Attachment scanning**: dangerous file-type blacklist + VirusTotal
  file-hash lookup (no file content is uploaded, only its SHA256)
- **Keyword/heuristic scoring**: urgency language, credential-harvesting
  phrases, generic greetings, Reply-To/From mismatch, excessive links, shouting
- **Per-user whitelist / blacklist** management
- **Multi-channel alerts**: email (sent from the user's own connected
  account) + optional Telegram + optional Slack
- **Automatic quarantine** of confirmed phishing emails (IMAP folder move)
- **Web dashboard**: live stats, 14-day trend chart, searchable scan
  history, CSV export, account management, whitelist/blacklist management
- **Docker / Docker Compose** for easy deployment

## How multi-account works

1. A user registers and logs into the dashboard (their own username/password).
2. From the dashboard, they connect their real inbox: email address, IMAP
   app password, and IMAP server. This is stored encrypted, tied to their
   user ID.
3. A background thread (started when `dashboard.py` runs) loops through
   *every* connected account for *every* user, scans unread mail, and
   records results scoped to that account's owner.
4. Each user's dashboard only ever queries `WHERE user_id = <them>`, so
   users never see each other's data.
5. A user can also connect more than one inbox (e.g. work + personal) —
   each shows up as a separate row with its own "Scan now" button.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

Generate an encryption key and put it in `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Fill in `.env`: `VIRUSTOTAL_API_KEY`, `ENCRYPTION_KEY`, `FLASK_SECRET_KEY`,
and optionally `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` / `SLACK_WEBHOOK_URL`.

Run the dashboard (this also starts the background scanner automatically):

```bash
python dashboard.py
```

Open http://127.0.0.1:5000, register an account, then connect your inbox
from the dashboard.

### Headless / no-dashboard mode

`main.py` is a standalone CLI loop that scans every connected account
without running the web UI (useful for a server with no browser access).
Don't run `main.py` and `dashboard.py` at the same time — each already
scans every account on its own, so running both would scan everything
twice.

```bash
python main.py
```

## Docker

```bash
cp .env.example .env   # fill it in first, including ENCRYPTION_KEY
docker compose up --build dashboard
```

(The `detector` service in `docker-compose.yml` is the headless CLI
alternative — start it instead of, not in addition to, `dashboard`.)

## Configuration notes

- `config.py` reads everything from `.env` via `python-dotenv`.
- `PROTECTED_DOMAINS` and `DANGEROUS_ATTACHMENT_EXTENSIONS` in `config.py`
  control the look-alike-domain and attachment checks.
- `KEYWORD_SCORE_THRESHOLD` controls how aggressive the keyword scoring
  engine is at flagging an email as phishing on its own (default: 50/100).
- `CHECK_INTERVAL` (config.py) controls how often, in seconds, every
  connected account gets re-scanned.
- VirusTotal API key and Telegram/Slack webhooks are shared app-level
  settings (one key covers all users) since they're organization-level
  API credentials, not personal ones.

## Project structure

| File | Responsibility |
|---|---|
| `dashboard.py` | Flask web app: registration/login, account management, dashboard UI, background scanning thread |
| `main.py` | Headless CLI alternative: loops over every connected account without the web UI |
| `scanner.py` | Shared per-account scan routine + `evaluate_email()` (all detection layers combined) |
| `email_handler.py` | IMAP connection, fetching emails, attachments, headers |
| `phishing_detection.py` | URL extraction, hidden-link mismatch, VirusTotal URL checks |
| `attachment_scanner.py` | Dangerous file types + VirusTotal file-hash lookups |
| `domain_analysis.py` | SPF/DKIM/DMARC parsing + look-alike domain detection |
| `keyword_scoring.py` | Social-engineering language scoring |
| `crypto_utils.py` | Encrypts/decrypts stored IMAP app-passwords |
| `database.py` | SQLite storage: users, email_accounts, scan history, flagged emails, whitelist/blacklist — all scoped per user |
| `alert.py` / `notifications.py` | Email / Telegram / Slack alerting |
| `quarantine.py` | Moves confirmed phishing emails to a Quarantine IMAP folder |
| `config.py` | Loads all settings/secrets from `.env` |

## Known limitations / next steps

- SPF/DKIM/DMARC parsing relies on the mail provider's own
  `Authentication-Results` header rather than independent DNS lookups —
  fine for Gmail-hosted inboxes, less reliable for arbitrary IMAP servers.
- Background scanning runs sequentially through all accounts; at real
  scale (many users) this should move to a task queue (Celery/RQ) with
  per-account workers instead of one Python thread.
- The dashboard's session auth is basic (username/password + Flask
  session cookie) — fine for personal/small-team use; add rate-limiting,
  password reset, and 2FA before exposing this to the public internet.
- Each user must currently generate their own IMAP "app password" — OAuth
  (Google/Microsoft sign-in) would be a friendlier long-term replacement.
