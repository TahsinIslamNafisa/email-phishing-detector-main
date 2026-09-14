import sqlite3
import csv
import io
from datetime import datetime

from config import DATABASE_NAME


def get_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            label TEXT,
            email_address TEXT,
            imap_server TEXT,
            encrypted_password TEXT,
            alert_email TEXT,
            is_active INTEGER DEFAULT 1,
            last_scanned_at TEXT,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            account_email TEXT,
            sender TEXT,
            subject TEXT,
            result TEXT,
            score INTEGER DEFAULT 0,
            reasons TEXT,
            scanned_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flagged_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            account_email TEXT,
            sender TEXT,
            subject TEXT,
            body TEXT,
            detected_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allow_block_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            entry TEXT,
            list_type TEXT,   -- 'whitelist' or 'blacklist'
            added_at TEXT,
            UNIQUE(user_id, entry)
        )
    """)

    conn.commit()

    # ------------------------------------------------------------
    # Lightweight migration: older databases (from earlier single-
    # user versions of this tool) won't have the new multi-user
    # columns yet. Add them in place instead of losing existing data.
    # ------------------------------------------------------------

    def _ensure_column(table, column, coltype):
        existing_cols = [row[1] for row in cursor.execute(f"PRAGMA table_info({table})")]
        if column not in existing_cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

    _ensure_column("scan_history", "user_id", "INTEGER")
    _ensure_column("scan_history", "account_email", "TEXT")
    _ensure_column("scan_history", "score", "INTEGER DEFAULT 0")
    _ensure_column("scan_history", "reasons", "TEXT")

    _ensure_column("flagged_emails", "user_id", "INTEGER")
    _ensure_column("flagged_emails", "account_email", "TEXT")

    _ensure_column("allow_block_list", "user_id", "INTEGER")

    conn.commit()
    conn.close()

def create_user(username, password_hash):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        """, (username, password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row


# ============================
# Email accounts (each user can connect one or more inboxes)
# ============================

def add_email_account(user_id, label, email_address, imap_server, encrypted_password, alert_email):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO email_accounts
        (user_id, label, email_address, imap_server, encrypted_password, alert_email, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        user_id, label, email_address, imap_server, encrypted_password, alert_email,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    account_id = cursor.lastrowid
    conn.close()
    return account_id


def get_accounts_for_user(user_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, label, email_address, imap_server, alert_email, is_active, last_scanned_at
        FROM email_accounts WHERE user_id = ? ORDER BY id DESC
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_active_accounts():
    """
    Used by the background scanner: returns every active account across
    every user, with its encrypted password (for decryption+IMAP login).
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, email_address, imap_server, encrypted_password, alert_email
        FROM email_accounts WHERE is_active = 1
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_account_by_id(account_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, email_address, imap_server, encrypted_password, alert_email
        FROM email_accounts WHERE id = ?
    """, (account_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def remove_email_account(account_id, user_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM email_accounts WHERE id = ? AND user_id = ?", (account_id, user_id))
    conn.commit()
    conn.close()


def mark_account_scanned(account_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE email_accounts SET last_scanned_at = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), account_id),
    )
    conn.commit()
    conn.close()


# ============================
# Scan history / flagged emails (scoped per user)
# ============================

def record_scan(user_id, account_email, email_data, result, score=0, reasons=None):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history
        (user_id, account_email, sender, subject, result, score, reasons, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        account_email,
        email_data.get("from", ""),
        email_data.get("subject", ""),
        result,
        score,
        "; ".join(reasons) if reasons else "",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    conn.close()


def record_phishing_email(user_id, account_email, email_data):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO flagged_emails
        (user_id, account_email, sender, subject, body, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        account_email,
        email_data.get("from", ""),
        email_data.get("subject", ""),
        email_data.get("body", ""),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    conn.close()


def get_statistics(user_id):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,))
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND result = 'SAFE'", (user_id,))
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND result = 'PHISHING'", (user_id,))
    phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM flagged_emails WHERE user_id = ?", (user_id,))
    flagged = cursor.fetchone()[0]

    conn.close()

    detection_rate = round((phishing / total) * 100, 2) if total > 0 else 0

    return {
        "total_scanned": total,
        "safe_emails": safe,
        "phishing_emails": phishing,
        "flagged_count": flagged,
        "detection_rate": detection_rate,
    }


def get_daily_trend(user_id, days=14):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT substr(scanned_at, 1, 10) AS day, result, COUNT(*)
        FROM scan_history
        WHERE user_id = ?
        GROUP BY day, result
        ORDER BY day DESC
        LIMIT 200
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()

    trend = {}
    for day, result, count in rows:
        trend.setdefault(day, {"date": day, "safe": 0, "phishing": 0})
        if result == "SAFE":
            trend[day]["safe"] = count
        elif result == "PHISHING":
            trend[day]["phishing"] = count

    return sorted(trend.values(), key=lambda r: r["date"])[-days:]


def get_recent_scans(user_id, limit=50, search=None):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    if search:
        like = f"%{search}%"
        cursor.execute("""
            SELECT id, account_email, sender, subject, result, score, scanned_at
            FROM scan_history
            WHERE user_id = ? AND (sender LIKE ? OR subject LIKE ? OR result LIKE ? OR account_email LIKE ?)
            ORDER BY id DESC LIMIT ?
        """, (user_id, like, like, like, like, limit))
    else:
        cursor.execute("""
            SELECT id, account_email, sender, subject, result, score, scanned_at
            FROM scan_history
            WHERE user_id = ?
            ORDER BY id DESC LIMIT ?
        """, (user_id, limit))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_phishing_emails(user_id, limit=50):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, account_email, sender, subject, detected_at
        FROM flagged_emails
        WHERE user_id = ?
        ORDER BY id DESC LIMIT ?
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def export_scans_csv(user_id, limit=1000):
    rows = get_recent_scans(user_id, limit=limit)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "account_email", "sender", "subject", "result", "score", "scanned_at"])
    writer.writerows(rows)
    return buffer.getvalue()


# ============================
# Whitelist / Blacklist (scoped per user)
# ============================

def add_to_list(user_id, entry, list_type):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO allow_block_list (user_id, entry, list_type, added_at)
        VALUES (?, ?, ?, ?)
    """, (
        user_id,
        entry.strip().lower(),
        list_type,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    conn.close()


def remove_from_list(user_id, entry):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM allow_block_list WHERE user_id = ? AND entry = ?", (user_id, entry.strip().lower()))
    conn.commit()
    conn.close()


def get_list(user_id, list_type):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT entry, added_at FROM allow_block_list WHERE user_id = ? AND list_type = ? ORDER BY added_at DESC",
        (user_id, list_type),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def check_sender_against_lists(user_id, sender_email_or_domain):
    initialize_database()
    sender = (sender_email_or_domain or "").lower()
    domain = sender.split("@")[-1] if "@" in sender else sender

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT entry, list_type FROM allow_block_list WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()

    for entry, list_type in rows:
        if entry == sender or entry == domain:
            return list_type
    return None
