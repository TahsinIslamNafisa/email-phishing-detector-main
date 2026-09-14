import os
import threading
import time
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, jsonify, request, Response, redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import (
    initialize_database,
    create_user, get_user_by_username, get_user_by_id,
    add_email_account, get_accounts_for_user, get_account_by_id, remove_email_account,
    get_all_active_accounts,
    get_statistics, get_recent_scans, get_phishing_emails, get_daily_trend,
    export_scans_csv, get_list, add_to_list, remove_from_list,
)
from crypto_utils import encrypt
from scanner import scan_account
from config import DEFAULT_IMAP_SERVER, CHECK_INTERVAL

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")


# ============================
# Auth helpers
# ============================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        # Guard against stale sessions pointing at a user_id that no
        # longer exists (e.g. the database was reset/replaced while a
        # browser still had an old session cookie) - this used to crash
        # downstream with a FOREIGN KEY constraint error instead.
        if not get_user_by_id(user_id):
            session.clear()
            flash("Your session was no longer valid. Please log in again.")
            return redirect(url_for("login"))

        return view(*args, **kwargs)
    return wrapped


def current_user_id():
    return session.get("user_id")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username and password are required."
        else:
            user_id = create_user(username, generate_password_hash(password))
            if user_id is None:
                error = "That username is already taken."
            else:
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("dashboard"))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = get_user_by_username(username)
        if row and check_password_hash(row[2], password):
            session["user_id"] = row[0]
            session["username"] = row[1]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================
# Dashboard
# ============================

@app.route("/")
@login_required
def dashboard():
    user_id = current_user_id()
    search = request.args.get("q", "").strip() or None

    stats = get_statistics(user_id)
    recent_scans = get_recent_scans(user_id, 50, search=search)
    phishing_emails = get_phishing_emails(user_id, 20)
    trend = get_daily_trend(user_id, 14)
    whitelist = get_list(user_id, "whitelist")
    blacklist = get_list(user_id, "blacklist")
    accounts = get_accounts_for_user(user_id)

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        stats=stats,
        recent_scans=recent_scans,
        phishing_emails=phishing_emails,
        trend=trend,
        whitelist=whitelist,
        blacklist=blacklist,
        search=search or "",
        accounts=accounts,
        default_imap_server=DEFAULT_IMAP_SERVER,
        check_interval=CHECK_INTERVAL,
    )


@app.route("/api/statistics")
@login_required
def api_statistics():
    return jsonify(get_statistics(current_user_id()))


@app.route("/api/trend")
@login_required
def api_trend():
    return jsonify(get_daily_trend(current_user_id(), 14))


@app.route("/export/csv")
@login_required
def export_csv():
    csv_data = export_scans_csv(current_user_id(), 1000)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_history.csv"},
    )


# ============================
# Connected email accounts (this is the "multi-account" part:
# each logged-in user connects and manages their own inbox/inboxes)
# ============================

@app.route("/accounts/add", methods=["POST"])
@login_required
def accounts_add():
    user_id = current_user_id()

    label = request.form.get("label", "").strip() or "My Inbox"
    email_address = request.form.get("email_address", "").strip()
    app_password = request.form.get("app_password", "")
    imap_server = request.form.get("imap_server", "").strip() or DEFAULT_IMAP_SERVER
    alert_email = request.form.get("alert_email", "").strip() or email_address

    if email_address and app_password:
        try:
            add_email_account(
                user_id, label, email_address, imap_server,
                encrypt(app_password), alert_email,
            )
            flash("Email account connected.")
        except sqlite3.IntegrityError:
            session.clear()
            flash("Your session was no longer valid. Please log in again and retry.")
            return redirect(url_for("login"))
    else:
        flash("Email and app password are required.")

    return redirect(url_for("dashboard"))


@app.route("/accounts/remove", methods=["POST"])
@login_required
def accounts_remove():
    account_id = request.form.get("account_id")
    if account_id:
        remove_email_account(int(account_id), current_user_id())
    return redirect(url_for("dashboard"))


@app.route("/accounts/scan_now", methods=["POST"])
@login_required
def accounts_scan_now():
    account_id = request.form.get("account_id")
    user_id = current_user_id()

    account_row = get_account_by_id(int(account_id)) if account_id else None

    if not account_row or account_row[1] != user_id:
        flash("Account not found.")
        return redirect(url_for("dashboard"))

    summary = scan_account(account_row)

    if summary["error"]:
        flash(f"Scan failed: {summary['error']}")
    else:
        flash(f"Scan complete: {summary['scanned']} email(s) checked, "
              f"{summary['phishing']} flagged as phishing.")

    return redirect(url_for("dashboard"))


# ============================
# Whitelist / Blacklist (scoped per user)
# ============================

@app.route("/lists/add", methods=["POST"])
@login_required
def lists_add():
    user_id = current_user_id()
    entry = request.form.get("entry", "").strip()
    list_type = request.form.get("list_type", "")
    if entry and list_type in ("whitelist", "blacklist"):
        add_to_list(user_id, entry, list_type)
    return redirect(url_for("dashboard"))


@app.route("/lists/remove", methods=["POST"])
@login_required
def lists_remove():
    entry = request.form.get("entry", "").strip()
    if entry:
        remove_from_list(current_user_id(), entry)
    return redirect(url_for("dashboard"))


# ============================
# Background scanning thread:
# periodically scans EVERY connected account for EVERY user,
# independent of anyone being logged into the dashboard right now.
# ============================

def background_scan_loop():
    while True:
        try:
            for account in get_all_active_accounts():
                scan_account(account)
        except Exception as e:
            print("❌ Background scan loop error:", e)
        time.sleep(CHECK_INTERVAL)


def start_background_scanner():
    thread = threading.Thread(target=background_scan_loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    initialize_database()

    print("=" * 60)
    print("PHISHING EMAIL DETECTOR DASHBOARD (multi-user)")
    print("=" * 60)
    print("Open: http://127.0.0.1:5000")
    print(f"Background scanner running every {CHECK_INTERVAL} seconds.")

    start_background_scanner()

    app.run(host="127.0.0.1", port=5000, debug=False)
