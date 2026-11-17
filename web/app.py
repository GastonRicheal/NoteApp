"""NotesApp - a small grades application.

Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""
import os
import csv
import io
import json
import hmac
import time
import base64
import re
import subprocess
from pathlib import Path

import psycopg2
import psycopg2.extras
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from comment_crypto import CommentDecryptionError, load_comment_cipher
from export_integrity import (
    ExportSizeError, ExportVerificationError, MAX_EXPORT_BYTES, load_export_hmac,
)
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, Response, jsonify, abort,
)

# --- Configuration ------------------------------------------------------------
# All configuration comes from the environment (set in docker-compose.yml).
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")


def load_jwt_key():
    """Load a provisioned 256-bit key; never start with a default secret."""
    try:
        encoded = os.environ.get("JWT_SECRET")
        if encoded is None:
            encoded = Path(os.environ["JWT_SECRET_FILE"]).read_text(encoding="ascii").strip()
        key = base64.b64decode(encoded, validate=True)
    except (KeyError, OSError, ValueError):
        raise RuntimeError("Provision JWT_SECRET or JWT_SECRET_FILE before starting NotesApp.") from None
    if len(key) != 32:
        raise RuntimeError("The JWT signing key must be 32 random bytes encoded as Base64.")
    return key


JWT_KEY = load_jwt_key()
comment_cipher = load_comment_cipher()
export_hmac = load_export_hmac()

app = Flask(__name__)
ph = PasswordHasher()
# Flask cookies can also authenticate API calls. Use a distinct signing key
# derived from the provisioned secret rather than a public cookie key.
app.secret_key = hmac.digest(JWT_KEY, b"NotesApp Flask session key v1", "sha256")


def is_argon2_hash(value: str) -> bool:
    return value.startswith("$argon2")


LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")


def log(msg):
    """Very small access log. No rotation, no policy (see flaw #14)."""
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


# --- Database -----------------------------------------------------------------
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = True
    return conn


def decrypt_note_comment(note):
    note["comment"] = comment_cipher.decrypt(note["comment"], note["id"])
    return note


@app.errorhandler(CommentDecryptionError)
def comment_decryption_failed(error):
    # Fail closed without exposing ciphertext, keys or partially decoded comments.
    log("comment authentication failed")
    return jsonify({"error": "Comment data could not be decrypted."}), 500


# --- HS256 JWT ----------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, altchars=b"-_", validate=True)


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.digest(JWT_KEY, signing_input, "sha256")
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(token: str):
    """Accept only HS256 tokens authenticated by the configured signing key."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(h_b64))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        expected = _b64url(hmac.digest(JWT_KEY, signing_input, "sha256")).encode("ascii")
        if not hmac.compare_digest(expected, sig_b64.encode("ascii")):
            return None
        payload = json.loads(_b64url_decode(p_b64))
    except (ValueError, RecursionError):
        return None
    return payload if valid_identity(payload) else None


def valid_identity(identity):
    if not isinstance(identity, dict):
        return False
    user_id = identity.get("user_id")
    return (type(user_id) is int and user_id > 0
            and identity.get("role") in ("student", "teacher", "admin"))


def current_identity():
    """Return the acting identity from a Bearer JWT if present, else the session."""
    auth = request.headers.get("Authorization")
    if auth is not None:
        scheme, _, token = auth.partition(" ")
        return verify_jwt(token.strip()) if scheme.lower() == "bearer" else None
    identity = {"user_id": session.get("user_id"), "username": session.get("username"),
                "role": session.get("role")}
    return identity if valid_identity(identity) else None


# --- Auth helpers -------------------------------------------------------------
def login_required(role=None):
    if "user_id" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session.get("role")
        if role == "student":
            return redirect(url_for("dashboard"))
        if role == "teacher":
            return redirect(url_for("teacher"))
        if role == "admin":
            return redirect(url_for("admin"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Flaw #8 fixed: the username is a bound parameter, never SQL grammar.
        # The password is checked below in Python (Argon2id aware), so a row
        # returned by the database is never on its own enough to authenticate.
        query = "SELECT id, username, role, password FROM users WHERE username = %s"
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query, (username,))
            row = cur.fetchone()
        except Exception as e:
            # Keep the raw error visible - helps the SQLi session.
            error = f"Query error: {e}"
            row = None
        authenticated = False
        if row:
            stored = row["password"]
            if is_argon2_hash(stored):
                try:
                    ph.verify(stored, password)
                    authenticated = True
                except (VerifyMismatchError, InvalidHash):
                    authenticated = False
            else:
                if stored == password:
                    authenticated = True
                    new_hash = ph.hash(password)
                    conn.cursor().execute(
                        "UPDATE users SET password = %s WHERE id = %s",
                        (new_hash, row["id"]),
                    )
                    log(f"upgraded {row['username']} to argon2")
        conn.close()
        if authenticated:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            # Issue the signed JWT the dashboard uses to call the API.
            session["token"] = make_jwt({
                "user_id": row["id"], "username": row["username"], "role": row["role"],
            })
            log(f"login success user={row['username']} role={row['role']}")
            return redirect(url_for("index"))
        if not error:
            error = "Invalid credentials."
        log(f"login failure username={username!r}")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, c.name AS class_name "
        "FROM notes n JOIN classes c ON c.id = n.class_id "
        "WHERE n.student_id = %s ORDER BY c.name",
        (session["user_id"],),
    )
    notes = cur.fetchall()
    conn.close()
    notes = [decrypt_note_comment(note) for note in notes]
    return render_template("dashboard.html", notes=notes, token=session.get("token"))


@app.route("/api/notes/<int:note_id>")
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    # Filter by ownership before returning or decrypting any student data.
    cur.execute(
        "SELECT n.id, n.student_id, n.class_id, n.grade, n.comment, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id WHERE n.id = %s "
        "AND (%s IN ('teacher', 'admin') OR n.student_id = %s)",
        (note_id, ident["role"], ident["user_id"]),
    )
    note = cur.fetchone()
    conn.close()
    if not note:
        return jsonify({"error": "not found"}), 404
    decrypt_note_comment(note)
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    return jsonify(note)


@app.route("/teacher")
def teacher():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    # A teacher sees every class (no owner scoping - broken access control).
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY name")
    classes = cur.fetchall()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, n.student_id, n.class_id, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
    )
    notes = cur.fetchall()
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    notes = [decrypt_note_comment(note) for note in notes]
    return render_template("teacher.html", classes=classes, notes=notes, students=students)


@app.route("/grades", methods=["POST"])
def grades():
    # Flaw #11: no CSRF token checked on this state-changing POST.
    if not login_required("teacher"):
        return redirect(url_for("login"))
    note_id = request.form.get("note_id", "").strip()
    student_id = request.form.get("student_id")
    class_id = request.form.get("class_id")
    grade = request.form.get("grade")
    comment = request.form.get("comment", "")
    if note_id:
        try:
            note_id = int(note_id)
        except ValueError:
            abort(400)
    conn = get_db()
    conn.autocommit = False
    try:
        with conn:
            with conn.cursor() as cur:
                if note_id:
                    cur.execute(
                        "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
                        (grade, comment_cipher.encrypt(comment, note_id), note_id),
                    )
                else:
                    # Get the database-generated id inside the same transaction, then bind
                    # the ciphertext to it. No plaintext comment is inserted even temporarily.
                    cur.execute(
                        "INSERT INTO notes (student_id, class_id, grade, comment) "
                        "VALUES (%s, %s, %s, NULL) RETURNING id",
                        (student_id, class_id, grade),
                    )
                    new_note_id = cur.fetchone()["id"]
                    cur.execute("UPDATE notes SET comment = %s WHERE id = %s",
                                (comment_cipher.encrypt(comment, new_note_id), new_note_id))
    finally:
        conn.close()
    log(f"grade write by {session.get('username')} note_id={note_id or 'new'}")
    return redirect(url_for("teacher"))


@app.route("/export.csv")
def export_csv():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    class_id = request.args.get("class_id")
    conn = get_db()
    cur = conn.cursor()
    if class_id:
        cur.execute(
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = cur.fetchall()
    conn.close()
    rows = [decrypt_note_comment(row) for row in rows]
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
    try:
        signed_export = export_hmac.sign_csv(buf.getvalue().encode("utf-8"))
    except ExportSizeError as error:
        return str(error), 413
    return Response(signed_export, mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=grades_export.csv",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })


@app.route("/verify-export", methods=["GET", "POST"])
def verify_export():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    result = None
    error = None
    status = 200
    if request.method == "POST":
        # Reject an oversized multipart request before asking Flask to parse it.
        if request.content_length and request.content_length > MAX_EXPORT_BYTES + 64 * 1024:
            error, status = "The file must not exceed 5 MiB.", 413
        else:
            uploaded = request.files.get("file")
            if uploaded is None or not uploaded.filename:
                error, status = "Choose a grades export file to verify.", 400
            else:
                signed_file = uploaded.stream.read(MAX_EXPORT_BYTES + 1)
                try:
                    export_hmac.verify_csv(signed_file)
                except ExportSizeError:
                    error, status = "The file must not exceed 5 MiB.", 413
                except ExportVerificationError:
                    result, status = False, 400
                else:
                    result = True
    response = Response(render_template("verify_export.html", result=result, error=error), status=status)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/admin")
def admin():
    if not login_required("admin"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    classes = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, classes=classes,
                           ping_result=request.args.get("ping_result"))


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    # Flaw #11: no CSRF token (handled in the next class).
    if not login_required("admin"):
        return redirect(url_for("login"))
    host = request.form.get("host", "").strip()
    # Flaw #9 fixed: no shell. The host is one argument in a list, so the
    # shell never re-reads it as grammar and ';' cannot start a new command.
    # Second wall: accept only letters, digits, dots and hyphens.
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        output = "Invalid host: use only letters, digits, dots and hyphens."
    else:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)
    log(f"admin ping host={host!r}")
    return render_template("admin.html", users=_all_users(), classes=_all_classes(),
                           ping_result=output)


def _all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def _all_classes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route("/admin/users", methods=["POST"])
def admin_users():
    if not login_required("admin"):
        return redirect(url_for("login"))
    action = request.form.get("action")
    conn = get_db()
    cur = conn.cursor()
    if action == "create":
        cur.execute(
            "INSERT INTO users (username, password, role, teacher_id) "
            "VALUES (%s, %s, %s, %s)",
            (request.form.get("username"), request.form.get("password"),
             request.form.get("role", "student"), None),
        )
    elif action == "delete":
        cur.execute("DELETE FROM users WHERE id = %s", (request.form.get("user_id"),))
    conn.close()
    return redirect(url_for("admin"))


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return "ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == "__main__":
    # Plain HTTP on purpose (flaw #3). Nginx + TLS is added in a later lab.
    app.run(host="0.0.0.0", port=5000, debug=True)
