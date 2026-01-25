import os
import uuid
from pathlib import Path

import pyodbc
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, send_from_directory
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# -------------------------
# Upload config (SECURE)
# -------------------------
UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2MB


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def sniff_jpeg_png(file_storage) -> bool:
    # minimal magic-bytes check
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    return head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG\r\n\x1a\n")


# -------------------------
# DB connection
# -------------------------
def get_conn():
    server = os.getenv("DB_SERVER", "localhost")
    database = os.getenv("DB_NAME", "VulnerableFlaskApp")
    driver = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")
    trust_cert = os.getenv("DB_TRUST_CERT", "yes")

    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        "Trusted_Connection=yes;"
        "Encrypt=yes;"
        f"TrustServerCertificate={trust_cert};"
    )
    return pyodbc.connect(conn_str)


# -------------------------
# Helpers
# -------------------------
def require_login():
    if "user_id" not in session:
        return False
    return True


# -------------------------
# Routes
# -------------------------
@app.get("/")
def home():
    return redirect("/login")


@app.get("/db-check")
def db_check():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT DB_NAME()")
        db_name = cur.fetchone()[0]
    return f"Connected to database ✅ {db_name}"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("register.html", error="Username and password are required.")

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                return render_template("register.html", error="Username already taken.")

            # NOTE: For real apps you'd hash passwords. Keeping simple for learning.
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
                (username, password),
            )
            conn.commit()

        return redirect("/login")
    except Exception as e:
        return render_template("register.html", error=f"Error: {e}")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("login.html", error="Username and password are required.")

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, password, role FROM users WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()

        if not row:
            return render_template("login.html", error="Invalid username or password.")

        user_id, db_username, db_password, role = row

        if password != db_password:
            return render_template("login.html", error="Invalid username or password.")

        session["user_id"] = user_id
        session["username"] = db_username
        session["role"] = role
        return redirect("/dashboard")

    except Exception as e:
        return render_template("login.html", error=f"Error: {e}")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/dashboard")
def dashboard():
    if not require_login():
        return redirect("/login")

    profile_image = None
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT profile_image FROM users WHERE id = ?", (session["user_id"],))
        row = cur.fetchone()
        if row:
            profile_image = row[0]

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        profile_image=profile_image,
    )


@app.route("/search", methods=["GET", "POST"])
def search():
    if not require_login():
        return redirect("/login")

    q = ""
    results = []
    xss_risk = False
    db_error = None

    if request.method == "POST":
        q = request.form.get("q", "")

        # SAFE demo: detect risky characters & show a popup warning (does NOT execute input)
        if any(ch in q for ch in ["<", ">", '"', "'"]):
            xss_risk = True

        try:
            with get_conn() as conn:
                cur = conn.cursor()

                # ✅ SAFE query (prevents SQLi)
                cur.execute(
                    "SELECT TOP 50 id, username, role FROM users WHERE username LIKE ? ORDER BY id",
                    (f"%{q}%",),
                )
                rows = cur.fetchall()

            results = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]

        except Exception as e:
            db_error = str(e)

    return render_template(
        "search.html",
        q=q,
        results=results,
        xss_risk=xss_risk,
        db_error=db_error,
    )


@app.get("/admin/<int:user_id>")
def admin_user_details(user_id: int):
    # Secure admin-only view
    if not require_login():
        return redirect("/login")
    if session.get("role") != "admin":
        return "Forbidden", 403

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()

    if not row:
        return "User not found", 404

    user = {
        "id": row[0],
        "username": row[1],
        "role": row[2],
        "created_at": row[3],
    }
    return render_template("admin.html", user=user)


@app.route("/profile/upload", methods=["GET", "POST"])
def upload_profile():
    if not require_login():
        return redirect("/login")

    if request.method == "GET":
        return render_template("profile_upload.html")

    file = request.files.get("photo")
    if not file or file.filename == "":
        return render_template("profile_upload.html", error="No file selected.")

    # SECURE checks
    if not allowed_file(file.filename):
        return render_template("profile_upload.html", error="Only .jpg, .jpeg, .png allowed.")

    if request.content_length and request.content_length > MAX_UPLOAD_BYTES:
        return render_template("profile_upload.html", error="File too large (max 2MB).")

    if not sniff_jpeg_png(file):
        return render_template("profile_upload.html", error="File content is not a real JPG/PNG.")

    safe_name = secure_filename(file.filename)
    ext = safe_name.rsplit(".", 1)[1].lower()
    new_name = f"{uuid.uuid4().hex}.{ext}"
    save_path = UPLOAD_FOLDER / new_name
    file.save(save_path)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET profile_image = ? WHERE id = ?", (new_name, session["user_id"]))
        conn.commit()

    return redirect("/dashboard")


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == "__main__":
    app.run(debug=True)


