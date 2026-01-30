"""
============================================================
VULNERABLE WEB APPLICATION 
============================================================
Vulnerabilities:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. IDOR - Profiles
4. IDOR - Files
5. IDOR - Invoices
6. Insecure File Upload
7. Broken Access Control (Admin)
8. Plaintext Passwords
9. No Rate Limiting
10. Verbose Error Messages
11. Debug Mode
12. Weak Secret Key
============================================================
"""

import os
from pathlib import Path

import random
from flask import Flask, render_template, request, redirect, session, send_from_directory, make_response, jsonify

import pyodbc
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, send_from_directory

load_dotenv()

app = Flask(__name__)

# ⚠️ VULNERABLE: Weak/hardcoded secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")


# -------------------------
# Upload config (VULNERABLE - No restrictions!)
# -------------------------
UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)


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
# Helper
# -------------------------
def require_login():
    return "user_id" in session


# -------------------------
# Routes
# -------------------------
@app.get("/")
def home():
    return redirect("/login")


@app.get("/db-check")
def db_check():
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT DB_NAME()")
            db_name = cur.fetchone()[0]
        return f"✅ Connected to database: {db_name}"
    except Exception as e:
        return f"❌ Database error: {e}"


# ============================================================
# AUTH: Plaintext Passwords + No Rate Limiting
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    if not first_name or not last_name or not email or not password:
        return render_template("register.html", error="All fields are required.")

    # ⚠️ VULNERABLE: No password policy enforcement!
    # Accepts any password like "1", "a", "123"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                return render_template("register.html", error="Email already registered.")

            # Generate OTP
            otp_code = str(random.randint(100000, 999999))
            
            # ⚠️ VULNERABLE: Store OTP in plain text
            cur.execute(
                "INSERT INTO otps (email, otp_code) VALUES (?, ?)",
                (email, otp_code)
            )
            conn.commit()

        # Store registration data in session temporarily
        session['pending_registration'] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password  # ⚠️ VULNERABLE: Plaintext password in session
        }
        session['pending_otp'] = otp_code  # ⚠️ VULNERABLE: OTP stored in session

        return redirect("/verify-otp")

    except Exception as e:
        return render_template("register.html", error=f"Error: {e}")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if 'pending_registration' not in session:
        return redirect("/register")

    if request.method == "GET":
        # ⚠️ VULNERABLE: OTP sent in response header (visible in Burp Suite)
        response = make_response(render_template("verify_otp.html", 
            email=session['pending_registration']['email']))
        
        # ⚠️ VULNERABLE: OTP exposed in custom header
        response.headers['X-OTP-Code'] = session.get('pending_otp', '')
        return response

    entered_otp = request.form.get("otp", "").strip()
    
    if entered_otp == session.get('pending_otp'):
        reg_data = session['pending_registration']
        
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO users (username, password, role, first_name, last_name, email) VALUES (?, ?, 'user', ?, ?, ?)",
                    (reg_data['email'], reg_data['password'], reg_data['first_name'], reg_data['last_name'], reg_data['email'])
                )
                conn.commit()

            session.pop('pending_registration', None)
            session.pop('pending_otp', None)

            return redirect("/login")

        except Exception as e:
            return render_template("verify_otp.html", error=f"Error: {e}",
                email=session['pending_registration']['email'])
    else:
        return render_template("verify_otp.html", 
            email=session['pending_registration']['email'],
            error="Invalid OTP. Please try again.")


@app.route("/login", methods=["GET", "POST"])
def login():
    # ⚠️ VULNERABLE: No rate limiting!
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

        # ⚠️ VULNERABLE: Plaintext comparison!
        if password != db_password:
            return render_template("login.html", error="Invalid username or password.")

        session["user_id"] = user_id
        session["username"] = db_username
        session["role"] = role

        # ⚠️ VULNERABLE: Create response with insecure cookies
        response = make_response(redirect("/dashboard"))
        
        # ⚠️ VULNERABLE: Admin cookie that can be tampered
        is_admin = "true" if role == "admin" else "false"
        
        response.set_cookie('admin', is_admin, httponly=False, samesite='Lax')
        response.set_cookie('user_id', str(user_id), httponly=False, samesite='Lax')
        response.set_cookie('username', db_username, httponly=False, samesite='Lax')
        
        return response

    except Exception as e:
        return render_template("login.html", error=f"Error: {e}")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ============================================================
# DASHBOARD
# ============================================================
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
        user_id=session.get("user_id"),
        profile_image=profile_image,
    )


# ============================================================
# VULNERABILITY #1 & #2: SQL Injection + XSS
# ============================================================
@app.route("/search", methods=["GET", "POST"])
def search():
    if not require_login():
        return redirect("/login")

    q = ""
    results = []
    error_message = None

    if request.method == "POST":
        q = request.form.get("q", "")

        # ⚠️ VULNERABLE: SQL Injection!
        query = f"SELECT TOP 50 id, username, role FROM users WHERE username LIKE '%{q}%' ORDER BY id"

        try:
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute(query)
                rows = cur.fetchall()

            results = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]

        except Exception as e:
            # ⚠️ VULNERABLE: Exposing database errors!
            error_message = str(e)

    return render_template("search.html", q=q, results=results, error_message=error_message)


# ============================================================
# VULNERABILITY #3: IDOR - User Profiles
# ============================================================
@app.route("/profile/<int:user_id>")
def view_profile(user_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No ownership check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, role, profile_image, created_at FROM users WHERE id = ?",
            (user_id,)
        )
        row = cur.fetchone()
        
        if not row:
            return render_template("error.html", message="User not found"), 404
        
        user = {
            "id": row[0],
            "username": row[1],
            "password": row[2],  # ⚠️ VULNERABLE: Exposing password!
            "role": row[3],
            "profile_image": row[4],
            "created_at": row[5],
        }
        
        cur.execute(
            "SELECT id, filename, original_name, uploaded_at FROM files WHERE user_id = ?",
            (user_id,)
        )
        files = [{"id": r[0], "filename": r[1], "original_name": r[2], "uploaded_at": r[3]} for r in cur.fetchall()]

    return render_template("profile.html", user=user, files=files, current_user_id=session.get("user_id"))


# ============================================================
# VULNERABILITY #4: IDOR - File Operations
# ============================================================
@app.route("/files/<int:user_id>")
def user_files(user_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No ownership check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user_row = cur.fetchone()
        if not user_row:
            return render_template("error.html", message="User not found"), 404
        
        cur.execute(
            "SELECT id, filename, original_name, uploaded_at FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
            (user_id,)
        )
        files = [{"id": r[0], "filename": r[1], "original_name": r[2], "uploaded_at": r[3]} for r in cur.fetchall()]

    return render_template("user_files.html", username=user_row[0], user_id=user_id, files=files)


@app.route("/download/<int:file_id>")
def download_file(file_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No ownership check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT filename, original_name FROM files WHERE id = ?", (file_id,))
        row = cur.fetchone()

    if not row:
        return "File not found", 404

    filename, original_name = row
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True, download_name=original_name)


@app.route("/delete-file/<int:file_id>", methods=["POST"])
def delete_file(file_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No ownership check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT filename FROM files WHERE id = ?", (file_id,))
        row = cur.fetchone()
        
        if row:
            filename = row[0]
            cur.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            
            file_path = UPLOAD_FOLDER / filename
            if file_path.exists():
                file_path.unlink()

    return redirect(request.referrer or "/dashboard")


# ============================================================
# VULNERABILITY #5: IDOR - Invoices
# ============================================================
@app.route("/invoice/<int:invoice_id>")
def view_invoice(invoice_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No ownership check!
    invoice = {
        "id": invoice_id,
        "amount": 100 + (invoice_id * 50),
        "description": f"Invoice #{invoice_id} - Premium Service",
        "user_id": (invoice_id % 5) + 1,
        "status": "Paid" if invoice_id % 2 == 0 else "Pending",
        "date": "2025-01-15",
        "items": [
            {"name": "Service Fee", "amount": 50 + (invoice_id * 10)},
            {"name": "Processing Fee", "amount": 25},
            {"name": "Tax", "amount": 25 + (invoice_id * 5)},
        ]
    }

    return render_template("invoice.html", invoice=invoice)


# ============================================================
# VULNERABILITY #6: Insecure File Upload
# ============================================================
@app.route("/profile/upload", methods=["GET", "POST"])
def upload_profile():
    if not require_login():
        return redirect("/login")

    if request.method == "GET":
        return render_template("profile_upload.html")

    file = request.files.get("photo")
    if not file or file.filename == "":
        return render_template("profile_upload.html", error="No file selected.")

    # ⚠️ VULNERABLE: No validation!
    filename = file.filename
    save_path = UPLOAD_FOLDER / filename
    file.save(save_path)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET profile_image = ? WHERE id = ?", (filename, session["user_id"]))
        conn.commit()

    return redirect("/dashboard")


@app.route("/upload", methods=["GET", "POST"])
def general_upload():
    if not require_login():
        return redirect("/login")

    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template("upload.html", error="No file selected.")

    # ⚠️ VULNERABLE: No validation!
    filename = file.filename
    save_path = UPLOAD_FOLDER / filename
    file.save(save_path)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO files (user_id, filename, original_name, uploaded_at) VALUES (?, ?, ?, GETDATE())",
            (session["user_id"], filename, file.filename)
        )
        conn.commit()

    return render_template("upload.html", success=True, filename=filename)


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ============================================================
# VULNERABILITY #7: Broken Access Control - Admin Panel
# ============================================================
@app.route("/admin")
def admin_panel():
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: Checking cookie instead of session!
    admin_cookie = request.cookies.get('admin', 'false')
    if admin_cookie != 'true':
        return render_template("error.html", message="Admin access required"), 403

    # ⚠️ VULNERABLE: No role check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, created_at FROM users ORDER BY id")
        users = [
            {"id": r[0], "username": r[1], "password": r[2], "role": r[3], "created_at": r[4]}
            for r in cur.fetchall()
        ]

    return render_template("admin.html", users=users)


@app.route("/admin/user/<int:user_id>")
def admin_user_detail(user_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No role check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, role, profile_image, created_at FROM users WHERE id = ?",
            (user_id,)
        )
        row = cur.fetchone()

    if not row:
        return render_template("error.html", message="User not found"), 404

    user = {
        "id": row[0],
        "username": row[1],
        "password": row[2],
        "role": row[3],
        "profile_image": row[4],
        "created_at": row[5],
    }

    return render_template("admin_user.html", user=user)


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No role check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    return redirect("/admin")


@app.route("/admin/make-admin/<int:user_id>", methods=["POST"])
def admin_make_admin(user_id: int):
    if not require_login():
        return redirect("/login")

    # ⚠️ VULNERABLE: No role check!
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        conn.commit()

    return redirect("/admin")


# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", message=f"Server error: {e}"), 500


# ============================================================
# RUN APP
# ============================================================
if __name__ == "__main__":
    # ⚠️ VULNERABLE: Debug mode enabled!
    app.run(debug=True, host="127.0.0.1", port=5000)