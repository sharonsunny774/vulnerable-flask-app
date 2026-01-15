import os
import pyodbc
from flask import Flask, render_template, request, redirect, session
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # intentionally simple for local dev (educational)


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

            # Check if username already exists
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                return render_template("register.html", error="Username already taken.")

            # Intentionally weak (educational): store plaintext password
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

        # Intentionally weak (educational): plaintext password comparison
        if password != db_password:
            return render_template("login.html", error="Invalid username or password.")

        session["user_id"] = user_id
        session["username"] = db_username
        session["role"] = role

        return redirect("/dashboard")

    except Exception as e:
        return render_template("login.html", error=f"Error: {e}")


@app.get("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.get("/admin/<int:user_id>")
def admin_user_details(user_id: int):
    # ⚠️ INTENTIONALLY VULNERABLE (educational):
    # Only checks if you're logged in, NOT whether you're an admin.
    # Also allows direct object reference by changing user_id in the URL.
    if "user_id" not in session:
        return redirect("/login")

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, role, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()

    if not row:
        return "User not found", 404

    user = {
        "id": row[0],
        "username": row[1],
        "password": row[2],   # intentionally sensitive for demo
        "role": row[3],
        "created_at": row[4],
    }

    return render_template("admin.html", user=user)

@app.route("/search", methods=["GET", "POST"])
def search():
    q = ""
    results = []
    xss_risk = False
    db_error = None

    if request.method == "POST":
        q = request.form.get("q", "")

        # XSS risk indicator (used by search.html banner)
        if any(ch in q for ch in ["<", ">", '"', "'"]):
            xss_risk = True

        try:
            with get_conn() as conn:
                cur = conn.cursor()

                # ✅ CONTROLLED SQLi DEMO TRIGGER
                # This simulates "SQL injection dumps all users"
                if "RETURN_ALL" in q.upper():
                    cur.execute(
                        "SELECT TOP 50 id, username, role FROM users ORDER BY id"
                    )
                else:
                    # ⚠️ INTENTIONALLY VULNERABLE: SQL Injection via string concatenation
                    query = f"""
                        SELECT TOP 50 id, username, role
                        FROM users
                        WHERE username LIKE '%{q}%'
                        ORDER BY id
                    """
                    cur.execute(query)

                rows = cur.fetchall()

            results = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]

        except Exception as e:
            db_error = str(e)

    return render_template(
        "search.html",
        q=q,
        results=results,
        xss_risk=xss_risk,
        db_error=db_error
    )


if __name__ == "__main__":
    app.run(debug=True)

