from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret123"

DB_NAME = "phishing_results.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            score INTEGER,
            risk TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def is_logged_in():
    return "username" in session


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        if not username or not password:
            error = "Username and password are required"
        elif len(password) < 6:
            error = "Password must be at least 6 characters"
        else:
            hashed_password = generate_password_hash(password)

            try:
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, password, created_at)
                    VALUES (?, ?, ?)
                """, (
                    username,
                    hashed_password,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
                conn.commit()
                conn.close()

                success = "Account created successfully. You can now login."

            except sqlite3.IntegrityError:
                error = "Username already exists"

    return render_template("register.html", error=error, success=success)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template("index.html", username=session["username"])


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if not is_logged_in():
        return redirect(url_for("login"))

    if request.method == "POST":
        text = request.form.get("email_text", "").lower()

        score = 0

        if "urgent" in text:
            score += 20
        if "verify" in text:
            score += 20
        if "password" in text:
            score += 20
        if "http://" in text:
            score += 20
        if "login" in text:
            score += 15

        if score >= 60:
            risk = "High Risk"
        elif score >= 30:
            risk = "Medium Risk"
        else:
            risk = "Low Risk"

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO results (username, score, risk, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            session["username"],
            score,
            risk,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

        return render_template("result.html", score=score, risk=risk)

    return render_template("analyze.html", username=session["username"])


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, score, risk, created_at
        FROM results
        WHERE username = ?
        ORDER BY id DESC
    """, (session["username"],))
    data = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", data=data, username=session["username"])


@app.route("/delete_history", methods=["POST"])
def delete_history():
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM results WHERE username = ?", (session["username"],))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
