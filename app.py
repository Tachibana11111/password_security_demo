from flask import Flask, render_template, request, redirect, url_for, flash, g
import sqlite3, hashlib

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

DB_PATH = "demo.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users_vulnerable (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                hash     TEXT    NOT NULL,
                algo     TEXT    NOT NULL,
                created  TEXT    DEFAULT (datetime('now','localtime'))
            );
        """)
        db.commit()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vulnerable")
def vulnerable():
    db    = get_db()
    users = db.execute(
        "SELECT id, username, hash, algo, created FROM users_vulnerable ORDER BY id DESC"
    ).fetchall()
    return render_template("vulnerable.html", users=users)

@app.route("/vulnerable/register", methods=["POST"])
def vulnerable_register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    algo     = request.form.get("algo", "md5")

    if not username or not password:
        flash("Vui lòng nhập đủ thông tin.", "danger")
        return redirect(url_for("vulnerable"))

    if algo == "md5":
        hashed = hashlib.md5(password.encode()).hexdigest()
    elif algo == "sha1":
        hashed = hashlib.sha1(password.encode()).hexdigest()
    else:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        algo   = "sha256"

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users_vulnerable (username, hash, algo) VALUES (?, ?, ?)",
            (username, hashed, algo)
        )
        db.commit()
        flash(f"Đăng ký thành công! Hash {algo.upper()}: {hashed[:24]}...", "warning")
    except sqlite3.IntegrityError:
        flash("Username đã tồn tại.", "danger")

    return redirect(url_for("vulnerable"))

@app.route("/vulnerable/login", methods=["POST"])
def vulnerable_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users_vulnerable WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        flash("Không tìm thấy user.", "danger")
        return redirect(url_for("vulnerable"))

    algo = user["algo"]
    if algo == "md5":
        attempt = hashlib.md5(password.encode()).hexdigest()
    elif algo == "sha1":
        attempt = hashlib.sha1(password.encode()).hexdigest()
    else:
        attempt = hashlib.sha256(password.encode()).hexdigest()

    if attempt == user["hash"]:         # ← lỗ hổng timing attack ở đây
        flash(f"Đăng nhập thành công! (hash so sánh bằng ==)", "warning")
    else:
        flash("Sai mật khẩu.", "danger")

    return redirect(url_for("vulnerable"))

@app.route("/vulnerable/clear", methods=["POST"])
def vulnerable_clear():
    db = get_db()
    db.execute("DELETE FROM users_vulnerable")
    db.commit()
    flash("Đã xóa toàn bộ user.", "info")
    return redirect(url_for("vulnerable"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
