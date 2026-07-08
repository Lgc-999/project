from flask import Flask, render_template, request, redirect, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
import sqlite3, os, time, secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ========== CSRF 防护 ==========
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def validate_csrf():
    token = request.form.get("csrf_token")
    expected = session.get("csrf_token")
    return token and expected and token == expected

# ========== HTTP 安全响应头 ==========
@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# ========== 数据库初始化 ==========
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    admin_pw = generate_password_hash("admin123")
    alice_pw = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", admin_pw, "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", alice_pw, "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()

init_db()

# 密码使用哈希存储（非明文）
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 暴力破解防护
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def is_ip_blocked(ip):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOCKOUT_MINUTES * 60]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS

def record_attempt(ip):
    login_attempts[ip].append(time.time())

def safe_user_data(user):
    if user:
        return {k: v for k, v in user.items() if k != "password"}
    return None

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username) if username else None
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        like = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SQL] {sql} (keyword=%{keyword}%)")
        c.execute(sql, (like, like))
        rows = c.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()
    return render_template("index.html", user=safe_user_data(user), results=results, keyword=keyword)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        if is_ip_blocked(ip):
            return render_template("login.html", error=f"尝试次数过多，请 {LOCKOUT_MINUTES} 分钟后再试")

        username = request.form.get("username")
        password = request.form.get("password")
        user = USERS.get(username)

        if user and check_password_hash(user["password"], password):
            session["username"] = username
            session.permanent = True
            return render_template("index.html", user=safe_user_data(user))

        record_attempt(ip)
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("register.html", error="CSRF 验证失败，请刷新页面重试")

        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        phone = request.form.get("phone")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql} (username={username})")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            USERS[username] = {
                "username": username,
                "password": generate_password_hash(password),
                "role": "user",
                "email": email,
                "phone": phone,
                "balance": 0,
            }
            msg = "注册成功，请登录"
        except Exception as e:
            msg = f"注册失败：{str(e)}"
        conn.close()
        return render_template("login.html", msg=msg)
    return render_template("register.html")

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        like = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SQL] {sql} (keyword=%{keyword}%)")
        c.execute(sql, (like, like))
        rows = c.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()
    return render_template("search.html", results=results, keyword=keyword)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug, host="0.0.0.0", port=80)
