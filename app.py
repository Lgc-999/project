from flask import Flask, render_template, request, redirect, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
import sqlite3, os, time, secrets, urllib.request, urllib.error, subprocess, platform, re, json, socket, ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
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
            phone TEXT,
            avatar TEXT DEFAULT NULL
        )
    """)
    # 兼容旧表：如果 avatar 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass  # 列已存在
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
        "id": 1,
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 9999,
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}
NEXT_USER_ID = 3

# 从数据库加载头像到 USERS 字典
def load_avatars():
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("SELECT username, avatar FROM users WHERE avatar IS NOT NULL AND avatar != ''")
        for row in c.fetchall():
            if row[0] in USERS:
                USERS[row[0]]["avatar"] = row[1]
    except sqlite3.OperationalError:
        pass
    conn.close()

load_avatars()

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
        if not validate_csrf():
            return render_template("login.html", error="会话过期，请刷新页面重试")
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

        # 密码强度检查
        if len(password) < 6:
            return render_template("register.html", error="密码长度不能少于6位")

        # 密码哈希后存入数据库
        password_hash = generate_password_hash(password)

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql} (username={username})")
        try:
            c.execute(sql, (username, password_hash, email, phone))
            conn.commit()
            USERS[username] = {
                "id": NEXT_USER_ID,
                "username": username,
                "password": password_hash,
                "role": "user",
                "email": email,
                "phone": phone,
                "balance": 0,
            }
            globals()["NEXT_USER_ID"] = NEXT_USER_ID + 1
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
        sql = "SELECT id, username FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SQL] {sql} (keyword=%{keyword}%)")
        c.execute(sql, (like, like))
        rows = c.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1]})
        conn.close()
    return render_template("search.html", results=results, keyword=keyword)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            return render_template("upload.html", error="请选择文件")

        # 检查文件扩展名
        ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}
        ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error=f"不支持的文件类型: .{ext}，仅支持图片格式")

        # 检查 MIME 类型
        if not f.content_type or not f.content_type.startswith("image/"):
            return render_template("upload.html", error=f"非图片文件: {f.content_type}")

        # 读取文件头魔数验证是否为真实图片
        header = f.read(16)
        f.seek(0)
        is_image = False
        if header[:8] == b'\x89PNG\r\n\x1a\n': is_image = True          # PNG
        elif header[:2] == b'\xff\xd8': is_image = True                  # JPEG
        elif header[:6] in (b'GIF87a', b'GIF89a'): is_image = True      # GIF
        elif header[:4] == b'RIFF' and header[8:12] == b'WEBP': is_image = True  # WebP
        elif header[:2] == b'BM': is_image = True                        # BMP
        if not is_image:
            return render_template("upload.html", error="文件内容不是有效图片")

        # 防止路径穿越 + 限制文件名只含安全字符
        safe_filename = os.path.basename(f.filename)
        # 只保留字母数字下划线连字符和点
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe_filename)
        os.makedirs("static/uploads", exist_ok=True)
        path = os.path.join("static/uploads", safe_name)

        # 处理同名文件
        counter = 1
        while os.path.exists(path):
            name_part, ext2 = safe_name.rsplit(".", 1) if "." in safe_name else (safe_name, "")
            safe_name = f"{name_part}_{counter}.{ext2}" if ext2 else f"{name_part}_{counter}"
            path = os.path.join("static/uploads", safe_name)
            counter += 1

        f.save(path)
        url = f"/static/uploads/{safe_name}"
        # 保存头像 URL 到用户信息（内存 + 数据库）
        username = session.get("username")
        if username in USERS:
            USERS[username]["avatar"] = url
            conn2 = sqlite3.connect("data/users.db")
            c2 = conn2.cursor()
            c2.execute("UPDATE users SET avatar = ? WHERE username = ?", (url, username))
            conn2.commit()
            conn2.close()
        return render_template("upload.html", success=True, url=url, filename=safe_name)

    return render_template("upload.html")


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")
    username = session.get("username")
    target = USERS.get(username)
    if not target:
        return render_template("profile.html", error="用户不存在")
    return render_template("profile.html", user=safe_user_data(target))


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")
    if not validate_csrf():
        return render_template("profile.html", error="CSRF 验证失败，请刷新页面重试")
    username = session.get("username")
    target = USERS.get(username)
    amount_str = request.form.get("amount", "0")
    try:
        amount = int(amount_str)
    except ValueError:
        return render_template("profile.html", user=safe_user_data(target), error="金额格式错误")

    if amount <= 0:
        return render_template("profile.html", user=safe_user_data(target), error="充值金额必须大于0")

    # 限制单次充值上限，防止业务逻辑滥用
    if amount > 100000:
        return render_template("profile.html", user=safe_user_data(target), error="单次充值金额不能超过100,000")

    if target:
        target["balance"] = target.get("balance", 0) + amount
    # 从 session 中的用户名获取 id 跳转
    uid = target.get("id")
    return redirect(f"/profile?user_id={uid}")


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect("/login")
    if not validate_csrf():
        return render_template("profile.html", error="CSRF 验证失败，请刷新页面重试")
    # 只能修改当前登录用户自己的密码，不从表单拿 username
    username = session.get("username")
    new_password = request.form.get("new_password")
    if not new_password or len(new_password) < 6:
        return render_template("profile.html", user=safe_user_data(USERS.get(username)), error="密码长度不能少于6位")
    if username and new_password and username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)
    return redirect("/profile")


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    content = None
    if name:
        # 禁止路径分隔符，只允许安全的文件名（字母数字下划线连字符和点）
        if not re.match(r'^[a-zA-Z0-9_.-]+$', name):
            content = "页面名称不合法"
        else:
            base_dir = os.path.abspath("pages")
            candidates = [name, name + ".html"]
            found = None
            for c in candidates:
                p = os.path.abspath(os.path.join("pages", c))
                if p.startswith(base_dir) and os.path.exists(p) and os.path.isfile(p):
                    found = p
                    break
            if found:
                with open(found, "r", encoding="utf-8") as f:
                    content = f.read()
            else:
                content = "页面不存在"
    else:
        content = "请输入页面名称"
    return render_template("index.html", page_content=content, page_name=name)


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect("/login")
    url = request.form.get("url", "")
    status_code = None
    content = ""
    error = None
    if url:
        # 只允许 http 和 https 协议
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            error = f"不支持的协议: {parsed.scheme}，仅支持 http/https"
        else:
            # 解析目标主机名，检查是否为内网地址
            host = parsed.hostname
            try:
                addrs = socket.getaddrinfo(host, parsed.port or 80)
                for addr in addrs:
                    ip_addr = addr[4][0]
                    try:
                        ip_obj = ipaddress.ip_address(ip_addr)
                        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                            error = f"禁止访问内网地址: {ip_addr}"
                            break
                    except ValueError:
                        pass
            except socket.gaierror:
                error = f"无法解析域名: {host}"

            if not error:
                try:
                    resp = urllib.request.urlopen(url, timeout=10)
                    status_code = resp.status
                    raw = resp.read()
                    content = raw.decode("utf-8", errors="replace")[:5000]
                except urllib.error.HTTPError as e:
                    status_code = e.code
                    content = str(e.reason)[:5000]
                except urllib.error.URLError as e:
                    error = f"URL 访问失败: {e.reason}"
                except Exception as e:
                    error = f"请求异常: {str(e)}"
    return render_template("index.html", fetch_status=status_code, fetch_content=content, fetch_error=error, fetch_url=url, user=safe_user_data(USERS.get(session.get("username"))))


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")
    result = None
    ip_val = ""
    if request.method == "POST":
        ip_val = request.form.get("ip", "").strip()
        if ip_val:
            # 验证输入是否为合法的 IP 地址或域名
            is_valid = False
            try:
                socket.inet_aton(ip_val)
                is_valid = True
            except socket.error:
                # 不是 IP，检查是否为合法域名
                domain_re = re.compile(
                    r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
                )
                if domain_re.match(ip_val):
                    is_valid = True
            if not is_valid:
                result = "输入不合法：仅支持 IP 地址或域名"
            else:
                try:
                    output = subprocess.check_output(["ping", "-c", "3", ip_val], timeout=30, stderr=subprocess.STDOUT)
                    result = output.decode("utf-8", errors="replace")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败，返回码: {e.returncode}"
                except subprocess.TimeoutExpired:
                    result = "Ping 超时（30秒）"
                except Exception as e:
                    result = f"执行异常: {str(e)}"
    return render_template("ping.html", result=result, ip=ip_val)


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect("/login")
    result = None
    error = None
    raw_xml = ""
    if request.method == "POST":
        raw_xml = request.form.get("xml_data", "")
        if raw_xml.strip():
            try:
                # 移除 DOCTYPE 和 ENTITY 定义，防止 XXE 攻击
                safe_xml = re.sub(r'<!DOCTYPE[^>]*>', '', raw_xml)
                safe_xml = re.sub(r'<!ENTITY[^>]*>', '', safe_xml)
                # 移除实体引用（如 &xxe;）
                safe_xml = re.sub(r'&\w+;', '', safe_xml)

                # 提取 user 节点
                users = []
                for m in re.finditer(r'<user>\s*<name>(.*?)</name>\s*<email>(.*?)</email>\s*</user>', safe_xml, re.DOTALL):
                    users.append({"name": m.group(1).strip(), "email": m.group(2).strip()})
                if users:
                    result = json.dumps(users, ensure_ascii=False, indent=2)
                else:
                    error = "未找到有效的 user 节点数据"
            except Exception as e:
                error = f"XML 解析失败: {str(e)}"
    return render_template("xml_import.html", result=result, error=error, xml_data=raw_xml)


if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug, host="0.0.0.0", port=80)
