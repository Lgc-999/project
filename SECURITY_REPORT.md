# 🔒 用户信息管理平台 — 安全审计报告

**项目名称：** 用户信息管理平台  
**审计日期：** 2026-07-07  
**审计人：** Claude Code  
**风险等级：** 🔴 严重（建议立即修复）

---

## 目录

1. [漏洞汇总](#1-漏洞汇总)
2. [漏洞详情与修复方案](#2-漏洞详情与修复方案)
   - [2.1 明文密码存储](#21-明文密码存储)
   - [2.2 HTML 注释泄露管理员账号密码](#22-html-注释泄露管理员账号密码)
   - [2.3 登录后明文展示密码](#23-登录后明文展示密码)
   - [2.4 硬编码弱密钥](#24-硬编码弱密钥)
   - [2.5 Debug 模式 + root 权限运行](#25-debug-模式--root-权限运行)
   - [2.6 无 CSRF 防护](#26-无-csrf-防护)
   - [2.7 无暴力破解防护](#27-无暴力破解防护)
3. [修复优先级建议](#3-修复优先级建议)

---

## 1. 漏洞汇总

| 编号 | 漏洞名称 | 风险等级 | 影响面 |
|------|---------|---------|--------|
| V-01 | 明文密码存储 | 🔴 严重 | 用户数据全部泄露 |
| V-02 | HTML 注释泄露管理员账号密码 | 🔴 严重 | 任意访问者可直接登录 |
| V-03 | 登录后明文展示密码 | 🟡 中危 | 密码在页面直接暴露 |
| V-04 | 硬编码弱密钥 | 🟡 中危 | Session 可被伪造 |
| V-05 | Debug 模式 + root 运行 | 🟡 中危 | 服务器被控风险 |
| V-06 | 无 CSRF 防护 | 🔵 低危 | 跨站请求伪造攻击 |
| V-07 | 无暴力破解防护 | 🔵 低危 | 密码可被批量爆破 |

---

## 2. 漏洞详情与修复方案

---

### 2.1 明文密码存储

#### 当前问题

`app.py` 中密码以**明文硬编码**在源码中：

```python
USERS = {
    "admin": {
        "password": "admin123",   # 明文！
        ...
    },
    "alice": {
        "password": "alice2025",  # 明文！
        ...
    },
}
```

且登录时直接用 `==` 字符串比对：

```python
if user and user["password"] == password:  # 直接比对明文
```

#### 风险

- 任何人看到代码就知道所有用户的密码
- 代码上传到 GitHub 后，全世界都能看到
- 数据库泄露则密码全部暴露

#### 修复方案

**① 使用 Werkzeug 的密码哈希（推荐，最简单）：**

```python
from werkzeug.security import generate_password_hash, check_password_hash

# 存储哈希值
USERS = {
    "admin": {
        "password": generate_password_hash("admin123"),
        ...
    }
}

# 登录时比对哈希
if user and check_password_hash(user["password"], password):
    # 登录成功
```

**② 或使用 bcrypt（更安全）：**

```bash
pip install bcrypt
```

```python
import bcrypt

# 注册时加密
hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
USERS["admin"]["password"] = hashed

# 登录时校验
if bcrypt.checkpw(password.encode(), user["password"]):
    # 登录成功
```

#### 修复后效果
- 数据库中存储的是哈希值（如 `pbkdf2:sha256:260000$...`），不是明文
- 即使代码泄露，也无法反推出原始密码
- 登录比对仍然可以正常工作

---

### 2.2 HTML 注释泄露管理员账号密码

#### 当前问题

`templates/login.html` 第 1 行：

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

#### 风险

- 任何用户在浏览器按 F12 查看网页源代码，即可看到管理员账号密码
- 搜索引擎爬虫可能收录该信息

#### 修复方案

**① 直接删除该注释：**

```html
<!-- 删除这一行 -->
{% extends "base.html" %}
{% block content %}
```

**② 如需调试信息，放到环境变量或配置文件中：**

```python
# app.py
import os
DEBUG_ACCOUNT = os.environ.get("DEBUG_ACCOUNT", "")
```

```html
{% if config.get('DEBUG') %}
    <!-- 调试模式启用 -->
{% endif %}
```

#### 修复后效果
- 网页源代码不再泄露敏感信息
- 调试信息仅在服务器端可控的情况下显示

---

### 2.3 登录后明文展示密码

#### 当前问题

`templates/index.html` 第 7-8 行：

```html
<ul class="info-list">
    <li><span class="label">用户名：</span>{{ user.username }}</li>
    <li><span class="label">密码：</span>{{ user.password }}</li>   <!-- 这里！ -->
```

#### 风险

- 用户登录后密码直接显示在页面上
- 旁人路过屏幕即可看到密码
- 截图分享时密码一同泄露

#### 修复方案

**① 移除密码字段显示（推荐）：**

```html
<ul class="info-list">
    <li><span class="label">用户名：</span>{{ user.username }}</li>
    <li><span class="label">邮箱：</span>{{ user.email }}</li>
    <li><span class="label">手机：</span>{{ user.phone }}</li>
    <li><span class="label">角色：</span>{{ user.role }}</li>
    <li><span class="label">余额：</span>{{ user.balance }}</li>
</ul>
```

或显示掩码版本：

```html
<li><span class="label">密码：</span>********</li>
```

**② 后端过滤敏感字段：**

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ...
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            # 不将密码传给模板
            safe_user = {k: v for k, v in user.items() if k != "password"}
            return render_template("index.html", user=safe_user)
```

#### 修复后效果
- 页面不再显示密码明文
- 用户信息展示时自动过滤敏感字段

---

### 2.4 硬编码弱密钥

#### 当前问题

`app.py` 第 4 行：

```python
app.secret_key = "dev-key-2025"
```

这是一个固定的、公开的弱密钥。

#### 风险

- Session 使用该密钥进行签名加密
- 攻击者可以用这个密钥伪造任意用户的 session
- 例如构造一个 `username=admin` 的 session，无需登录即可进入管理后台

#### 修复方案

**① 从环境变量读取（推荐）：**

```python
import os

app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())
```

**② 生成一个真正的随机密钥：**

```bash
# 生成一个安全的随机密钥
python3 -c "import secrets; print(secrets.token_hex(32))"
```

输出示例：`a7f8c2e1b3d94f506e2a8c7b9d1e3f5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2`

```python
app.secret_key = "a7f8c2e1b3d94f506e2a8c7b9d1e3f5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
```

**③ 配置文件分离：**

```python
# config.py
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# app.py
from config import Config
app.config.from_object(Config)
```

#### 修复后效果
- 即使源码泄露，攻击者也无法伪造 session
- 每次部署可以更换不同的密钥

---

### 2.5 Debug 模式 + root 权限运行

#### 当前问题

`app.py` 第 61 行：

```python
app.run(debug=True, host="0.0.0.0", port=80)
```

- `debug=True`：Flask 调试模式
- 以 **root 用户** 运行
- 监听 `0.0.0.0`（所有网络接口）

#### 风险

- Debug 模式下如果代码出错，会显示交互式调试器，可执行任意 Python 代码
- 以 root 运行意味着整个服务器在攻击者面前不设防
- 监听 0.0.0.0 意味着局域网内任何设备都可以访问

#### 修复方案

**① 生产环境关闭 Debug：**

```python
# 根据环境变量控制
import os
debug = os.environ.get("FLASK_ENV") == "development"

app.run(debug=debug, host="0.0.0.0", port=80)
```

**② 使用普通用户运行：**

```bash
# 创建专用用户
useradd -m -s /bin/bash flaskuser

# 用该用户运行
sudo -u flaskuser python3 app.py
```

**③ 使用 Gunicorn + Nginx 部署（生产环境）：**

```bash
# 安装 gunicorn
pip install gunicorn

# 用非 root 用户运行
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Nginx 作为反向代理（对外监听 80 端口）：

```nginx
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### 修复后效果
- 代码出错不会暴露敏感信息
- 攻击者即使攻破应用也无法获得 root 权限
- Nginx 反向代理提供额外的安全层

---

### 2.6 无 CSRF 防护

#### 当前问题

`login.html` 中的表单没有 CSRF Token：

```html
<form method="POST" action="/login">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">登录</button>
</form>
```

#### 风险

- 攻击者可以构造恶意页面，诱导用户点击
- 用户在不自知的情况下向登录接口提交表单
- 虽然单纯登录危害不大，但如果有修改密码等操作风险更高

#### 修复方案

**① 使用 Flask-WTF（推荐）：**

```bash
pip install flask-wtf
```

```python
# app.py
from flask_wtf.csrf import CSRFProtect

app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(32).hex()
csrf = CSRFProtect(app)
```

```html
<form method="POST" action="/login">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="username">
    ...
</form>
```

**② 手动实现 CSRF Token：**

```python
# app.py
import secrets

@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

@app.route("/login", methods=["POST"])
def login():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        return "CSRF 验证失败", 403
    ...
```

#### 修复后效果
- 每个表单都带有一个一次性 Token
- 外部网站无法伪造提交请求

---

### 2.7 无暴力破解防护

#### 当前问题

登录接口没有限制尝试次数：

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = USERS.get(username)
    if user and user["password"] == password:  # 无限尝试
        ...
```

#### 风险

- 攻击者可以用脚本每秒尝试数百个密码
- 弱密码（如 admin123）几秒钟内即可被爆破

#### 修复方案

**① 简单的 IP 限流（使用 Flask-Limiter）：**

```bash
pip install flask-limiter
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # 每分钟最多 5 次登录尝试
def login():
    ...
```

**② 手动实现登录失败计数：**

```python
# 用字典记录失败次数
login_attempts = {}

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = time.time()

    # 清理超过 15 分钟的记录
    login_attempts[ip] = [t for t in login_attempts.get(ip, []) if now - t < 900]

    # 如果 15 分钟内失败超过 5 次，临时封禁
    if len(login_attempts.get(ip, [])) >= 5:
        return render_template("login.html", error="尝试次数过多，请 15 分钟后重试")

    username = request.form.get("username")
    password = request.form.get("password")
    user = USERS.get(username)

    if user and user["password"] == password:
        session["username"] = username
        return render_template("index.html", user=user)

    # 记录失败
    login_attempts.setdefault(ip, []).append(now)
    return render_template("login.html", error="用户名或密码错误")
```

#### 修复后效果
- 同一个 IP 短时间内无法大量尝试密码
- 大幅增加暴力破解的时间成本

---

## 3. 修复优先级建议

### 🔴 立即修复（上线前必须完成）

| 优先级 | 漏洞 | 预计耗时 |
|--------|------|---------|
| P0 | ① 明文密码存储 → 哈希加密 | 30 分钟 |
| P1 | ② 删除 HTML 注释泄露 | 1 分钟 |
| P2 | ④ 更换硬编码密钥 | 5 分钟 |

### 🟡 尽快修复

| 优先级 | 漏洞 | 预计耗时 |
|--------|------|---------|
| P3 | ③ 移除页面密码展示 | 5 分钟 |
| P4 | ⑤ Debug 关闭 + 非 root 运行 | 15 分钟 |

### 🔵 后续完善

| 优先级 | 漏洞 | 预计耗时 |
|--------|------|---------|
| P5 | ⑥ 添加 CSRF 防护 | 20 分钟 |
| P6 | ⑦ 添加暴力破解防护 | 15 分钟 |

---

## 修复后代码示例（整合版）

```python
from flask import Flask, render_template, request, redirect, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# CSRF 防护
csrf = CSRFProtect(app)

# 限流
limiter = Limiter(get_remote_address, app=app)

# 密码哈希存储
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

@app.after_request
def add_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username) if username else None
    # 过滤密码字段
    if user:
        user = {k: v for k, v in user.items() if k != "password"}
    return render_template("index.html", user=user)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            safe_user = {k: v for k, v in user.items() if k != "password"}
            return render_template("index.html", user=safe_user)
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug, host="0.0.0.0", port=5000)
```

---

*报告生成时间：2026-07-07 | 工具：Claude Code*
