#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中文密码测试网站
================
完全遵循 工程描述.md 的规范：

  注册：明文 → NFC → UTF-8 字节 → bcrypt 哈希 → 入库
  登录：明文 → NFC → 用户选择编码字节 → bcrypt 校验（兼容历史编码错乱）
"""

import unicodedata
from datetime import datetime, timedelta

import bcrypt
import pymysql
import pymysql.cursors
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from config import (
    ALLOWED_ENCODINGS,
    DB_CONFIG,
    LOCK_MINUTES,
    MAX_LOGIN_ATTEMPTS,
    SECRET_KEY,
)

# ---------------------------------------------------------------------------
# Flask 初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY


# ---------------------------------------------------------------------------
# 数据库连接（每次请求自动获取新连接，用完即关，简单可靠）
# ---------------------------------------------------------------------------
def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


# ---------------------------------------------------------------------------
# 密码处理工具函数
# ---------------------------------------------------------------------------
def normalize_text(raw: str) -> str:
    """Unicode NFC 标准化 —— 解决码位不同的视觉相同字符问题"""
    return unicodedata.normalize("NFC", raw)


def hash_password(raw: str) -> bytes:
    """
    注册 / 重置密码时使用的标准流程：
    明文 → NFC → UTF-8 严格编码 → bcrypt 哈希
    返回 bytes 哈希（存入 DB 时 decode 为字符串）
    """
    norm = normalize_text(raw)
    pwd_bytes = norm.encode("utf-8", errors="strict")
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt())


def check_password(raw: str, expected_hash: str, encoding: str = "utf-8") -> bool:
    """
    登录时校验密码：
    明文 → NFC → 用户选择编码（默认 UTF-8）→ bcrypt 校验

    返回 True/False
    如果编码导致 UnicodeEncodeError，抛出 ValueError
    """
    if encoding not in ALLOWED_ENCODINGS:
        raise ValueError("不支持的编码格式")

    norm = normalize_text(raw)
    # 如果所选编码无法表达输入的字符，会抛出 UnicodeEncodeError
    pwd_bytes = norm.encode(encoding, errors="strict")
    return bcrypt.checkpw(pwd_bytes, expected_hash.encode("utf-8"))


# ---------------------------------------------------------------------------
# 限流检查 / 记录
# ---------------------------------------------------------------------------
def is_account_locked(cursor, username: str) -> bool:
    cursor.execute(
        "SELECT locked_until FROM user WHERE username = %s", (username,)
    )
    row = cursor.fetchone()
    if row is None:
        return False
    if row["locked_until"] is None:
        return False
    if row["locked_until"] > datetime.now():
        return True
    # 锁定过期，重置计数器
    cursor.execute(
        "UPDATE user SET login_attempts = 0, locked_until = NULL WHERE username = %s",
        (username,),
    )
    return False


def record_login_failure(cursor, username: str):
    """增加失败次数，达到上限则锁定"""
    cursor.execute(
        "UPDATE user SET login_attempts = login_attempts + 1 WHERE username = %s",
        (username,),
    )
    cursor.execute(
        "SELECT login_attempts FROM user WHERE username = %s", (username,)
    )
    row = cursor.fetchone()
    if row and row["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        lock_time = datetime.now() + timedelta(minutes=LOCK_MINUTES)
        cursor.execute(
            "UPDATE user SET locked_until = %s WHERE username = %s",
            (lock_time, username),
        )
        return True  # 刚刚被锁定
    return False


def reset_login_attempts(cursor, username: str):
    cursor.execute(
        "UPDATE user SET login_attempts = 0, locked_until = NULL WHERE username = %s",
        (username,),
    )


# ---------------------------------------------------------------------------
# 路由 —— 首页
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("index.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ---------------------------------------------------------------------------
# 路由 —— 注册
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 基本校验
        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(username) > 100:
            error = "用户名最长 100 个字符"
        else:
            try:
                conn = get_db()
                with conn.cursor() as cur:
                    # 检查用户名是否已存在
                    cur.execute(
                        "SELECT id FROM user WHERE username = %s", (username,)
                    )
                    if cur.fetchone():
                        error = "用户名已被注册"
                    else:
                        # --- 注册核心流程 ---
                        password_hash = hash_password(password)
                        cur.execute(
                            "INSERT INTO user (username, password_hash) VALUES (%s, %s)",
                            (username, password_hash.decode("utf-8")),
                        )
                        conn.commit()
                        success = "注册成功！请前往登录。"
            except UnicodeEncodeError:
                error = "编码异常，请检查输入字符"
            except pymysql.err.IntegrityError:
                error = "用户名已被注册"
            except Exception as e:
                error = f"系统异常：{str(e)}"
            finally:
                conn.close()

    return render_template("register.html", error=error, success=success)


# ---------------------------------------------------------------------------
# 路由 —— 登录
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if "username" in session:
        return redirect(url_for("index"))

    error = None
    error_code = None
    selected_encoding = "utf-8"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        encoding = request.form.get("encoding", "utf-8").lower()
        selected_encoding = encoding  # 记住用户本次选择

        if not username or not password:
            error = "用户名和密码不能为空"
        else:
            # ---- 编码白名单校验 ----
            if encoding not in ALLOWED_ENCODINGS:
                error = "不支持的编码格式"
                error_code = 4000
            else:
                conn = get_db()
                try:
                    with conn.cursor() as cur:
                        # 查询用户
                        cur.execute(
                            "SELECT id, username, password_hash "
                            "FROM user WHERE username = %s",
                            (username,),
                        )
                        user = cur.fetchone()

                        if user is None:
                            error = "用户名或密码错误"
                            error_code = 1001
                        elif is_account_locked(cur, username):
                            error = (
                                f"账号已临时锁定，请 {LOCK_MINUTES} 分钟后再试"
                            )
                            error_code = 1001
                        else:
                            try:
                                # ---- 登录核心校验 ----
                                valid = check_password(
                                    password, user["password_hash"], encoding
                                )
                                if valid:
                                    # 成功
                                    reset_login_attempts(cur, username)
                                    conn.commit()
                                    session["username"] = user["username"]
                                    session["user_id"] = user["id"]
                                    return redirect(url_for("index"))
                                else:
                                    # 密码错误
                                    locked = record_login_failure(
                                        cur, username
                                    )
                                    conn.commit()
                                    error = "密码输入错误"
                                    error_code = 1001
                                    if locked:
                                        error = (
                                            f"密码错误次数过多，"
                                            f"账号已临时锁定 {LOCK_MINUTES} 分钟"
                                        )
                            except UnicodeEncodeError:
                                # 分支 A：所选编码无法表达输入的字符
                                error = (
                                    f"当前选择的编码（{encoding.upper()}）"
                                    f"无法支持你输入的文字（生僻字/特殊符号/Emoji）。"
                                    f"请切换编码为 UTF-8 重试，"
                                    f"或点击下方链接前往重置密码。"
                                )
                                error_code = 2001
                finally:
                    conn.close()

    return render_template(
        "login.html",
        error=error,
        error_code=error_code,
        selected_encoding=selected_encoding,
        allowed_encodings=sorted(ALLOWED_ENCODINGS),
    )


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
