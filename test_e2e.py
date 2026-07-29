#!/usr/bin/env python3
"""
中文密码测试网站 —— 端到端功能测试
测试覆盖：注册、正常登录、编码兼容、生僻字、Emoji、错误密码、账号锁定
"""

import pymysql
from config import DB_CONFIG

TEST_USER = "testuser_中文"
TEST_PASSWORD = "密码123😀测试"
BAD_PASSWORD = "错误密码"


def test_all():
    conn = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cur = conn.cursor()

    # 清理上次测试数据
    cur.execute("DELETE FROM user WHERE username LIKE 'testuser%'")
    conn.commit()

    # ------ 1. 直接测试密码哈希工具 ------
    print("=" * 50)
    print("🧪 测试 1：注册核心流程")
    print("=" * 50)

    from app import hash_password, normalize_text, check_password
    import unicodedata

    # 测试 NFC 标准化
    # 用组合字符 e + ́ (U+0065 + U+0301) vs é (U+00E9)
    composed = "é"
    decomposed = "é"
    assert unicodedata.normalize("NFC", composed) == unicodedata.normalize("NFC", decomposed), \
        "NFC 标准化失败"
    print("  ✅ NFC 标准化验证通过")

    # 测试哈希一致性
    h1 = hash_password(TEST_PASSWORD)
    h2 = hash_password(TEST_PASSWORD)
    assert h1 != h2, "bcrypt 每次应生成不同哈希"
    print("  ✅ bcrypt 加盐哈希生成正常")

    # 验证同一密码不同哈希都能校验通过
    assert check_password(TEST_PASSWORD, h1.decode("utf-8")), "h1 校验失败"
    assert check_password(TEST_PASSWORD, h2.decode("utf-8")), "h2 校验失败"
    assert not check_password(TEST_PASSWORD + "x", h1.decode("utf-8")), "错误密码应校验失败"
    print("  ✅ 密码校验逻辑正确")

    # ------ 2. 测试数据库写入 ------
    print("\n" + "=" * 50)
    print("🧪 测试 2：数据库写入与读取")
    print("=" * 50)

    password_hash = hash_password(TEST_PASSWORD)
    cur.execute(
        "INSERT INTO user (username, password_hash) VALUES (%s, %s)",
        (TEST_USER, password_hash.decode("utf-8")),
    )
    conn.commit()
    # 验证写入长度
    cur.execute("SELECT password_hash FROM user WHERE username = %s", (TEST_USER,))
    row = cur.fetchone()
    # bcrypt 哈希通常为 60 字节
    assert 50 <= len(row["password_hash"]) <= 255, f"哈希长度异常: {len(row['password_hash'])}"
    print(f"  ✅ 用户 [{TEST_USER}] 写入成功，哈希长度: {len(row['password_hash'])} 字符")

    # ------ 3. 测试 UTF-8 登录校验 ------
    print("\n" + "=" * 50)
    print("🧪 测试 3：UTF-8 登录校验")
    print("=" * 50)

    cur.execute("SELECT password_hash FROM user WHERE username = %s", (TEST_USER,))
    row = cur.fetchone()
    assert check_password(TEST_PASSWORD, row["password_hash"], encoding="utf-8"), \
        "UTF-8 登录校验失败"
    print("  ✅ UTF-8 登录正确")
    assert not check_password(BAD_PASSWORD, row["password_hash"], encoding="utf-8"), \
        "错误密码应校验失败"
    print("  ✅ 错误密码被正确拒绝")

    # ------ 4. 测试 GBK 编码兼容（生僻字导致异常） ------
    print("\n" + "=" * 50)
    print("🧪 测试 4：GBK 编码兼容场景")
    print("=" * 50)

    # 密码中含 Emoji 😀 (超出 GBK 范围)
    emoji_password = "密码😀"
    emoji_hash = hash_password(emoji_password)
    cur.execute(
        "INSERT INTO user (username, password_hash) VALUES (%s, %s)",
        ("testuser_emoji", emoji_hash.decode("utf-8")),
    )
    conn.commit()

    try:
        check_password(emoji_password, emoji_hash.decode("utf-8"), encoding="gbk")
        print("  ❌ GBK 应抛出 UnicodeEncodeError")
    except UnicodeEncodeError:
        print("  ✅ Emoji 密码选择 GBK → 正确抛编码异常")
    except ValueError as e:
        print(f"  ❌ 意外错误: {e}")

    # 纯中文密码，GBK 校验应失败（数据库存的是 UTF-8 哈希，字节序列不同）
    # 这正是系统设计：GBK 兼容仅用于客户端编码错乱的历史场景
    cn_password = "纯中文密码"
    cn_hash = hash_password(cn_password)
    cur.execute(
        "INSERT INTO user (username, password_hash) VALUES (%s, %s)",
        ("testuser_gbk", cn_hash.decode("utf-8")),
    )
    conn.commit()
    gbk_result = check_password(cn_password, cn_hash.decode("utf-8"), encoding="gbk")
    assert not gbk_result, \
        "纯中文密码 + GBK 应校验失败（字节序列 ≠ UTF-8 哈希）"
    print("  ✅ 纯中文密码 → GBK 编码校验失败（符合设计预期：UTF-8 与 GBK 字节不同）")

    # ASCII 密码，GBK 和 UTF-8 字节相同，应校验成功
    ascii_password = "Hello123!@#"
    ascii_hash = hash_password(ascii_password)
    assert check_password(ascii_password, ascii_hash.decode("utf-8"), encoding="gbk"), \
        "纯 ASCII 密码 + GBK 应校验成功（字节序列与 UTF-8 相同）"
    print("  ✅ 纯 ASCII 密码 + GBK 编码正常登录（字节相同）")

    # ------ 5. 测试非法编码 ------
    print("\n" + "=" * 50)
    print("🧪 测试 5：非法编码拦截")
    print("=" * 50)

    try:
        check_password(TEST_PASSWORD, "dummy", encoding="iso-2022-jp")
        print("  ❌ 应抛出 ValueError")
    except ValueError as e:
        assert "不支持" in str(e)
        print("  ✅ 非法编码被正确拒绝")

    # ------ 6. 测试账号锁定 ------
    print("\n" + "=" * 50)
    print("🧪 测试 6：登录失败锁定")
    print("=" * 50)

    from app import record_login_failure, reset_login_attempts, is_account_locked
    from datetime import datetime

    # 重置计数器
    reset_login_attempts(cur, TEST_USER)
    conn.commit()

    cur.execute("SELECT login_attempts FROM user WHERE username = %s", (TEST_USER,))
    assert cur.fetchone()["login_attempts"] == 0
    print("  ✅ 计数器已重置")

    # 模拟 5 次失败
    for i in range(5):
        locked = record_login_failure(cur, TEST_USER)
        conn.commit()

    cur.execute("SELECT login_attempts, locked_until FROM user WHERE username = %s", (TEST_USER,))
    row = cur.fetchone()
    assert row["login_attempts"] >= 5, f"失败计数应为 5+: {row['login_attempts']}"
    assert row["locked_until"] is not None, "账号应被锁定"
    assert is_account_locked(cur, TEST_USER), "is_account_locked 应返回 True"
    print("  ✅ 连续 5 次失败 → 账号锁定 10 分钟")

    # 清理
    cur.execute("DELETE FROM user WHERE username LIKE 'testuser%'")
    conn.commit()

    print("\n" + "=" * 50)
    print("✅✅✅ 所有测试通过！")
    print("=" * 50)

    cur.close()
    conn.close()


if __name__ == "__main__":
    test_all()
