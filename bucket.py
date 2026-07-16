from __future__ import annotations

import base64
import hashlib
import hmac
import html
import mimetypes
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable, Optional
from urllib.parse import quote, urlsplit

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_local_env() -> None:
    env_path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_local_env()


APP_TITLE = "FrameConnection Bucket"
DEFAULT_PREFIX = os.environ.get("R2_PREFIX", "cloudflare_domain")
DEFAULT_SUBDIRECTORY = os.environ.get("DEFAULT_SUBDIRECTORY", "general")
SUPERUSER_EMAIL = os.environ.get("SUPERUSER_EMAIL", "joaoccoliveira@live.com").strip().lower()
SUPERUSER_INITIAL_PASSWORD = os.environ.get("SUPERUSER_INITIAL_PASSWORD", "joaoxx12345")
INITIAL_API_TOKENS = os.environ.get("INITIAL_API_TOKENS", "").strip()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "bucket_session")
SESSION_MAX_AGE_SECONDS = int(os.environ.get("SESSION_MAX_AGE_SECONDS", "604800"))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_PATH = os.environ.get("SQLITE_PATH", os.path.join(os.getcwd(), "bucket.db"))
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID", "").strip()
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "").strip()
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "").strip()
R2_ENDPOINT_URL = os.environ.get(
    "R2_ENDPOINT_URL",
    f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com" if R2_ACCOUNT_ID else "",
).strip()
R2_PUBLIC_BASE_URL = os.environ.get("R2_PUBLIC_BASE_URL", "").strip()
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").strip()
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="bucket-session")
app = FastAPI(title=APP_TITLE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_postgres() -> bool:
    return DATABASE_URL.startswith(("postgres://", "postgresql://"))


def is_running_on_railway() -> bool:
    return any(
        os.environ.get(var)
        for var in ("RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID", "RAILWAY_SERVICE_ID")
    )


def row_to_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    return dict(row)


def get_connection():
    if is_postgres():
        # Railway private hostnames are not resolvable from local machines.
        # In that local-only case, transparently fall back to SQLite.
        if ".railway.internal" in DATABASE_URL and not is_running_on_railway():
            connection = sqlite3.connect(SQLITE_PATH)
            connection.row_factory = sqlite3.Row
            return "sqlite", connection
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "DATABASE_URL points to Postgres, but psycopg is not installed."
            ) from exc

        connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return "postgres", connection

    connection = sqlite3.connect(SQLITE_PATH)
    connection.row_factory = sqlite3.Row
    return "sqlite", connection


def execute(
    connection,
    engine: str,
    sql: str,
    params: Iterable[Any] = (),
    *,
    fetchone: bool = False,
    fetchall: bool = False,
):
    if engine == "postgres":
        sql = sql.replace("?", "%s")
    cursor = connection.execute(sql, tuple(params))
    if fetchone:
        return cursor.fetchone()
    if fetchall:
        return cursor.fetchall()
    return None


def commit(connection) -> None:
    connection.commit()


def rollback(connection) -> None:
    try:
        connection.rollback()
    except Exception:
        pass


def column_exists(connection, engine: str, table_name: str, column_name: str) -> bool:
    if engine == "sqlite":
        rows = execute(connection, engine, f"PRAGMA table_info({table_name})", fetchall=True)
        return any(row_to_dict(row).get("name") == column_name for row in rows or [])

    row = execute(
        connection,
        engine,
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = ? AND column_name = ?
        """,
        (table_name, column_name),
        fetchone=True,
    )
    return row is not None


def ensure_schema() -> None:
    engine, connection = get_connection()
    try:
        execute(
            connection,
            engine,
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
            """,
        )
        execute(
            connection,
            engine,
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                owner_email TEXT NOT NULL,
                subdirectory TEXT NOT NULL DEFAULT '',
                object_key TEXT NOT NULL UNIQUE,
                display_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
        )
        execute(
            connection,
            engine,
            """
            CREATE TABLE IF NOT EXISTS signup_tokens (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                allowed_email TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_by TEXT,
                used_by_user_id TEXT,
                used_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL
            )
            """,
        )
        execute(
            connection,
            engine,
            """
            CREATE TABLE IF NOT EXISTS directories (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
        )

        if not column_exists(connection, engine, "users", "role"):
            execute(connection, engine, "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if not column_exists(connection, engine, "files", "subdirectory"):
            execute(connection, engine, "ALTER TABLE files ADD COLUMN subdirectory TEXT NOT NULL DEFAULT ''")

        commit(connection)
    finally:
        connection.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return base64.urlsafe_b64encode(salt + digest).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(stored_hash.encode("ascii"))
    except Exception:
        return False
    if len(raw) < 17:
        return False
    salt = raw[:16]
    expected = raw[16:]
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return hmac.compare_digest(candidate, expected)


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(email: str) -> str:
    payload = {"email": email, "csrf": secrets.token_urlsafe(24)}
    return serializer.dumps(payload)


def read_session(token: Optional[str]) -> Optional[dict[str, str]]:
    if not token:
        return None
    try:
        payload = serializer.loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (SignatureExpired, BadSignature):
        return None
    if not isinstance(payload, dict):
        return None
    email = payload.get("email")
    csrf = payload.get("csrf")
    if not email or not csrf:
        return None
    return {"email": str(email), "csrf": str(csrf)}


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_relative_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    normalized = normalized.lstrip("/")
    if not normalized:
        raise HTTPException(status_code=400, detail="A file path is required.")

    parts: list[str] = []
    for part in PurePosixPath(normalized).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise HTTPException(status_code=400, detail="Relative path segments are not allowed.")
        parts.append(part)

    if not parts:
        raise HTTPException(status_code=400, detail="A file path is required.")
    return "/".join(parts)


def normalize_subdirectory(subdirectory: str) -> str:
    value = normalize_relative_path(subdirectory)
    if value.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid subdirectory name.")
    return value


def join_key_parts(*parts: str) -> str:
    cleaned = [part.strip("/") for part in parts if part and part.strip("/")]
    return "/".join(cleaned)


def make_object_key(subdirectory: str, relative_path: str) -> str:
    return join_key_parts(DEFAULT_PREFIX, subdirectory, relative_path)


def make_directory_marker_key(subdirectory: str) -> str:
    return join_key_parts(DEFAULT_PREFIX, subdirectory, ".keep")


def get_r2_client():
    if not (R2_BUCKET_NAME and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_ENDPOINT_URL):
        raise RuntimeError(
            "R2 environment variables are missing. Set R2_BUCKET_NAME, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and R2_ENDPOINT_URL or R2_ACCOUNT_ID."
        )
    return boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
    )


def build_public_url(object_key: str) -> str:
    encoded_key = quote(object_key, safe="/")
    if R2_PUBLIC_BASE_URL:
        return f"{R2_PUBLIC_BASE_URL.rstrip('/')}/{encoded_key}"
    if APP_BASE_URL:
        return f"{APP_BASE_URL.rstrip('/')}/public/{encoded_key}"
    return f"/public/{encoded_key}"


def format_r2_error(exc: Exception) -> str:
    if isinstance(exc, RuntimeError):
        return str(exc)
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'UnknownError')}: {error.get('Message', 'Unknown storage error')}"
    return str(exc)


def get_user_by_email(email: str) -> Optional[dict[str, Any]]:
    engine, connection = get_connection()
    try:
        row = execute(
            connection,
            engine,
            "SELECT id, email, password_hash, role, created_at FROM users WHERE email = ?",
            (normalize_email(email),),
            fetchone=True,
        )
        return row_to_dict(row) if row else None
    finally:
        connection.close()


def is_superuser(user: dict[str, Any]) -> bool:
    return normalize_email(user.get("email", "")) == SUPERUSER_EMAIL or user.get("role") == "superuser"


def role_for_email(email: str) -> str:
    return "superuser" if normalize_email(email) == SUPERUSER_EMAIL else "user"


def insert_signup_token(raw_token: str, *, allowed_email: Optional[str], created_by: str, expires_at: Optional[str]) -> None:
    token_hash = hash_api_token(raw_token)
    engine, connection = get_connection()
    try:
        existing = execute(
            connection,
            engine,
            "SELECT id FROM signup_tokens WHERE token_hash = ?",
            (token_hash,),
            fetchone=True,
        )
        if existing:
            return
        execute(
            connection,
            engine,
            """
            INSERT INTO signup_tokens (id, token_hash, allowed_email, is_active, created_by, used_by_user_id, used_at, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                token_hash,
                normalize_email(allowed_email) if allowed_email else None,
                1,
                created_by,
                None,
                None,
                expires_at,
                utc_now(),
            ),
        )
        commit(connection)
    finally:
        connection.close()


def seed_initial_signup_tokens() -> None:
    if not INITIAL_API_TOKENS:
        return

    entries = [part.strip() for part in re.split(r"[,;\n]", INITIAL_API_TOKENS) if part.strip()]
    for entry in entries:
        allowed_email = None
        token = entry
        if ":" in entry:
            maybe_email, maybe_token = entry.split(":", 1)
            if "@" in maybe_email:
                allowed_email = maybe_email.strip()
                token = maybe_token.strip()
        if token:
            insert_signup_token(token, allowed_email=allowed_email, created_by="system", expires_at=None)


def ensure_default_directory() -> None:
    try:
        create_subdirectory_record(DEFAULT_SUBDIRECTORY, "system")
    except HTTPException:
        return


def create_user_with_signup_token(email: str, password: str, api_token: str) -> dict[str, Any]:
    normalized = normalize_email(email)
    if not normalized or "@" not in normalized:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not api_token.strip():
        raise HTTPException(status_code=400, detail="API token is required to create an account.")

    engine, connection = get_connection()
    try:
        existing = execute(
            connection,
            engine,
            "SELECT id FROM users WHERE email = ?",
            (normalized,),
            fetchone=True,
        )
        if existing:
            raise HTTPException(status_code=400, detail="A user with that email already exists.")

        token_hash = hash_api_token(api_token.strip())
        now_iso = utc_now()
        token_row = execute(
            connection,
            engine,
            """
            SELECT id, allowed_email
            FROM signup_tokens
            WHERE token_hash = ?
              AND is_active = 1
              AND used_by_user_id IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (token_hash, now_iso),
            fetchone=True,
        )
        if not token_row:
            raise HTTPException(status_code=400, detail="Invalid or expired API token.")

        token_data = row_to_dict(token_row)
        allowed_email = token_data.get("allowed_email")
        if allowed_email and normalize_email(allowed_email) != normalized:
            raise HTTPException(status_code=400, detail="This API token is assigned to a different email.")

        user_id = str(uuid.uuid4())
        execute(
            connection,
            engine,
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, normalized, hash_password(password), role_for_email(normalized), now_iso),
        )
        execute(
            connection,
            engine,
            "UPDATE signup_tokens SET used_by_user_id = ?, used_at = ?, is_active = 0 WHERE id = ?",
            (user_id, now_iso, token_data["id"]),
        )
        commit(connection)

        user = execute(
            connection,
            engine,
            "SELECT id, email, password_hash, role, created_at FROM users WHERE id = ?",
            (user_id,),
            fetchone=True,
        )
        return row_to_dict(user)
    except HTTPException:
        rollback(connection)
        raise
    except Exception as exc:
        rollback(connection)
        raise HTTPException(status_code=500, detail=f"Could not create user: {exc}") from exc
    finally:
        connection.close()


def authenticate_user(email: str, password: str) -> Optional[dict[str, Any]]:
    user = get_user_by_email(email)
    if not user:
        return None
    return user if verify_password(password, user["password_hash"]) else None


def create_subdirectory_record(subdirectory: str, created_by: str) -> None:
    normalized = normalize_subdirectory(subdirectory)
    engine, connection = get_connection()
    try:
        existing = execute(
            connection,
            engine,
            "SELECT id FROM directories WHERE name = ?",
            (normalized,),
            fetchone=True,
        )
        if existing:
            return
        execute(
            connection,
            engine,
            "INSERT INTO directories (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), normalized, normalize_email(created_by), utc_now()),
        )
        commit(connection)
    finally:
        connection.close()


def create_subdirectory(subdirectory: str, created_by: str) -> None:
    normalized = normalize_subdirectory(subdirectory)
    create_subdirectory_record(normalized, created_by)
    client = get_r2_client()
    client.put_object(Bucket=R2_BUCKET_NAME, Key=make_directory_marker_key(normalized), Body=b"")


def ensure_superuser_account() -> None:
    super_email = normalize_email(SUPERUSER_EMAIL)
    if not super_email or "@" not in super_email:
        return

    if get_user_by_email(super_email):
        return

    engine, connection = get_connection()
    try:
        execute(
            connection,
            engine,
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                super_email,
                hash_password(SUPERUSER_INITIAL_PASSWORD),
                "superuser",
                utc_now(),
            ),
        )
        commit(connection)
    finally:
        connection.close()


def delete_user_account(target_email: str) -> None:
    normalized_email = normalize_email(target_email)
    if not normalized_email or "@" not in normalized_email:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if normalized_email == SUPERUSER_EMAIL:
        raise HTTPException(status_code=403, detail="The superuser account cannot be removed.")

    user = get_user_by_email(normalized_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.get("role") == "superuser":
        raise HTTPException(status_code=403, detail="The superuser account cannot be removed.")

    engine, connection = get_connection()
    try:
        execute(connection, engine, "DELETE FROM users WHERE email = ?", (normalized_email,))
        commit(connection)
    finally:
        connection.close()


def renew_superuser_password(new_password: str) -> None:
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    super_email = normalize_email(SUPERUSER_EMAIL)
    user = get_user_by_email(super_email)
    if not user:
        raise HTTPException(status_code=404, detail="Superuser account not found.")

    engine, connection = get_connection()
    try:
        execute(
            connection,
            engine,
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (hash_password(new_password), super_email),
        )
        commit(connection)
    finally:
        connection.close()


def list_subdirectories() -> list[str]:
    engine, connection = get_connection()
    try:
        rows_a = execute(connection, engine, "SELECT name FROM directories", fetchall=True) or []
        rows_b = execute(
            connection,
            engine,
            "SELECT DISTINCT subdirectory FROM files WHERE subdirectory IS NOT NULL AND subdirectory <> ''",
            fetchall=True,
        ) or []
        values = {row_to_dict(row).get("name") for row in rows_a}
        values.update(row_to_dict(row).get("subdirectory") for row in rows_b)
    finally:
        connection.close()

    values = {v for v in values if v}
    values.add(DEFAULT_SUBDIRECTORY)
    return sorted(values)


def get_current_session(request: Request) -> Optional[dict[str, str]]:
    return read_session(request.cookies.get(SESSION_COOKIE_NAME))


def require_session(request: Request) -> dict[str, str]:
    session = get_current_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return session


def require_user(request: Request) -> dict[str, Any]:
    session = require_session(request)
    user = get_user_by_email(session["email"])
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_superuser(user: dict[str, Any]) -> None:
    if not is_superuser(user):
        raise HTTPException(status_code=403, detail="Superuser access required.")


def require_csrf(request: Request, session: dict[str, str], token: Optional[str]) -> None:
    candidate = token or request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")
    if not candidate or candidate != session["csrf"]:
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def upsert_file_metadata(
    uploaded_by_email: str,
    subdirectory: str,
    object_key: str,
    display_path: str,
    size_bytes: int,
    content_type: str,
) -> None:
    engine, connection = get_connection()
    try:
        execute(
            connection,
            engine,
            """
            INSERT INTO files (id, owner_email, subdirectory, object_key, display_path, size_bytes, content_type, updated_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(object_key) DO UPDATE SET
                owner_email = excluded.owner_email,
                subdirectory = excluded.subdirectory,
                display_path = excluded.display_path,
                size_bytes = excluded.size_bytes,
                content_type = excluded.content_type,
                updated_at = excluded.updated_at
            """,
            (
                str(uuid.uuid4()),
                normalize_email(uploaded_by_email),
                subdirectory,
                object_key,
                display_path,
                size_bytes,
                content_type,
                utc_now(),
                utc_now(),
            ),
        )
        commit(connection)
    finally:
        connection.close()


def delete_file_metadata(object_key: str) -> None:
    engine, connection = get_connection()
    try:
        execute(connection, engine, "DELETE FROM files WHERE object_key = ?", (object_key,))
        commit(connection)
    finally:
        connection.close()


def list_files_for_subdirectory(subdirectory: str) -> list[dict[str, Any]]:
    engine, connection = get_connection()
    try:
        rows = execute(
            connection,
            engine,
            """
            SELECT subdirectory, object_key, display_path, size_bytes, content_type, updated_at, created_at
            FROM files
            WHERE subdirectory = ?
            ORDER BY updated_at DESC
            """,
            (subdirectory,),
            fetchall=True,
        )
        return [row_to_dict(row) for row in rows or []]
    finally:
        connection.close()


def get_file_metadata(object_key: str) -> Optional[dict[str, Any]]:
    engine, connection = get_connection()
    try:
        row = execute(
            connection,
            engine,
            "SELECT subdirectory, object_key, display_path, size_bytes, content_type, updated_at, created_at FROM files WHERE object_key = ?",
            (object_key,),
            fetchone=True,
        )
        return row_to_dict(row) if row else None
    finally:
        connection.close()


def render_layout(
    title: str,
    body: str,
    *,
    session: Optional[dict[str, str]] = None,
    message: Optional[str] = None,
) -> HTMLResponse:
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    auth_block = ""
    if session:
                auth_block = f"""
                <div class="auth-panel">
                    <div class="session-meta">Signed in as <strong>{html.escape(session["email"])}</strong></div>
                    <form method="post" action="/logout">
                        <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
                        <button class="secondary" type="submit">Log out</button>
                    </form>
                </div>
                """
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f1ea;
      --panel: #fffdf8;
      --text: #1f2937;
      --muted: #6b7280;
      --line: #d7d2c8;
      --accent: #1f6feb;
      --accent-strong: #1447b3;
      --danger: #b42318;
      --shadow: 0 18px 40px rgba(31, 41, 55, 0.12);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    body {{ margin: 0; background: radial-gradient(circle at top left, #fff7df 0, #f4f1ea 35%, #ece8de 100%); color: var(--text); }}
    .shell {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero {{ display: flex; justify-content: space-between; align-items: start; gap: 16px; margin-bottom: 24px; }}
    .brand {{ font-size: 34px; font-weight: 800; letter-spacing: -0.04em; margin: 0; }}
    .subtitle {{ margin: 6px 0 0; color: var(--muted); max-width: 70ch; }}
    .card {{ background: rgba(255,255,255,0.82); backdrop-filter: blur(8px); border: 1px solid rgba(215,210,200,0.8); border-radius: 22px; box-shadow: var(--shadow); padding: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 18px; }}
    .stack {{ display: grid; gap: 12px; }}
    label {{ font-size: 14px; font-weight: 700; display: block; margin-bottom: 6px; }}
    input, select {{ width: 100%; box-sizing: border-box; border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; font: inherit; background: white; }}
    button, .button {{ border: 0; border-radius: 12px; padding: 10px 14px; font: inherit; font-weight: 700; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 8px; }}
    button.primary, .button.primary {{ background: var(--accent); color: white; }}
    button.primary:hover, .button.primary:hover {{ background: var(--accent-strong); }}
    button.secondary, .button.secondary {{ background: #eceff6; color: var(--text); }}
    button.danger, .button.danger {{ background: #fef3f2; color: var(--danger); }}
    .notice {{ margin-bottom: 18px; border-radius: 14px; background: #ecfdf3; color: #027a48; padding: 12px 14px; border: 1px solid #abefc6; }}
    .split {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: center; justify-content: space-between; }}
    .muted {{ color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; }}
    .col-size {{ width: 88px; }}
    .col-type {{ width: 130px; }}
    .col-updated {{ width: 235px; }}
    .col-actions {{ width: 140px; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid rgba(215,210,200,0.75); vertical-align: middle; }}
    th {{ font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    .file-row-main td {{ padding-top: 10px; padding-bottom: 4px; border-bottom: 0; }}
    .file-row-sub td {{ padding-top: 0; padding-bottom: 10px; font-size: 12px; color: var(--muted); }}
    .file-row-sub code {{ font-size: 12px; }}
    .file-path {{ font-weight: 700; line-height: 1.25; white-space: nowrap; }}
    .session-meta {{ color: var(--muted); font-size: 14px; }}
    .auth-panel {{ display: grid; gap: 8px; justify-items: end; }}
    .auth-panel form {{ margin: 0; }}
    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .actions.compact button, .actions.compact .button {{ padding: 7px 10px; border-radius: 10px; font-size: 12px; }}
    code {{ background: #f3f4f6; border-radius: 8px; padding: 2px 6px; }}
    .footer-note {{ margin-top: 14px; color: var(--muted); font-size: 14px; }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <div>
        <h1 class="brand">{html.escape(APP_TITLE)}</h1>
        <p class="subtitle">Before registering, ask for an API token. Registered user can Create/Read/Update/Delete files inside any existing subdirectory.</p>
      </div>
      <div>{auth_block}</div>
    </div>
    {notice}
    {body}
  </div>
</body>
</html>"""
    return HTMLResponse(page)


def auth_page(*, message: Optional[str] = None) -> HTMLResponse:
    body = """
    <div class="grid">
      <section class="card stack">
        <h2>Sign in</h2>
        <form class="stack" method="post" action="/login">
          <div>
            <label for="login_email">Email</label>
            <input id="login_email" name="email" type="email" autocomplete="email" required>
          </div>
          <div>
            <label for="login_password">Password</label>
            <input id="login_password" name="password" type="password" autocomplete="current-password" required>
          </div>
          <button class="primary" type="submit">Sign in</button>
        </form>
      </section>
      <section class="card stack">
        <h2>Create account</h2>
        <form class="stack" method="post" action="/register">
          <div>
            <label for="register_email">Email</label>
            <input id="register_email" name="email" type="email" autocomplete="email" required>
          </div>
          <div>
            <label for="register_password">Password</label>
            <input id="register_password" name="password" type="password" autocomplete="new-password" minlength="8" required>
          </div>
          <div>
            <label for="register_api_token">API token</label>
            <input id="register_api_token" name="api_token" type="text" autocomplete="off" required>
          </div>
          <button class="primary" type="submit">Create account</button>
        </form>
      </section>
    </div>
    """
    return render_layout(APP_TITLE, body, message=message)


def dashboard_page(
    user: dict[str, Any],
    session: dict[str, str],
    selected_subdirectory: str,
    *,
    message: Optional[str] = None,
) -> HTMLResponse:
    all_subdirs = list_subdirectories()
    if selected_subdirectory not in all_subdirs:
        selected_subdirectory = all_subdirs[0] if all_subdirs else DEFAULT_SUBDIRECTORY

    files = list_files_for_subdirectory(selected_subdirectory)
    file_rows = []
    safe_subdir_query = quote(selected_subdirectory, safe="")

    for item in files:
        encoded_path = quote(item["display_path"], safe="/")
        download_url = f"/files/{encoded_path}?subdirectory={safe_subdir_query}"
        delete_url = f"/files/{encoded_path}/delete"
        public_url = build_public_url(item["object_key"])
        split_public_url = urlsplit(public_url)
        public_url_path = split_public_url.path or public_url
        file_rows.append(
            f"""
            <tr class="file-row-main">
              <td><div class="file-path">{html.escape(item['display_path'])}</div></td>
              <td>{html.escape(str(item['size_bytes']))}</td>
              <td>{html.escape(item['content_type'])}</td>
              <td>{html.escape(item['updated_at'])}</td>
              <td>
                <div class="actions compact">
                  <a class="button secondary" href="{html.escape(download_url)}">Download</a>
                  <form method="post" action="{html.escape(delete_url)}" style="display:inline-flex;">
                    <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
                    <input type="hidden" name="subdirectory" value="{html.escape(selected_subdirectory)}">
                    <button class="danger" type="submit">Delete</button>
                  </form>
                </div>
              </td>
            </tr>
            <tr class="file-row-sub">
                            <td colspan="5">
                                <div>Public URL path: <a href="{html.escape(public_url)}"><code>{html.escape(public_url_path)}</code></a></div>
                                <div>Object key: <code>{html.escape(item['object_key'])}</code></div>
                            </td>
            </tr>
            """
        )

    subdir_options = "".join(
        f'<option value="{html.escape(name)}" {"selected" if name == selected_subdirectory else ""}>{html.escape(name)}</option>'
        for name in all_subdirs
    )

    superuser_panel = ""
    if is_superuser(user):
        superuser_panel = f"""
        <section class="card stack">
          <h2>Superuser controls</h2>
          <form class="stack" method="post" action="/directories">
            <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
            <div>
              <label for="new_subdirectory">Create subdirectory</label>
              <input id="new_subdirectory" name="subdirectory" type="text" placeholder="team-a" required>
            </div>
            <button class="primary" type="submit">Create subdirectory</button>
          </form>
          <form class="stack" method="post" action="/tokens">
            <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
            <div>
              <label for="allowed_email">Optional email restriction</label>
              <input id="allowed_email" name="allowed_email" type="email" placeholder="user@example.com">
            </div>
            <div>
              <label for="expires_in_days">Token expires in days</label>
              <input id="expires_in_days" name="expires_in_days" type="number" min="1" max="365" value="30" required>
            </div>
            <button class="primary" type="submit">Generate signup API token</button>
          </form>
                    <form class="stack" method="post" action="/users/delete">
                        <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
                        <div>
                            <label for="delete_user_email">Remove non-superuser account</label>
                            <input id="delete_user_email" name="user_email" type="email" placeholder="user@example.com" required>
                        </div>
                        <button class="danger" type="submit">Remove user</button>
                    </form>
                    <form class="stack" method="post" action="/users/superuser/password">
                        <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
                        <div>
                            <label for="superuser_new_password">Renew superuser password</label>
                            <input id="superuser_new_password" name="new_password" type="password" minlength="8" autocomplete="new-password" required>
                        </div>
                        <div>
                            <label for="superuser_confirm_password">Confirm new password</label>
                            <input id="superuser_confirm_password" name="confirm_password" type="password" minlength="8" autocomplete="new-password" required>
                        </div>
                        <button class="primary" type="submit">Update superuser password</button>
                    </form>
        </section>
        """

    upload_card = f"""
    <section class="card stack">
      <h2>Upload a file</h2>
      <form class="stack" method="post" action="/files" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
                <input type="hidden" name="subdirectory" value="{html.escape(selected_subdirectory)}">
        <div>
                    <label>Current subdirectory</label>
                    <div><code>{html.escape(selected_subdirectory)}</code></div>
        </div>
        <div>
          <label for="path">Path inside subdirectory</label>
          <input id="path" name="path" type="text" placeholder="picture.png or docs/picture.png">
        </div>
        <div>
          <label for="file">File</label>
          <input id="file" name="file" type="file" required>
        </div>
        <button class="primary" type="submit">Upload / overwrite</button>
      </form>
            <div class="footer-note">Objects are stored as <code>{html.escape(join_key_parts(DEFAULT_PREFIX, selected_subdirectory, 'path'))}</code>. Change subdirectory from the Shared files selector.</div>
    </section>
    """

    files_card = f"""
    <section class="card stack">
      <div class="split">
                <h2 style="margin: 0;">Shared files</h2>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{html.escape(session['csrf'])}">
          <button class="secondary" type="submit">Sign out</button>
        </form>
      </div>
      <form class="split" method="get" action="/dashboard">
        <label for="selected_subdirectory" style="margin:0;">Browse subdirectory</label>
                <select id="selected_subdirectory" name="subdirectory" style="max-width:320px;" onchange="this.form.submit()">{subdir_options}</select>
                <button class="secondary" type="submit">Open</button>
      </form>
      <div class="muted">Available files in this subdirectory: {len(files)}</div>
      <div style="overflow-x:auto;">
        <table>
          <colgroup>
            <col>
            <col class="col-size">
            <col class="col-type">
            <col class="col-updated">
            <col class="col-actions">
          </colgroup>
          <thead>
            <tr>
              <th>Path</th>
              <th>Size</th>
              <th>Type</th>
              <th>Updated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {''.join(file_rows) if file_rows else '<tr><td colspan="5" class="muted">No files in this subdirectory yet.</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="footer-note">Current subdirectory: <code>{html.escape(selected_subdirectory)}</code></div>
    </section>
    """

    body = f"<div class=\"grid\">{upload_card}{files_card}{superuser_panel}</div>"
    return render_layout(APP_TITLE, body, session=session, message=message)


def sanitize_upload_name(upload: UploadFile) -> str:
    raw_name = (upload.filename or "").strip().replace("\\", "/")
    raw_name = PurePosixPath(raw_name).name
    if not raw_name:
        raise HTTPException(status_code=400, detail="The uploaded file must have a name.")
    return raw_name


def build_file_response(object_key: str):
    client = get_r2_client()
    try:
        response = client.get_object(Bucket=R2_BUCKET_NAME, Key=object_key)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code in {"NoSuchKey", "404", "NotFound"}:
            raise HTTPException(status_code=404, detail="File not found.") from exc
        raise

    metadata = get_file_metadata(object_key)
    headers = {}
    if metadata:
        headers["Content-Disposition"] = f'attachment; filename="{metadata["display_path"].split("/")[-1]}"'
    elif "ContentDisposition" in response:
        headers["Content-Disposition"] = response["ContentDisposition"]
    if response.get("ContentType"):
        headers["Content-Type"] = response["ContentType"]

    def iterator():
        body = response["Body"]
        try:
            while True:
                chunk = body.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            body.close()

    return StreamingResponse(iterator(), headers=headers, media_type=response.get("ContentType", "application/octet-stream"))


def create_signup_token(created_by_email: str, allowed_email: Optional[str], expires_in_days: int) -> str:
    if expires_in_days < 1 or expires_in_days > 365:
        raise HTTPException(status_code=400, detail="Token expiry must be between 1 and 365 days.")

    raw_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
    insert_signup_token(
        raw_token,
        allowed_email=normalize_email(allowed_email) if allowed_email else None,
        created_by=normalize_email(created_by_email),
        expires_at=expires_at,
    )
    return raw_token


ensure_schema()
seed_initial_signup_tokens()
ensure_default_directory()
ensure_superuser_account()


@app.on_event("startup")
def on_startup() -> None:
    ensure_schema()
    seed_initial_signup_tokens()
    ensure_default_directory()
    ensure_superuser_account()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = get_current_session(request)
    if session:
        return RedirectResponse("/dashboard", status_code=303)
    return auth_page()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, subdirectory: str = ""):
    session = require_session(request)
    user = require_user(request)
    all_subdirs = list_subdirectories()
    selected = subdirectory.strip() if subdirectory.strip() else (all_subdirs[0] if all_subdirs else DEFAULT_SUBDIRECTORY)
    return dashboard_page(user, session, selected)


@app.post("/register")
def register(email: str = Form(...), password: str = Form(...), api_token: str = Form(...)):
    try:
        user = create_user_with_signup_token(email, password, api_token)
    except HTTPException as exc:
        return auth_page(message=str(exc.detail))

    session_token = create_session(user["email"])
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, session_token)
    return response


@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return auth_page(message="Invalid email or password.")

    session_token = create_session(user["email"])
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, session_token)
    return response


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    response = RedirectResponse("/", status_code=303)
    session = get_current_session(request)
    if session:
        require_csrf(request, session, csrf_token)
    clear_session_cookie(response)
    return response


@app.get("/logout")
def logout_get():
    response = RedirectResponse("/", status_code=303)
    clear_session_cookie(response)
    return response


@app.post("/directories")
def create_directory_route(request: Request, subdirectory: str = Form(...), csrf_token: str = Form(...)):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)
    require_superuser(user)

    try:
        normalized = normalize_subdirectory(subdirectory)
        create_subdirectory(normalized, user["email"])
        return dashboard_page(user, session, normalized, message=f"Subdirectory created: {normalized}")
    except (HTTPException, RuntimeError, ClientError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else format_r2_error(exc)
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message=f"Could not create subdirectory: {detail}")


@app.post("/tokens")
def create_token_route(
    request: Request,
    csrf_token: str = Form(...),
    allowed_email: str = Form(""),
    expires_in_days: int = Form(30),
):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)
    require_superuser(user)

    try:
        token = create_signup_token(user["email"], allowed_email.strip() or None, int(expires_in_days))
        return dashboard_page(
            user,
            session,
            DEFAULT_SUBDIRECTORY,
            message=f"New signup API token (copy now): {token}",
        )
    except (HTTPException, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message=f"Could not create token: {detail}")


@app.post("/users/delete")
def delete_user_route(request: Request, csrf_token: str = Form(...), user_email: str = Form(...)):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)
    require_superuser(user)

    try:
        delete_user_account(user_email)
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message=f"Removed user: {normalize_email(user_email)}")
    except HTTPException as exc:
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message=f"Could not remove user: {exc.detail}")


@app.post("/users/superuser/password")
def renew_superuser_password_route(
    request: Request,
    csrf_token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)
    require_superuser(user)

    if new_password != confirm_password:
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message="Could not renew password: passwords do not match.")

    try:
        renew_superuser_password(new_password)
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message="Superuser password renewed successfully.")
    except HTTPException as exc:
        return dashboard_page(user, session, DEFAULT_SUBDIRECTORY, message=f"Could not renew password: {exc.detail}")


@app.get("/files/{relative_path:path}")
def download_file(request: Request, relative_path: str, subdirectory: str = ""):
    require_user(request)
    normalized_subdir = normalize_subdirectory(subdirectory or DEFAULT_SUBDIRECTORY)
    normalized_path = normalize_relative_path(relative_path)
    object_key = make_object_key(normalized_subdir, normalized_path)
    try:
        return build_file_response(object_key)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"Download failed: {format_r2_error(exc)}") from exc
    except ClientError as exc:
        raise HTTPException(status_code=502, detail=f"Download failed: {format_r2_error(exc)}") from exc


@app.get("/public/{object_key:path}")
def public_file(object_key: str):
    normalized_key = normalize_relative_path(object_key)
    try:
        return build_file_response(normalized_key)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"Download failed: {format_r2_error(exc)}") from exc
    except ClientError as exc:
        raise HTTPException(status_code=502, detail=f"Download failed: {format_r2_error(exc)}") from exc


@app.post("/files")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    path: str = Form(""),
    subdirectory: str = Form(...),
    csrf_token: str = Form(...),
):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)

    normalized_subdir = normalize_subdirectory(subdirectory)
    chosen_path = path.strip() if path.strip() else sanitize_upload_name(file)
    normalized_path = normalize_relative_path(chosen_path)
    object_key = make_object_key(normalized_subdir, normalized_path)

    content = await file.read()
    content_type = file.content_type or mimetypes.guess_type(normalized_path)[0] or "application/octet-stream"

    try:
        client = get_r2_client()
        client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=object_key,
            Body=content,
            ContentType=content_type,
        )
        upsert_file_metadata(user["email"], normalized_subdir, object_key, normalized_path, len(content), content_type)
    except (RuntimeError, ClientError) as exc:
        return dashboard_page(user, session, normalized_subdir, message=f"Upload failed: {format_r2_error(exc)}")

    return RedirectResponse(f"/dashboard?subdirectory={quote(normalized_subdir, safe='')}", status_code=303)


@app.post("/files/{relative_path:path}/delete")
def delete_file(
    request: Request,
    relative_path: str,
    csrf_token: str = Form(...),
    subdirectory: str = Form(...),
):
    session = require_session(request)
    require_csrf(request, session, csrf_token)
    user = require_user(request)

    normalized_subdir = normalize_subdirectory(subdirectory)
    normalized_path = normalize_relative_path(relative_path)
    object_key = make_object_key(normalized_subdir, normalized_path)

    try:
        client = get_r2_client()
        client.delete_object(Bucket=R2_BUCKET_NAME, Key=object_key)
        delete_file_metadata(object_key)
    except (RuntimeError, ClientError) as exc:
        return dashboard_page(user, session, normalized_subdir, message=f"Delete failed: {format_r2_error(exc)}")

    return RedirectResponse(f"/dashboard?subdirectory={quote(normalized_subdir, safe='')}", status_code=303)


@app.get("/api/me")
def api_me(request: Request):
    session = require_session(request)
    user = require_user(request)
    return {
        "email": user["email"],
        "role": user.get("role", "user"),
        "is_superuser": is_superuser(user),
        "csrf": session["csrf"],
        "prefix": DEFAULT_PREFIX,
        "subdirectories": list_subdirectories(),
    }


@app.get("/api/files")
def api_list_files(request: Request, subdirectory: str = ""):
    require_user(request)
    normalized_subdir = normalize_subdirectory(subdirectory or DEFAULT_SUBDIRECTORY)
    files = list_files_for_subdirectory(normalized_subdir)
    return {
        "subdirectory": normalized_subdir,
        "items": [
            {
                "path": item["display_path"],
                "object_key": item["object_key"],
                "size_bytes": item["size_bytes"],
                "content_type": item["content_type"],
                "updated_at": item["updated_at"],
                "download_url": f"/files/{quote(item['display_path'], safe='/')}?subdirectory={quote(normalized_subdir, safe='')}",
                "public_url": build_public_url(item["object_key"]),
            }
            for item in files
        ],
    }


@app.get("/healthz")
def healthcheck():
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("bucket:app", host="0.0.0.0", port=port, reload=False)
