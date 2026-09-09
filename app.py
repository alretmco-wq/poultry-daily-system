from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Any, Dict, Optional
import sqlite3, json, os, hashlib, hmac, secrets, time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "data" / "daily.db"
STATIC = BASE / "static"
DB.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="نظام اليومية - توزيع الدواجن")
SESSION_COOKIE = "poultry_daily_session"
SESSION_SECONDS = 60 * 60 * 24 * 14

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def hash_password(password: str, salt: Optional[bytes]=None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return f"{salt.hex()}${digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000).hex()
        return hmac.compare_digest(test, digest_hex)
    except Exception:
        return False

def init_db():
    with conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS dailies (
          id TEXT PRIMARY KEY,
          daily_date TEXT,
          rep TEXT,
          saved_at TEXT,
          payload TEXT NOT NULL
        )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_dailies_date ON dailies(daily_date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_dailies_rep ON dailies(rep)")
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          display_name TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','user')),
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          username TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          FOREIGN KEY(username) REFERENCES users(username)
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS private_expenses (
          id TEXT PRIMARY KEY,
          expense_date TEXT NOT NULL,
          name TEXT NOT NULL,
          amount REAL NOT NULL DEFAULT 0,
          created_by TEXT NOT NULL,
          saved_at TEXT NOT NULL,
          payload TEXT NOT NULL,
          FOREIGN KEY(created_by) REFERENCES users(username)
        )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_private_expenses_date ON private_expenses(expense_date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_private_expenses_user ON private_expenses(created_by)")
        existing = c.execute("SELECT username FROM users LIMIT 1").fetchone()
        if not existing:
            admin_password = os.getenv("DAILY_ADMIN_PASSWORD", "Poultry@2026")
            c.execute("INSERT INTO users(username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
                      ("admin", "الإدارة", hash_password(admin_password), "admin", int(time.time())))

init_db()

class Daily(BaseModel):
    data: Dict[str, Any]

class PrivateExpense(BaseModel):
    data: Dict[str, Any]

class LoginBody(BaseModel):
    username: str
    password: str

class PasswordBody(BaseModel):
    old_password: str
    new_password: str

class UserCreate(BaseModel):
    username: str
    display_name: str
    password: str
    role: str = "user"

def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "login required")
    now = int(time.time())
    with conn() as c:
        row = c.execute("""SELECT u.username,u.display_name,u.role,u.active,s.expires_at
                           FROM sessions s JOIN users u ON u.username=s.username
                           WHERE s.token=?""", (token,)).fetchone()
        if not row or not row["active"] or row["expires_at"] < now:
            if row:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "session expired")
    return dict(row)

def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    return user

@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/auth/login")
def login(body: LoginBody, response: Response):
    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (body.username.strip(),)).fetchone()
        if not row or not row["active"] or not verify_password(body.password, row["password_hash"]):
            raise HTTPException(401, "بيانات الدخول غير صحيحة")
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + SESSION_SECONDS
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        c.execute("INSERT INTO sessions(token,username,expires_at) VALUES(?,?,?)", (token,row["username"],expires))
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_SECONDS, path="/")
    return {"ok": True, "user": {"username": row["username"], "display_name": row["display_name"], "role": row["role"]}}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with conn() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"username":user["username"],"display_name":user["display_name"],"role":user["role"]}

@app.post("/api/auth/change-password")
def change_password(body: PasswordBody, user=Depends(current_user)):
    if len(body.new_password) < 8:
        raise HTTPException(400, "كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف")
    with conn() as c:
        row=c.execute("SELECT password_hash FROM users WHERE username=?",(user["username"],)).fetchone()
        if not row or not verify_password(body.old_password,row["password_hash"]):
            raise HTTPException(400,"كلمة المرور الحالية غير صحيحة")
        c.execute("UPDATE users SET password_hash=? WHERE username=?",(hash_password(body.new_password),user["username"]))
        c.execute("DELETE FROM sessions WHERE username=?",(user["username"],))
    return {"ok":True}

@app.get("/api/users")
def list_users(admin=Depends(require_admin)):
    with conn() as c:
        rows=c.execute("SELECT username,display_name,role,active,created_at FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/users")
def create_user(body: UserCreate, admin=Depends(require_admin)):
    username=body.username.strip()
    if not username or len(body.password)<8 or body.role not in ("admin","user"):
        raise HTTPException(400,"بيانات المستخدم غير صالحة")
    try:
        with conn() as c:
            c.execute("INSERT INTO users(username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
                      (username,body.display_name.strip() or username,hash_password(body.password),body.role,int(time.time())))
    except sqlite3.IntegrityError:
        raise HTTPException(409,"اسم المستخدم موجود مسبقاً")
    return {"ok":True}

@app.get("/api/dailies")
def list_dailies(user=Depends(current_user)):
    with conn() as c:
        rows = c.execute("SELECT payload FROM dailies ORDER BY daily_date DESC, saved_at DESC").fetchall()
    return [json.loads(r["payload"]) for r in rows]

@app.put("/api/dailies/{daily_id}")
def upsert_daily(daily_id: str, body: Daily, user=Depends(current_user)):
    rec = body.data
    if str(rec.get("id")) != daily_id:
        raise HTTPException(400, "daily id mismatch")
    rec["updatedBy"] = user["username"]
    if not rec.get("createdBy"):
        rec["createdBy"] = user["username"]
    with conn() as c:
        c.execute("""
        INSERT INTO dailies(id,daily_date,rep,saved_at,payload)
        VALUES(?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          daily_date=excluded.daily_date,
          rep=excluded.rep,
          saved_at=excluded.saved_at,
          payload=excluded.payload
        """, (daily_id, rec.get("date", ""), rec.get("rep", ""), rec.get("savedAt", ""), json.dumps(rec, ensure_ascii=False)))
    return {"ok": True, "id": daily_id, "data": rec}

@app.delete("/api/dailies/{daily_id}")
def delete_daily(daily_id: str, admin=Depends(require_admin)):
    with conn() as c:
        c.execute("DELETE FROM dailies WHERE id=?", (daily_id,))
    return {"ok": True}

@app.get("/api/private-expenses")
def list_private_expenses(user=Depends(current_user)):
    with conn() as c:
        rows = c.execute(
            "SELECT payload FROM private_expenses WHERE created_by=? ORDER BY expense_date DESC, saved_at DESC",
            (user["username"],)
        ).fetchall()
    return [json.loads(r["payload"]) for r in rows]

@app.put("/api/private-expenses/{expense_id}")
def upsert_private_expense(expense_id: str, body: PrivateExpense, user=Depends(current_user)):
    rec = dict(body.data)
    if str(rec.get("id")) != expense_id:
        raise HTTPException(400, "private expense id mismatch")
    expense_date = str(rec.get("date") or "").strip()
    name = str(rec.get("name") or "").strip()
    try:
        amount = float(rec.get("amount") or 0)
    except (TypeError, ValueError):
        raise HTTPException(400, "مبلغ المصروف غير صالح")
    if not expense_date or not name or amount <= 0:
        raise HTTPException(400, "التاريخ واسم المصروف والمبلغ مطلوبة")

    now_iso = str(rec.get("savedAt") or "").strip()
    if not now_iso:
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with conn() as c:
        existing = c.execute(
            "SELECT created_by,payload FROM private_expenses WHERE id=?", (expense_id,)
        ).fetchone()
        if existing and existing["created_by"] != user["username"]:
            raise HTTPException(403, "لا تملك صلاحية تعديل هذا المصروف")

        created_by = existing["created_by"] if existing else user["username"]
        rec["date"] = expense_date
        rec["name"] = name
        rec["amount"] = amount
        rec["savedAt"] = now_iso
        rec["createdBy"] = created_by
        rec["updatedBy"] = user["username"]
        if not rec.get("createdAt"):
            if existing:
                try:
                    old = json.loads(existing["payload"])
                    rec["createdAt"] = old.get("createdAt") or old.get("savedAt") or now_iso
                except Exception:
                    rec["createdAt"] = now_iso
            else:
                rec["createdAt"] = now_iso

        c.execute("""
        INSERT INTO private_expenses(id,expense_date,name,amount,created_by,saved_at,payload)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          expense_date=excluded.expense_date,
          name=excluded.name,
          amount=excluded.amount,
          saved_at=excluded.saved_at,
          payload=excluded.payload
        """, (expense_id, expense_date, name, amount, created_by, now_iso, json.dumps(rec, ensure_ascii=False)))
    return {"ok": True, "id": expense_id, "data": rec}

@app.delete("/api/private-expenses/{expense_id}")
def delete_private_expense(expense_id: str, user=Depends(current_user)):
    with conn() as c:
        row = c.execute("SELECT created_by FROM private_expenses WHERE id=?", (expense_id,)).fetchone()
        if not row:
            return {"ok": True}
        if row["created_by"] != user["username"]:
            raise HTTPException(403, "لا تملك صلاحية حذف هذا المصروف")
        c.execute("DELETE FROM private_expenses WHERE id=?", (expense_id,))
    return {"ok": True}

@app.get("/")
def root():
    return FileResponse(STATIC / "index.html")

app.mount("/static", StaticFiles(directory=STATIC), name="static")
