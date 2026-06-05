#!/usr/bin/env python3
"""
pf_kerio_sso_bridge.py  (multi-Kerio + web GUI)
-----------------------------------------------
Bridge between PacketFence's generic "JSONRPC" Firewall SSO module and one or
more Kerio Control firewalls (Administration API: ActiveHosts.login/.logout).

Two things on one port:
  POST /            -> PacketFence JSON-RPC endpoint (methods Start / Stop)
                       auth: HTTP Basic with BRIDGE_USER / BRIDGE_PASS
  GET  /            -> management GUI (add / remove / test Kerio targets)
  /api/*            -> GUI backend
                       auth: HTTP Basic with ADMIN_USER / ADMIN_PASS

On a PacketFence "Start" the bridge finds, among the configured Kerios, the one
whose Active Hosts list contains the device IP, then logs out + logs in that
host so Kerio applies per-USERNAME policy/logging. "Stop" logs the host out.

Kerio targets are stored in CONFIG_PATH (JSON) so they survive restarts.

Requirements per Kerio (same as before): Kerio must be the L3 gateway for the
user VLAN (host appears in Active Hosts), the username must be a real Kerio
user, and the API account needs admin rights.

DIY / unsupported. Test in a lab first.
"""

import base64
import ipaddress
import json
import os
import ssl
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- config (env)
CONFIG_PATH = os.getenv("CONFIG_PATH", "/data/kerios.json")
BRIDGE_USER = os.getenv("BRIDGE_USER", "packetfence")   # PacketFence -> bridge
BRIDGE_PASS = os.getenv("BRIDGE_PASS", "change-me")
ADMIN_USER  = os.getenv("ADMIN_USER", "admin")          # GUI login
ADMIN_PASS  = os.getenv("ADMIN_PASS", "change-me-too")
LISTEN_ADDR = os.getenv("LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9090"))
CERT_FILE   = os.getenv("CERT_FILE", "")
KEY_FILE    = os.getenv("KEY_FILE", "")
# Host may not be in Kerio Active Hosts the instant PacketFence fires Start/Update,
# so retry the lookup a few times before giving up.
RETRY_TRIES = int(os.getenv("RETRY_TRIES", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "2"))


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- Kerio client
class KerioError(Exception):
    def __init__(self, err):
        self.code = err.get("code")
        self.message = err.get("message", "")
        super().__init__(f"[{self.code}] {self.message}")


class KerioClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._token = None
        self._cookie = None
        self._id = 0
        self._ctx = ssl.create_default_context()
        if not cfg.get("verify"):
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    @property
    def url(self):
        return f"https://{self.cfg['host']}:{self.cfg.get('port', 4081)}/admin/api/jsonrpc/"

    def user_name(self, name):
        return f"{self.cfg.get('prefix','')}{name}{self.cfg.get('suffix','')}"

    def _raw(self, method, params, auth=True):
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-Token"] = self._token
            if self._cookie:
                headers["Cookie"] = self._cookie
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        resp = urllib.request.urlopen(req, context=self._ctx, timeout=15)
        sc = resp.headers.get("Set-Cookie")
        if sc:
            self._cookie = sc.split(";", 1)[0]
        body = json.loads(resp.read().decode())
        if body.get("error"):
            raise KerioError(body["error"])
        return body.get("result", {})

    def _login(self):
        self._cookie = None
        r = self._raw("Session.login", {
            "userName": self.cfg["user"], "password": self.cfg["password"],
            "application": {"name": "pf-kerio-sso-bridge", "vendor": "custom", "version": "2.0"}
        }, auth=False)
        self._token = r.get("token")
        if not self._token:
            raise RuntimeError("login returned no token")

    def call(self, method, params):
        with self._lock:
            if not self._token:
                self._login()
            try:
                return self._raw(method, params)
            except KerioError as e:
                if e.code == -32001:           # session expired -> relogin once
                    self._login()
                    return self._raw(method, params)
                raise

    def host_id_by_ip(self, ip):
        q = {"fields": [], "conditions": [], "combining": "Or",
             "start": 0, "limit": 100000, "orderBy": []}
        r = self.call("ActiveHosts.get", {"query": q, "refresh": True})
        for h in r.get("list", []):
            if h.get("ip") == ip:
                return h.get("id")
        return None

    def logout(self, host_id):
        self.call("ActiveHosts.logout", {"ids": [host_id]})

    def login_user(self, host_id, user):
        self.call("ActiveHosts.login", {"hostId": host_id, "userName": self.user_name(user)})

    def test(self):
        """Read-only connectivity check: login + active host count."""
        with self._lock:
            self._login()
            q = {"fields": [], "conditions": [], "combining": "Or",
                 "start": 0, "limit": 1, "orderBy": []}
            r = self._raw("ActiveHosts.get", {"query": q, "refresh": True})
            return r.get("totalItems", 0)


# ---------------------------------------------------------------- registry
class Registry:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.entries = {}          # id -> cfg dict
        self.clients = {}          # id -> KerioClient
        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                for e in json.load(f):
                    self.entries[e["id"]] = e
        except FileNotFoundError:
            pass
        except Exception as ex:
            log(f"[registry] load error: {ex}")
        self._rebuild_clients()

    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(list(self.entries.values()), f, indent=2)
        os.replace(tmp, self.path)

    def _rebuild_clients(self):
        self.clients = {i: KerioClient(e) for i, e in self.entries.items()}

    def public_list(self):
        out = []
        for e in self.entries.values():
            o = {k: e.get(k) for k in
                 ("id", "name", "host", "port", "user", "verify", "prefix", "suffix", "subnets", "enabled")}
            o["hasPassword"] = bool(e.get("password"))
            out.append(o)
        return out

    def upsert(self, data):
        with self._lock:
            eid = data.get("id") or uuid.uuid4().hex[:8]
            existing = self.entries.get(eid, {})
            entry = {
                "id": eid,
                "name": data.get("name", "").strip() or eid,
                "host": data.get("host", "").strip(),
                "port": int(data.get("port") or 4081),
                "user": data.get("user", "").strip(),
                "password": data.get("password") or existing.get("password", ""),
                "verify": bool(data.get("verify", False)),
                "prefix": data.get("prefix", ""),
                "suffix": data.get("suffix", ""),
                "subnets": [s.strip() for s in (data.get("subnets") or []) if s.strip()],
                "enabled": bool(data.get("enabled", True)),
            }
            self.entries[eid] = entry
            self._save()
            self._rebuild_clients()
            return eid

    def delete(self, eid):
        with self._lock:
            self.entries.pop(eid, None)
            self._save()
            self._rebuild_clients()

    def candidates_for_ip(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        result = []
        for eid, e in self.entries.items():
            if not e.get("enabled"):
                continue
            subs = e.get("subnets") or []
            if subs and addr is not None:
                in_any = False
                for s in subs:
                    try:
                        if addr in ipaddress.ip_network(s, strict=False):
                            in_any = True
                            break
                    except ValueError:
                        continue
                if not in_any:
                    continue
            result.append((eid, self.clients[eid]))
        return result


REG = Registry(CONFIG_PATH)

# optional one-time seed from old single-Kerio env vars
if not REG.entries and os.getenv("KERIO_HOST"):
    REG.upsert({"name": "seed", "host": os.getenv("KERIO_HOST"),
                "port": os.getenv("KERIO_PORT", "4081"), "user": os.getenv("KERIO_USER", ""),
                "password": os.getenv("KERIO_PASS", ""),
                "prefix": os.getenv("USER_DOMAIN_PREFIX", ""),
                "suffix": os.getenv("USER_DOMAIN_SUFFIX", "")})


# ---------------------------------------------------------------- SSO logic
def sso_start(ip, user):
    if not ip or not user:
        return "missing ip or user"
    tried = REG.candidates_for_ip(ip)
    if not tried:
        return "no kerio targets configured for this ip"
    for attempt in range(RETRY_TRIES):
        for eid, client in tried:
            try:
                hid = client.host_id_by_ip(ip)
            except Exception as ex:
                log(f"[start] {client.cfg['name']} get error: {ex}")
                continue
            if hid:
                try:
                    client.logout(hid)
                except Exception:
                    pass
                try:
                    client.login_user(hid, user)
                except Exception as ex:
                    return f"login failed on {client.cfg['name']}: {ex}"
                log(f"[start] {ip} -> {client.user_name(user)} on '{client.cfg['name']}'")
                return None
        if attempt < RETRY_TRIES - 1:
            time.sleep(RETRY_DELAY)
    return f"no active host for ip {ip} on any configured kerio"


def sso_stop(ip):
    if not ip:
        return "missing ip"
    for eid, client in REG.candidates_for_ip(ip):
        try:
            hid = client.host_id_by_ip(ip)
            if hid:
                client.logout(hid)
                log(f"[stop] released {ip} on '{client.cfg['name']}'")
        except Exception as ex:
            log(f"[stop] {client.cfg['name']} error: {ex}")
    return None


# ---------------------------------------------------------------- HTTP server
def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


GUI = """<!doctype html><html><head><meta charset=utf-8>
<title>PF \u2192 Kerio SSO Bridge</title>
<style>
body{font:14px system-ui,Segoe UI,Arial;margin:0;background:#f4f5f7;color:#222}
header{background:#2f3640;color:#fff;padding:14px 22px;font-size:18px}
.wrap{max-width:1000px;margin:22px auto;padding:0 16px}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px #0002}
th,td{padding:9px 11px;border-bottom:1px solid #eee;text-align:left;font-size:13px}
th{background:#fafafa}
button{cursor:pointer;border:0;border-radius:4px;padding:6px 11px;font-size:13px}
.b{background:#0b5fff;color:#fff}.d{background:#e23;color:#fff}.t{background:#19a974;color:#fff}
.card{background:#fff;padding:18px;margin-top:18px;box-shadow:0 1px 3px #0002;border-radius:6px}
label{display:block;font-size:12px;color:#555;margin:8px 0 3px}
input{width:100%;padding:7px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.muted{color:#888}.ok{color:#19a974}.err{color:#e23}
.row{display:flex;gap:8px;align-items:center}
</style></head><body>
<header>PacketFence &rarr; Kerio Control &mdash; SSO Bridge</header>
<div class=wrap>
  <table id=tbl><thead><tr><th>Name</th><th>Host:Port</th><th>API user</th>
  <th>Subnets</th><th>Enabled</th><th>Status</th><th></th></tr></thead><tbody></tbody></table>
  <div class=card>
    <h3 id=ftitle>Add Kerio firewall</h3>
    <input type=hidden id=id>
    <div class=grid>
      <div><label>Name</label><input id=name placeholder="Main Office"></div>
      <div><label>Host / IP</label><input id=host placeholder="10.0.0.10"></div>
      <div><label>Port</label><input id=port value=4081></div>
      <div><label>API user</label><input id=user placeholder="sso-api"></div>
      <div><label>API password</label><input id=password type=password placeholder="(unchanged if blank)"></div>
      <div><label>Username prefix (e.g. EXAMPLE\\)</label><input id=prefix></div>
      <div><label>Username suffix (e.g. @example.local)</label><input id=suffix></div>
      <div><label>Subnets (CIDR, comma-sep, blank = any)</label><input id=subnets placeholder="10.0.0.0/24"></div>
      <div class=row style="margin-top:22px"><label style="margin:0"><input type=checkbox id=enabled checked style="width:auto"> Enabled</label>
        <label style="margin:0 0 0 14px"><input type=checkbox id=verify style="width:auto"> Verify TLS</label></div>
    </div>
    <div style="margin-top:14px" class=row>
      <button class=b onclick=save()>Save</button>
      <button onclick=resetForm()>Clear</button>
      <span id=msg class=muted></span>
    </div>
  </div>
</div>
<script>
async function api(path,opt){const r=await fetch(path,opt);if(!r.ok)throw new Error(await r.text());return r.json()}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function load(){
  const list=await api('/api/kerios');const tb=document.querySelector('#tbl tbody');tb.innerHTML='';
  for(const k of list){const tr=document.createElement('tr');
    tr.innerHTML=`<td>${esc(k.name)}</td><td>${esc(k.host)}:${k.port}</td><td>${esc(k.user)}</td>
      <td class=muted>${esc((k.subnets||[]).join(', ')||'any')}</td>
      <td>${k.enabled?'yes':'<span class=muted>no</span>'}</td>
      <td id=st_${k.id} class=muted>\u2014</td>
      <td class=row>
        <button class=t onclick="test('${k.id}')">Test</button>
        <button onclick='edit(${JSON.stringify(k)})'>Edit</button>
        <button class=d onclick="del('${k.id}','${esc(k.name)}')">Delete</button></td>`;
    tb.appendChild(tr);}
}
function val(id){return document.getElementById(id).value}
function resetForm(){['id','name','host','user','password','prefix','suffix','subnets'].forEach(i=>document.getElementById(i).value='');
  document.getElementById('port').value=4081;document.getElementById('enabled').checked=true;
  document.getElementById('verify').checked=false;document.getElementById('ftitle').textContent='Add Kerio firewall';
  document.getElementById('msg').textContent=''}
function edit(k){document.getElementById('id').value=k.id;document.getElementById('name').value=k.name;
  document.getElementById('host').value=k.host;document.getElementById('port').value=k.port;
  document.getElementById('user').value=k.user;document.getElementById('prefix').value=k.prefix||'';
  document.getElementById('suffix').value=k.suffix||'';document.getElementById('subnets').value=(k.subnets||[]).join(', ');
  document.getElementById('enabled').checked=k.enabled;document.getElementById('verify').checked=k.verify;
  document.getElementById('ftitle').textContent='Edit: '+k.name;window.scrollTo(0,document.body.scrollHeight)}
async function save(){
  const body={id:val('id')||undefined,name:val('name'),host:val('host'),port:val('port'),
    user:val('user'),password:val('password'),prefix:val('prefix'),suffix:val('suffix'),
    subnets:val('subnets').split(',').map(s=>s.trim()).filter(Boolean),
    enabled:document.getElementById('enabled').checked,verify:document.getElementById('verify').checked};
  try{await api('/api/kerios',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    resetForm();load();}catch(e){document.getElementById('msg').innerHTML='<span class=err>'+esc(''+e)+'</span>'}
}
async function del(id,name){if(!confirm('Delete '+name+'?'))return;
  await api('/api/kerios/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});load()}
async function test(id){const c=document.getElementById('st_'+id);c.textContent='testing...';c.className='muted';
  try{const r=await api('/api/kerios/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
    c.innerHTML='<span class=ok>OK \u00b7 '+r.activeHosts+' hosts</span>';}
  catch(e){c.innerHTML='<span class=err>FAIL</span>';c.title=''+e}}
load();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _auth(self, user, pw):
        return self.headers.get("Authorization") == basic(user, pw)

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="bridge"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, html):
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n).decode()) if n else {}

    # GUI + GUI backend (ADMIN auth)
    def do_GET(self):
        if not self._auth(ADMIN_USER, ADMIN_PASS):
            return self._deny()
        if self.path in ("/", "/ui"):
            return self._html(GUI)
        if self.path == "/api/kerios":
            return self._json(REG.public_list())
        self.send_error(404)

    def do_POST(self):
        # PacketFence JSON-RPC endpoint
        if self.path == "/":
            if not self._auth(BRIDGE_USER, BRIDGE_PASS):
                return self._deny()
            try:
                req = self._body()
            except Exception as e:
                return self._json({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": str(e)}})
            rid, method, p = req.get("id"), req.get("method"), req.get("params", {}) or {}
            try:
                if method in ("Start", "Update"):
                    err = sso_start(p.get("ip"), p.get("user"))
                elif method == "Stop":
                    err = sso_stop(p.get("ip"))
                else:
                    log(f"[rpc] unknown method: {method}")
                    return self._json({"jsonrpc": "2.0", "id": rid,
                                       "error": {"code": -32601, "message": f"unknown method {method}"}})
                return self._json({"jsonrpc": "2.0", "id": rid,
                                   "result": ["OK"] if err is None else [err]})
            except Exception as e:
                log(f"[{method}] {e}")
                return self._json({"jsonrpc": "2.0", "id": rid, "result": [str(e)]})

        # GUI backend (ADMIN auth)
        if not self._auth(ADMIN_USER, ADMIN_PASS):
            return self._deny()
        try:
            data = self._body()
            if self.path == "/api/kerios":
                eid = REG.upsert(data)
                return self._json({"id": eid})
            if self.path == "/api/kerios/delete":
                REG.delete(data.get("id"))
                return self._json({"ok": True})
            if self.path == "/api/kerios/test":
                client = REG.clients.get(data.get("id"))
                if not client:
                    return self._json({"error": "no such kerio"}, 404)
                count = client.test()
                return self._json({"ok": True, "activeHosts": count})
        except Exception as e:
            return self._json({"error": str(e)}, 400)
        self.send_error(404)

    def log_message(self, *a):
        pass


def main():
    httpd = ThreadingHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler)
    if CERT_FILE and KEY_FILE:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http (front with TLS!)"
    log(f"bridge on {scheme}://{LISTEN_ADDR}:{LISTEN_PORT}  | GUI '/' (admin)  | PF JSON-RPC POST '/' (bridge)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
