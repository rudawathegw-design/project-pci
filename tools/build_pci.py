"""build_pci.py — render docs/index.html for the PCI DSS Compliance Cockpit.

The PCI data is AES-GCM encrypted with the site password ("pci"); the page
ships only ciphertext, decrypted in the browser on unlock. Live FIBXPI status
and comments are layered on via the Worker at runtime.
"""
import os, json, base64, secrets, datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "data", "pci_data.json")
OUT  = os.path.join(HERE, "docs", "index.html")

PCI_PASSWORD = os.environ.get("PCI_PASSWORD", "pci")
PBKDF2_ITERATIONS = 300_000
# Worker proxy for live FIBXPI status + comments (set at deploy). Empty = the
# cockpit renders the imported baseline only (no live layer).
GH_PROXY = os.environ.get("PCI_PROXY", "https://project-pci-proxy.rudaw-a-the-gw.workers.dev")

# Box evidence embeds — folders (share links) + the two source workbooks.
EVIDENCE = [
    {"k": "evidences", "t": "Evidence library",  "s": "Screenshots, configs & supporting proofs",
     "url": "https://app.box.com/embed/s/698kt3rxy7akyza01za5lmtr68t6zdq4?sortColumn=date"},
    {"k": "whole",     "t": "Full evidence set",  "s": "Complete shared evidence folder",
     "url": "https://app.box.com/embed/s/cjmt5wsne4qd585uaqfqf2n1jmocx6qx?sortColumn=date"},
    {"k": "gaps",      "t": "Gap report (Excel)", "s": "Assessment findings workbook",
     "url": "https://app.box.com/integrations/officeonline/openOfficeOnline?fileId=2411611826029&sharedAccessCode="},
    {"k": "milestones","t": "Milestones plan (Excel)", "s": "PCI DSS project plan workbook",
     "url": "https://app.box.com/integrations/officeonline/openOfficeOnline?fileId=2243065682000&sharedAccessCode="},
]

def encrypt_payload(plaintext: str, password: str) -> dict:
    salt  = secrets.token_bytes(16); nonce = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(), "iter": PBKDF2_ITERATIONS}

with open(DATA, encoding="utf-8") as f:
    model = json.load(f)
model["generated"] = datetime.datetime.now(datetime.timezone.utc).astimezone(
    datetime.timezone(datetime.timedelta(hours=3))).strftime("%Y-%m-%d %I:%M %p Baghdad")

ENC = encrypt_payload(json.dumps(model, ensure_ascii=False), PCI_PASSWORD)

TEMPLATE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCI DSS Cockpit</title>
<style>
:root{--navy:#0b1f3a;--navy2:#12294b;--ink:#0f172a;--sub:#64748b;--line:#e2e8f0;
  --teal:#0f9389;--teal-d:#0c7a72;--bg:#eef2f6;--card:#fff;--green:#10b981;--amber:#f59e0b;
  --red:#ef4444;--blue:#2563eb;--slate:#94a3b8;}
*{box-sizing:border-box}html{overflow-x:clip}
body{margin:0;font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);
  background:radial-gradient(ellipse 120% 60% at 50% -10%,#e7eef8,transparent 60%),var(--bg);-webkit-font-smoothing:antialiased}
.wrap{max-width:1240px;margin:0 auto;padding:clamp(14px,2.2vw,30px);overflow-x:clip}
h1,h2,h3{margin:0}a{color:var(--teal-d)}
#gate{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:#f4f7fa;overflow:hidden}
#gate::before{content:"";position:absolute;inset:0;opacity:1;background-image:radial-gradient(ellipse 90% 55% at 50% -10%,#e3edf7,transparent 60%),linear-gradient(#0b1f3a08 1px,transparent 1px),linear-gradient(90deg,#0b1f3a08 1px,transparent 1px);background-size:auto,42px 42px,42px 42px}
.gate-card{position:relative;background:#fff;border:1px solid var(--line);border-radius:20px;padding:34px;width:min(400px,92vw);color:#0f172a;box-shadow:0 30px 70px rgba(15,31,58,.14)}
.gate-badge{font-size:11px;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:var(--teal-d)}
.gate-title{font-size:23px;font-weight:800;margin-top:8px;color:#0b1f3a}
.gate-sub{color:#64748b;font-size:13.5px;margin-top:8px;line-height:1.5}
.gate-inp{width:100%;margin-top:18px;border:1.5px solid #e2e8f0;background:#fff;color:#0f172a;border-radius:11px;padding:13px 15px;font-size:15px;outline:none;letter-spacing:2px}
.gate-inp:focus{border-color:var(--teal)}
.gate-btn{width:100%;margin-top:12px;border:none;border-radius:11px;padding:13px;font-weight:800;font-size:15px;color:#fff;background:linear-gradient(90deg,#0f9389,#0c7a72);cursor:pointer}
.gate-btn:disabled{opacity:.7;cursor:wait}
.gate-err{color:#dc2626;font-size:12.5px;height:16px;margin-top:8px}
.gate-foot{color:#94a3b8;font-size:11px;margin-top:18px}
#intro{position:fixed;inset:0;z-index:900;background:#04101f;display:none;overflow:hidden}
#intro video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
#intro .veil{position:absolute;inset:0;background:linear-gradient(180deg,rgba(4,16,31,.15),rgba(4,16,31,.75))}
#intro .cap{position:absolute;left:0;right:0;bottom:12%;text-align:center;color:#fff;font-weight:800;font-size:clamp(22px,4vw,40px);letter-spacing:-.01em;text-shadow:0 4px 30px rgba(0,0,0,.5);opacity:0;animation:capIn 1s ease .5s forwards}
#intro .cap small{display:block;font-size:13px;font-weight:700;letter-spacing:3px;color:#5eead4;text-transform:uppercase;margin-bottom:8px}
@keyframes capIn{to{opacity:1}}
#intro .skip{position:absolute;top:16px;right:18px;color:#cbd5e1;background:rgba(0,0,0,.35);border:1px solid #ffffff33;border-radius:8px;padding:7px 12px;font-size:12px;font-weight:700;cursor:pointer}
#app{display:none}
.top{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:13px}
.brand-mark{width:44px;height:44px;border-radius:12px;background:linear-gradient(145deg,#0f9389,#0b1f3a);display:grid;place-items:center;color:#fff;font-weight:900;font-size:15px}
.brand-t{font-size:19px;font-weight:800;letter-spacing:-.01em}
.brand-s{font-size:12px;color:var(--sub);font-weight:600}
.gen{font-size:11px;color:var(--slate);font-weight:600;text-align:right}
.hero{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:14px;margin-bottom:20px}
@media(max-width:820px){.hero{grid-template-columns:1fr}}
.hcard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px}
.hcard.dark{background:linear-gradient(150deg,#0b1f3a,#12294b);color:#fff;border:none}
.hlbl{font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8}
.hcard.dark .hlbl{color:#8fb0d8}
.hbig{font-size:46px;font-weight:900;letter-spacing:-.03em;line-height:1;margin-top:8px}
.hsub{font-size:12.5px;color:var(--sub);margin-top:8px}.hcard.dark .hsub{color:#b7c6dc}
.ring{--p:0;width:104px;height:104px;border-radius:50%;background:conic-gradient(#2dd4bf calc(var(--p)*1%),rgba(255,255,255,.12) 0);display:grid;place-items:center;margin-top:6px}
.ring i{width:80px;height:80px;border-radius:50%;background:#0b1f3a;display:grid;place-items:center;font-style:normal;font-weight:900;font-size:22px}
.hflex{display:flex;align-items:center;gap:16px}
.sec{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:20px}
.sec-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.sec-t{font-size:15px;font-weight:800}.sec-t small{color:var(--sub);font-weight:600;font-size:12px;margin-left:6px}
.journey{position:relative;display:flex;overflow-x:auto;padding:6px 2px 4px}
.jp{flex:1 0 150px;min-width:150px;position:relative;padding:0 6px}
.jp .bar{height:6px;border-radius:999px;background:#e2e8f0;position:relative;margin-bottom:12px}
.jp .bar i{position:absolute;inset:0;border-radius:999px;background:var(--green);width:0}
.jp .dot{position:absolute;top:-4px;left:50%;transform:translateX(-50%);width:26px;height:26px;border-radius:50%;background:#fff;border:3px solid #cbd5e1;display:grid;place-items:center;font-size:11px;font-weight:900;color:#64748b;z-index:2}
.jp.done .dot{border-color:var(--green);color:var(--green)}
.jp.active .dot{border-color:var(--teal);color:var(--teal);box-shadow:0 0 0 5px rgba(15,147,137,.15)}
.jp.done .bar i{background:var(--green)}.jp.active .bar i{background:var(--teal)}
.jp-name{font-size:12.5px;font-weight:700;color:#334155;line-height:1.3}
.jp-meta{font-size:11px;color:var(--slate);margin-top:3px}.jp.active .jp-name{color:var(--teal-d)}
.gaps{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.gcard{border:1px solid var(--line);border-radius:13px;padding:15px 16px;cursor:pointer;background:#fff;transition:.15s}
.gcard:hover{border-color:var(--teal);box-shadow:0 6px 20px rgba(15,147,137,.12);transform:translateY(-1px)}
.gc-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.gc-name{font-size:13.5px;font-weight:800}.gc-pct{font-size:13px;font-weight:900}
.gc-bar{height:8px;border-radius:999px;background:#eef2f6;margin:11px 0 9px;overflow:hidden}
.gc-bar i{display:block;height:100%;border-radius:999px}
.gc-meta{display:flex;gap:12px;font-size:11.5px;color:var(--sub);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:5px;font-weight:700}.pill b{font-weight:900}
.dot-o{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block}
.dot-c{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block}
.ev-row{display:flex;gap:12px;flex-wrap:wrap}
.ev-btn{flex:1 0 200px;border:1px solid var(--line);border-radius:12px;padding:16px 18px;background:#f8fbfd;cursor:pointer;text-align:left}
.ev-btn:hover{border-color:var(--teal);background:#f0faf9}
.ev-btn .t{font-weight:800;font-size:14px}.ev-btn .s{font-size:12px;color:var(--sub);margin-top:3px}
.ov{position:fixed;inset:0;background:rgba(11,31,58,.55);backdrop-filter:blur(5px);z-index:1100;display:none;align-items:center;justify-content:center;padding:20px}
.ov.show{display:flex}
.modal{background:#fff;border-radius:18px;width:min(940px,96vw);max-height:90vh;display:flex;flex-direction:column;overflow:hidden}
.modal.wide{width:min(1000px,97vw)}
.modal.full{width:100vw;height:100vh;max-height:100vh;border-radius:0}
.modal.full .m-body{flex:1}
.modal.full iframe{height:calc(100vh - 60px)!important}
.m-head{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:10px}
.m-head h3{font-size:16px;font-weight:800}
.m-close{border:1px solid var(--line);background:#fff;border-radius:9px;padding:8px 14px;font-weight:700;cursor:pointer}
.m-body{padding:8px 22px 22px;overflow-y:auto}
.m-body.flush{padding:0}
.finding{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-top:12px}
.f-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.f-sec{font-weight:800;font-size:13.5px}
.tag{font-size:10.5px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;padding:2px 9px;border-radius:999px}
.tag.open{background:#fee2e2;color:#b91c1c}.tag.closed{background:#dcfce7;color:#166534}.tag.fib{background:#dbeafe;color:#1e40af}
.f-row{font-size:13px;color:#334155;line-height:1.55;margin-top:6px}.f-row b{color:#0f172a}
.f-links{margin-top:10px;display:flex;gap:10px;flex-wrap:wrap}
.f-links a{font-size:12px;font-weight:700;text-decoration:none;background:#f1f5f9;padding:6px 11px;border-radius:8px}
.cbtn{font-size:12px;font-weight:700;border:1px solid var(--line);background:#fff;padding:6px 11px;border-radius:8px;cursor:pointer;color:var(--teal-d)}
.cbtn:hover{background:#f0faf9;border-color:var(--teal)}
.live-grid{display:grid;gap:6px}
.live-row{display:grid;grid-template-columns:100px 1fr auto auto;gap:12px;align-items:center;padding:9px 12px;border:1px solid var(--line);border-radius:10px;text-decoration:none;color:inherit;background:#fff}
.live-row:hover{border-color:var(--red);background:#fff7f7}
.lr-key{font-weight:800;font-size:12px;color:var(--teal-d);font-family:ui-monospace,monospace}
.lr-sum{font-size:13px;color:#334155;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lr-st{font-size:11px;font-weight:700;color:#64748b}
.lr-days{font-size:12px;font-weight:800;color:var(--red);white-space:nowrap}
@media(max-width:640px){.live-row{grid-template-columns:80px 1fr auto}.lr-st{display:none}}
.foot{color:var(--slate);font-size:11.5px;text-align:center;margin:24px 0 8px}
/* Assessment timeline (Jira epic) */
.tl{display:flex;overflow-x:auto;padding:16px 4px 8px}
.tl-node{flex:1 0 158px;min-width:158px;position:relative;padding:28px 8px 0;text-align:center;cursor:pointer}
.tl-node::before{content:"";position:absolute;top:13px;left:0;right:0;height:4px;background:#e2e8f0}
.tl-node:first-child::before{left:50%}.tl-node:last-child::before{right:50%}
.tl-node.done::before{background:var(--green)}
.tl-dot{position:absolute;top:4px;left:50%;transform:translateX(-50%);width:22px;height:22px;border-radius:50%;background:#fff;border:3px solid #cbd5e1;z-index:2;display:grid;place-items:center;font-size:11px;font-weight:900;color:#94a3b8}
.tl-node.done .tl-dot{background:var(--green);border-color:var(--green);color:#fff}
.tl-node.prog .tl-dot{background:var(--teal);border-color:var(--teal);color:#fff}
.tl-node.over .tl-dot{background:var(--red);border-color:var(--red);color:#fff}
.tl-key{font-family:ui-monospace,monospace;font-size:11px;font-weight:800;color:var(--teal-d)}
.tl-name{font-size:11.5px;color:#334155;line-height:1.25;margin-top:3px;height:29px;overflow:hidden}
.tl-due{font-size:10.5px;font-weight:800;margin-top:5px;color:var(--slate)}
.tl-node.over .tl-due{color:var(--red)}
.tl-node:hover .tl-name{color:var(--teal-d)}
.legend{display:flex;gap:14px;font-size:11px;color:var(--sub);font-weight:600}
.legend i{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:4px;vertical-align:middle}
/* Owners */
.own-row{display:grid;grid-template-columns:150px 1fr 90px;gap:12px;align-items:center;padding:8px 2px}
.own-name{font-size:13px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.own-bar{height:9px;border-radius:999px;background:#eef2f6;overflow:hidden}
.own-bar i{display:block;height:100%;border-radius:999px;background:var(--green)}
.own-meta{font-size:11.5px;color:var(--sub);font-weight:700;text-align:right}
.own-meta b.over{color:var(--red)}
/* task modal */
.tm-row{font-size:13.5px;color:#334155;margin-top:8px;line-height:1.5}.tm-row b{color:#0f172a}
/* remediation strip */
.strip{display:flex;align-items:center;gap:16px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 18px;margin-bottom:18px;flex-wrap:wrap}
.strip-pct{display:flex;flex-direction:column;line-height:1}.strip-pct span{font-size:30px;font-weight:900;letter-spacing:-.02em;color:var(--teal-d)}
.strip-pct small{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--slate);margin-top:4px}
.strip-bar{flex:1 1 200px;height:12px;border-radius:999px;background:#eef2f6;overflow:hidden;min-width:160px}
.strip-bar i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#0f9389,#10b981);width:0;transition:width .6s}
.strip-nums{display:flex;gap:16px;flex-wrap:wrap}.sn{font-size:12.5px;color:var(--sub);font-weight:600}.sn b{font-weight:900;color:#0f172a}
/* filters */
.filters{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.f-search{flex:1 1 240px;min-width:180px;border:1.5px solid var(--line);border-radius:10px;padding:9px 13px;font-size:13.5px;outline:none}
.f-search:focus{border-color:var(--teal)}
.f-sel{border:1.5px solid var(--line);border-radius:10px;padding:9px 12px;font-size:13px;background:#fff;outline:none;cursor:pointer}
/* worklist table */
.wl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
.wl{width:100%;border-collapse:collapse;font-size:13px;min-width:720px}
.wl th{text-align:left;font-size:10.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);padding:11px 14px;background:#f8fafc;border-bottom:1px solid var(--line);position:sticky;top:0}
.wl td{padding:12px 14px;border-bottom:1px solid #eef2f6;vertical-align:top}
.wl tr:last-child td{border-bottom:none}
.wl tr.f-open{cursor:pointer}.wl tr.f-open:hover td{background:#f8fbfd}
.wl-area{font-weight:700;color:#334155;font-size:12.5px}
.wl-obs{color:#0f172a;line-height:1.45}.wl-ev{color:var(--sub);font-size:12px;margin-top:4px}
.wl-ev b{color:#475569;font-weight:700}
.wl-tk a{font-family:ui-monospace,monospace;font-size:11.5px;font-weight:800;text-decoration:none;background:#eef2ff;color:#3730a3;padding:3px 8px;border-radius:7px;white-space:nowrap}
.wl-tk .none{color:#cbd5e1;font-size:11px}
.wl-more{display:none}.wl tr.exp .wl-more{display:block;margin-top:9px;padding-top:9px;border-top:1px dashed #e2e8f0}
.wl-more .m1{font-size:12.5px;color:#334155;line-height:1.5;margin-top:5px}.wl-more .m1 b{color:#0f172a}
.wl-acts{margin-top:9px;display:flex;gap:8px;flex-wrap:wrap}
.st-tag{font-size:10.5px;font-weight:800;letter-spacing:.03em;text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap;display:inline-block}
.st-tag.open{background:#fee2e2;color:#b91c1c}.st-tag.closed{background:#dcfce7;color:#166534}.st-tag.na{background:#f1f5f9;color:#64748b}
.fib-tag{font-size:11px;font-weight:700;color:#475569}
/* jira reference */
.jref{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}
.jr{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-radius:11px;padding:10px 13px}
.jr-key{font-family:ui-monospace,monospace;font-size:11.5px;font-weight:800;color:var(--teal-d);text-decoration:none;white-space:nowrap}
.jr-sum{flex:1;font-size:12.5px;color:#334155;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.jr-st{font-size:10.5px;font-weight:800;padding:2px 8px;border-radius:999px;white-space:nowrap}
.jr-st.done{background:#dcfce7;color:#166534}.jr-st.prog{background:#fef3c7;color:#92400e}.jr-st.over{background:#fee2e2;color:#b91c1c}
</style></head>
<body>
<div id="gate"><div class="gate-card">
  <div class="gate-badge">First Iraq Bank · Compliance</div>
  <div class="gate-title">PCI DSS Cockpit</div>
  <div class="gate-sub">Enter the access password to open the live compliance cockpit.</div>
  <input id="gate-inp" class="gate-inp" type="password" placeholder="Password" autocomplete="off">
  <button class="gate-btn" id="gate-btn" onclick="unlock()">Open cockpit →</button>
  <div class="gate-err" id="gate-err"></div>
  <div class="gate-foot">Encrypted end-to-end · authorized personnel only</div>
</div></div>
<div id="intro">
  <video id="introv" src="intro.mp4" playsinline preload="auto"></video>
  <div class="veil"></div>
  <div class="cap"><small>First Iraq Bank</small>PCI DSS Compliance Cockpit</div>
  <button class="skip" onclick="endIntro()">Skip ›</button>
</div>
<div id="app"><div class="wrap">
  <div class="top">
    <div class="brand"><div class="brand-mark">PCI</div>
      <div><div class="brand-t">PCI DSS Compliance Cockpit</div><div class="brand-s" id="proj"></div></div></div>
    <div class="gen" id="gen"></div>
  </div>
  <!-- compact remediation strip -->
  <div class="strip">
    <div class="strip-pct"><span id="gap-pct">0%</span><small>remediated</small></div>
    <div class="strip-bar"><i id="gap-barfill"></i></div>
    <div class="strip-nums">
      <span class="sn"><b id="sn-closed">0</b> closed</span>
      <span class="sn"><b id="sn-open" style="color:var(--red)">0</b> open</span>
      <span class="sn"><b id="sn-total">0</b> findings</span>
      <span class="sn" id="gap-src">—</span>
    </div>
  </div>
  <!-- findings worklist -->
  <div class="sec">
    <div class="sec-h"><div class="sec-t">Findings worklist <small id="wl-count"></small></div></div>
    <div class="filters">
      <input id="f-search" class="f-search" placeholder="Search findings, evidence, ticket…" oninput="renderWorklist()">
      <select id="f-status" class="f-sel" onchange="renderWorklist()">
        <option value="">All statuses</option><option value="Open">Open only</option><option value="Closed">Closed only</option></select>
      <select id="f-area" class="f-sel" onchange="renderWorklist()"><option value="">All areas</option></select>
    </div>
    <div class="wl-wrap"><table class="wl" id="wl"><thead><tr>
      <th style="width:150px">Area</th><th>Finding &amp; evidence required</th>
      <th style="width:112px">Ticket</th><th style="width:96px">Assessor</th><th style="width:118px">FIB status</th>
    </tr></thead><tbody id="wl-body"><tr><td colspan="5" style="color:#94a3b8;padding:16px">Loading live from Box…</td></tr></tbody></table></div>
  </div>
  <!-- Jira team-evidence tickets (compact side reference) -->
  <div class="sec" id="jira-sec" style="display:none"><div class="sec-h"><div class="sec-t">Team evidence tickets <small id="jira-sub">Jira epic FIBXPI-49</small></div></div>
    <div class="jref" id="jref"></div></div>
  <div class="sec"><div class="sec-h"><div class="sec-t">Documents &amp; evidence <small>opens full-screen from Box</small></div></div>
    <div class="ev-row" id="ev-row"></div>
  </div>
  <div class="foot">First Iraq Bank · PCI DSS Compliance Cockpit · generated <span id="gen2"></span></div>
</div></div>
<div class="ov" id="ov" onclick="if(event.target===this)closeOv()"><div class="modal" id="ov-modal">
  <div class="m-head"><h3 id="ov-title">Area</h3><button class="m-close" onclick="closeOv()">Close</button></div>
  <div class="m-body" id="ov-body"></div>
</div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
<script>
const ENC = /*__ENC__*/{};
const EVIDENCE = /*__EVIDENCE__*/{};
const GH_PROXY = "__GH_PROXY__";
let PCI = null, GAPS = null, EPIC = [];
const esc = s => { const d=document.createElement('div'); d.textContent=(s==null?'':String(s)); return d.innerHTML; };
function _b64dec(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
async function _deriveKey(pw, salt, iter){
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:iter, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
}
async function decryptBlob(blob, pw){
  const key = await _deriveKey(pw, _b64dec(blob.salt), blob.iter);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:_b64dec(blob.nonce)}, key, _b64dec(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function unlock(){
  const inp=document.getElementById('gate-inp'), err=document.getElementById('gate-err'), btn=document.getElementById('gate-btn');
  const pw=(inp.value||'').trim().toLowerCase();
  if(!pw){ err.textContent='Enter the password.'; return; }
  btn.disabled=true; err.textContent='Decrypting…';
  try{
    PCI = await decryptBlob(ENC, pw);
    sessionStorage.setItem('pci_pw', pw);
    document.getElementById('gate').style.display='none';
    render(); playIntro();
  }catch(e){ err.textContent='Incorrect password.'; btn.disabled=false; }
}
document.getElementById('gate-inp').addEventListener('keydown',e=>{if(e.key==='Enter')unlock();});
function playIntro(){
  const wrap=document.getElementById('intro'), v=document.getElementById('introv'); wrap.style.display='block';
  let done=false; const fin=()=>{ if(done)return; done=true; endIntro(); };
  v.play().catch(()=>{}); v.addEventListener('ended',fin); setTimeout(fin,9000);
}
function endIntro(){ const w=document.getElementById('intro'); w.style.transition='opacity .5s'; w.style.opacity='0';
  setTimeout(()=>{ w.style.display='none'; document.getElementById('app').style.display='block'; },500); }
function statusColor(p){ return p>=80?'var(--green)':p>=40?'var(--amber)':'var(--red)'; }
function jiraKey(u){ const m=/([A-Z]+-\d+)/.exec(u||''); return m?m[1]:''; }
const TODAY=new Date().toISOString().slice(0,10);
function daysLate(due){ return Math.round((Date.now()-new Date(due).getTime())/86400000); }

function render(){
  document.getElementById('proj').textContent=PCI.project||'';
  document.getElementById('gen').textContent='Updated '+(PCI.generated||'');
  document.getElementById('gen2').textContent=PCI.generated||'';
  document.getElementById('app').style.display='block';
  document.getElementById('ev-row').innerHTML=EVIDENCE.map(e=>`<div class="ev-btn" onclick="openEvidence('${e.k}')"><div class="t">${esc(e.t)}</div><div class="s">${esc(e.s)}</div></div>`).join('');
  loadGaps();   // live gap workbook from Box → remediation bar + area cards
  loadEpic();   // live Jira epic FIBXPI-49 → timeline + overdue + owners
}

// ── Parse the Box gap workbook (SheetJS) into {summary, areas[]} ──
function parseGaps(wb){
  const norm=s=>String(s==null?'':s).replace(/\s+/g,' ').trim();
  const rowsOf=ws=>XLSX.utils.sheet_to_json(ws,{header:1,defval:''});
  const areas=[]; let summary={open:0,closed:0,total:0,pct:0}; const byName={};
  const sumName=wb.SheetNames.find(n=>/summary/i.test(n));
  if(sumName){
    let started=false;
    for(const r of rowsOf(wb.Sheets[sumName])){
      const a=norm(r[0]);
      if(!started){ if(/^review sheet$/i.test(a)) started=true; continue; }
      if(!a) continue;
      const open=+r[1]||0, closed=+r[2]||0, total=+r[3]||0, pct=total?Math.round(100*closed/total):0;
      if(/^total$/i.test(a)){ summary={open,closed,total,pct}; continue; }
      const area={name:a,open,closed,total,pct,findings:[]}; areas.push(area); byName[a.toLowerCase()]=area;
    }
  }
  for(const sn of wb.SheetNames){
    if(/summary/i.test(sn)) continue;
    const rows=rowsOf(wb.Sheets[sn]);
    let hi=-1; for(let i=0;i<rows.length;i++){ if(rows[i].some(c=>/^sr\.?\s*no/i.test(norm(c)))){ hi=i; break; } }
    if(hi<0) continue;
    const hdr=rows[hi].map(c=>norm(c).toLowerCase());
    const col=(...names)=>{ for(let j=0;j<hdr.length;j++) if(names.some(nm=>hdr[j].includes(nm))) return j; return -1; };
    const ci={section:col('section'),obs:col('observation'),rec:col('recommendation'),ev:col('evidence req','evidence'),status:col('status'),assessor:col('assessor'),client:col('client comment'),fib:col('fib status'),link:col('link')};
    const findings=[];
    for(const r of rows.slice(hi+1)){
      const section=ci.section>=0?norm(r[ci.section]):'', obs=ci.obs>=0?norm(r[ci.obs]):'';
      if(!section&&!obs) continue;
      const stRaw=ci.status>=0?norm(r[ci.status]).toLowerCase():'';
      const status=stRaw.includes('clos')?'Closed':(stRaw.includes('open')?'Open':(ci.status>=0?norm(r[ci.status]):''));
      let jira=ci.link>=0&&/atlassian/.test(norm(r[ci.link]))?norm(r[ci.link]):'';
      if(!jira) for(const c of r){ const s=norm(c); if(/atlassian\.net\/browse\//.test(s)){ jira=s; break; } }
      findings.push({section,observation:obs,recommendation:ci.rec>=0?norm(r[ci.rec]):'',
        evidence_required:ci.ev>=0?norm(r[ci.ev]):'',status,fib_status:ci.fib>=0?norm(r[ci.fib]):'',
        assessor_comments:ci.assessor>=0?norm(r[ci.assessor]):'',client_comments:ci.client>=0?norm(r[ci.client]):'',jira});
    }
    const key=norm(sn).toLowerCase();
    let area=byName[key]||areas.find(a=>key.startsWith(a.name.toLowerCase())||a.name.toLowerCase().startsWith(key));
    if(area){ area.findings=findings; }
    else{ const o=findings.filter(f=>f.status==='Open').length,c=findings.filter(f=>f.status==='Closed').length,t=findings.length;
      areas.push({name:norm(sn),open:o,closed:c,total:t,pct:t?Math.round(100*c/t):0,findings}); }
  }
  return {summary,areas};
}
async function loadGaps(){
  const pw=sessionStorage.getItem('pci_pw')||'', src=document.getElementById('gap-src');
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'gaps'})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    GAPS=parseGaps(XLSX.read(await r.arrayBuffer(),{type:'array'}));
    src.textContent='● live from Box'; src.style.color='var(--teal-d)';
  }catch(e){ GAPS=(PCI&&PCI.gaps)||{summary:{},areas:[]}; src.textContent='baseline snapshot (Box unavailable)'; }
  renderGaps();
}
let WL_ALL=[];
function renderGaps(){
  const gs=GAPS.summary||{}, areas=GAPS.areas||[];
  // strip
  document.getElementById('gap-pct').textContent=(gs.pct||0)+'%';
  document.getElementById('gap-barfill').style.width=(gs.pct||0)+'%';
  document.getElementById('sn-closed').textContent=(gs.closed||0);
  document.getElementById('sn-open').textContent=(gs.open||0);
  document.getElementById('sn-total').textContent=(gs.total||0);
  // flatten findings into one worklist
  WL_ALL=[]; areas.forEach(a=>(a.findings||[]).forEach((f,i)=>WL_ALL.push(Object.assign({},f,{area:a.name,n:i+1}))));
  // area filter options
  const sel=document.getElementById('f-area');
  sel.innerHTML='<option value="">All areas ('+WL_ALL.length+')</option>'+
    areas.map(a=>`<option value="${esc(a.name)}">${esc(a.name)} (${a.total})</option>`).join('');
  renderWorklist();
}
function renderWorklist(){
  const q=(document.getElementById('f-search').value||'').toLowerCase().trim();
  const fst=document.getElementById('f-status').value;
  const far=document.getElementById('f-area').value;
  let rows=WL_ALL.filter(f=>{
    if(far && f.area!==far) return false;
    if(fst && f.status!==fst) return false;
    if(q){ const hay=(f.area+' '+f.section+' '+f.observation+' '+f.evidence_required+' '+f.recommendation+' '+f.jira+' '+f.fib_status).toLowerCase(); if(!hay.includes(q)) return false; }
    return true;
  });
  document.getElementById('wl-count').textContent=rows.length+' of '+WL_ALL.length+' findings';
  const body=document.getElementById('wl-body');
  if(!rows.length){ body.innerHTML='<tr><td colspan="5" style="color:#94a3b8;padding:16px">No findings match.</td></tr>'; return; }
  body.innerHTML=rows.map(f=>{
    const st=(f.status||'').toLowerCase();
    const stTag=st==='closed'?'<span class="st-tag closed">Closed</span>':(st==='open'?'<span class="st-tag open">Open</span>':`<span class="st-tag na">${esc(f.status||'—')}</span>`);
    const key=jiraKey(f.jira);
    const live=key&&_LIVE[key]?_LIVE[key]:null;
    const tk=key?`<a class="wl-tk-a" href="${esc(f.jira)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(key)}</a>${live?'<div style="font-size:10px;color:#64748b;margin-top:3px">'+esc(live.status)+'</div>':''}`:'<span class="none">no ticket</span>';
    const sec=f.section?`<span style="color:#64748b">${esc(f.section)} · </span>`:'';
    return `<tr class="f-open" onclick="this.classList.toggle('exp')">
      <td><div class="wl-area">${esc(f.area)}</div></td>
      <td><div class="wl-obs">${sec}${esc(f.observation||'—')}</div>
        ${f.evidence_required?`<div class="wl-ev"><b>Evidence:</b> ${esc(f.evidence_required)}</div>`:''}
        <div class="wl-more">
          ${f.recommendation?`<div class="m1"><b>Recommendation:</b> ${esc(f.recommendation)}</div>`:''}
          ${f.assessor_comments?`<div class="m1" style="color:#64748b"><b>Assessor:</b> ${esc(f.assessor_comments)}</div>`:''}
          ${f.client_comments?`<div class="m1" style="color:#64748b"><b>Client/FIB:</b> ${esc(f.client_comments)}</div>`:''}
          <div class="wl-acts">${key?`<a class="cbtn" href="${esc(f.jira)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="text-decoration:none">Open ${esc(key)} ↗</a><button class="cbtn" onclick="event.stopPropagation();commentOn('${esc(key)}')">💬 Comment</button>`:'<span style="font-size:11.5px;color:#94a3b8">No linked Jira ticket</span>'}</div>
        </div></td>
      <td class="wl-tk">${tk}</td>
      <td>${stTag}</td>
      <td><span class="fib-tag">${esc(f.fib_status||'—')}</span></td></tr>`;
  }).join('');
}

// ── Live Jira epic FIBXPI-49 → compact team-evidence ticket reference ──
let _LIVE={};
async function loadEpic(){
  if(!GH_PROXY) return;
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'issues'})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json(); EPIC=d.issues||[]; _LIVE={}; EPIC.forEach(i=>_LIVE[i.key]=i);
    const cls=i=>i.category==='done'?'done':((i.due&&i.due<TODAY)?'over':'prog');
    const done=EPIC.filter(i=>i.category==='done').length;
    const over=EPIC.filter(i=>i.due&&i.category!=='done'&&i.due<TODAY).length;
    document.getElementById('jira-sub').innerHTML='Jira epic FIBXPI-49 · '+done+'/'+EPIC.length+' done'+(over?' · <b style="color:var(--red)">'+over+' overdue</b>':'');
    document.getElementById('jref').innerHTML=EPIC.map(i=>{
      const c=cls(i), lbl=c==='done'?'Done':(c==='over'?daysLate(i.due)+'d late':'In progress');
      return `<div class="jr"><a class="jr-key" href="https://fibtask.atlassian.net/browse/${esc(i.key)}" target="_blank" rel="noopener">${esc(i.key)}</a>
        <span class="jr-sum" title="${esc(i.summary)}">${esc(i.summary)}</span>
        <span class="jr-st ${c}">${esc(lbl)}</span>
        <button class="cbtn" style="padding:3px 8px" onclick="commentOn('${esc(i.key)}')">💬</button></div>`;
    }).join('')||'<div style="color:#94a3b8;padding:6px">No tickets.</div>';
    document.getElementById('jira-sec').style.display='';
    if(WL_ALL.length) renderWorklist(); // refresh so live Jira statuses show on rows
  }catch(e){ document.getElementById('jira-sub').textContent='Live Jira unavailable'; }
}
function openTask(key){
  const i=_LIVE[key]; if(!i) return;
  const over=i.due&&i.category!=='done'&&i.due<TODAY;
  const m=document.getElementById('ov-modal'); m.classList.remove('full','wide');
  document.getElementById('ov-body').classList.remove('flush');
  document.getElementById('ov-title').textContent=key+' — '+i.summary;
  document.getElementById('ov-body').innerHTML=`
    <div class="tm-row"><b>Status:</b> ${esc(i.status)}${over?' <span class="tag open">'+daysLate(i.due)+'d overdue</span>':''}</div>
    <div class="tm-row"><b>Owner:</b> ${esc(i.assignee||'—')}</div>
    <div class="tm-row"><b>Due:</b> ${esc(i.due||'—')} &nbsp; <b>Priority:</b> ${esc(i.priority||'—')} &nbsp; <b>Type:</b> ${esc(i.type||'—')}</div>
    <div class="f-links" style="margin-top:14px">
      <a href="https://fibtask.atlassian.net/browse/${esc(key)}" target="_blank" rel="noopener">Open ${esc(key)} in Jira ↗</a>
      <button class="cbtn" onclick="commentOn('${esc(key)}')">💬 Comment</button>
      <button class="cbtn" onclick="nudge('${esc(key)}','${esc((i.assignee||'').split(' ')[0])}')">✉ Nudge owner</button>
    </div>`;
  document.getElementById('ov').classList.add('show');
}
function nudge(key,who){
  const pre=(who?who+', ':'')+'please share the latest status and upload the required evidence for '+key+'. Thank you.';
  commentOn(key,pre);
}
function openArea(idx){
  const a=(GAPS.areas||[])[idx]; if(!a) return;
  document.getElementById('ov-modal').classList.remove('wide');
  document.getElementById('ov-body').classList.remove('flush');
  document.getElementById('ov-title').textContent=a.name+' — '+a.closed+'/'+a.total+' closed ('+a.pct+'%)';
  document.getElementById('ov-body').innerHTML=(a.findings||[]).map((f,i)=>{
    const st=(f.status||'').toLowerCase();
    const stTag=st==='closed'?'<span class="tag closed">Closed</span>':(st==='open'?'<span class="tag open">Open</span>':'');
    const fib=f.fib_status?`<span class="tag fib">${esc(f.fib_status)}</span>`:'';
    const key=jiraKey(f.jira);
    const live=key&&_LIVE[key]?_LIVE[key]:null;
    const liveChip=live?`<span class="tag" style="background:#eef2ff;color:#3730a3">Jira: ${esc(live.status)}</span>`:'';
    const actions=key?`<div class="f-links"><a href="${esc(f.jira)}" target="_blank" rel="noopener">Jira ${esc(key)} ↗</a><button class="cbtn" onclick="commentOn('${esc(key)}')">💬 Comment</button></div>`:'';
    return `<div class="finding"><div class="f-top"><span class="f-sec">${i+1}. ${esc(f.section||'Finding')}</span>${stTag}${fib}${liveChip}</div>
      ${f.observation?`<div class="f-row"><b>Observation:</b> ${esc(f.observation)}</div>`:''}
      ${f.recommendation?`<div class="f-row"><b>Recommendation:</b> ${esc(f.recommendation)}</div>`:''}
      ${f.evidence_required?`<div class="f-row"><b>Evidence required:</b> ${esc(f.evidence_required)}</div>`:''}
      ${f.assessor_comments?`<div class="f-row" style="color:#64748b"><b>Assessor:</b> ${esc(f.assessor_comments)}</div>`:''}
      ${actions}</div>`;
  }).join('')||'<div style="padding:20px;color:#94a3b8">No findings.</div>';
  document.getElementById('ov').classList.add('show');
}
function openEvidence(k){
  const e=EVIDENCE.find(x=>x.k===k); if(!e) return;
  const m=document.getElementById('ov-modal'); m.classList.remove('wide'); m.classList.add('full');
  document.getElementById('ov-title').textContent=e.t;
  const b=document.getElementById('ov-body'); b.classList.add('flush');
  b.innerHTML=`<iframe src="${esc(e.url)}" style="width:100%;height:calc(100vh - 60px);border:0;display:block" allow="fullscreen" allowfullscreen></iframe>`;
  document.getElementById('ov').classList.add('show');
}
async function commentOn(key,pre){
  const text=prompt('Add a comment to '+key+' (posts to Jira):', pre||''); if(text==null) return;
  const t=text.trim(); if(!t) return;
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},body:JSON.stringify({action:'comment',key:key,text:t})});
    const d=await r.json().catch(()=>({}));
    alert(r.ok?('Comment posted to '+key+' ✓'):('Failed: '+(d.message||('HTTP '+r.status))));
  }catch(e){ alert('Failed: '+e.message); }
}
function closeOv(){ const o=document.getElementById('ov'); o.classList.remove('show');
  const m=document.getElementById('ov-modal'); m.classList.remove('full','wide');
  const b=document.getElementById('ov-body'); b.classList.remove('flush'); b.innerHTML=''; }
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeOv();});
setTimeout(()=>document.getElementById('gate-inp').focus(),200);
</script></body></html>
"""

html = (TEMPLATE
        .replace("/*__ENC__*/{}", json.dumps(ENC))
        .replace("/*__EVIDENCE__*/{}", json.dumps(EVIDENCE))
        .replace("__GH_PROXY__", GH_PROXY))
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(html)
print(f"Wrote {OUT}  ({len(html):,} bytes, encrypted, iter={PBKDF2_ITERATIONS})")
