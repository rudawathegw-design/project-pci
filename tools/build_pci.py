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
     "url": "https://app.box.com/embed/s/aa38b8t7vyhe5xazjw8ycqwhnklwh4j2"},
    {"k": "milestones","t": "Milestones plan (Excel)", "s": "PCI DSS project plan workbook",
     "url": "https://app.box.com/embed/s/uznh5wcvxbif8vv25qtiogwwe2sppujb"},
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
/* documents: light glossy glass tiles, sitting right under the title */
.ev-sec{margin-bottom:18px}
.ev-head{font-size:11px;font-weight:800;letter-spacing:.13em;text-transform:uppercase;color:var(--slate);
  margin:0 2px 10px}
.ev-head small{font-weight:600;letter-spacing:.02em;text-transform:none;font-size:11.5px;color:#b6c2d1;margin-left:8px}
.ev-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.ev-btn{position:relative;overflow:hidden;cursor:pointer;text-align:left;border-radius:14px;padding:17px 18px;
  border:1px solid rgba(255,255,255,.9);
  background:linear-gradient(180deg,#ffffff 0%,#f7fafc 55%,#eef4f9 100%);
  box-shadow:0 1px 0 #fff inset,0 8px 22px rgba(15,31,58,.08),0 1px 3px rgba(15,31,58,.06);
  transition:transform .2s ease,box-shadow .2s ease}
/* glass highlight across the top half */
.ev-btn::before{content:"";position:absolute;inset:0 0 auto 0;height:52%;pointer-events:none;
  background:linear-gradient(180deg,rgba(255,255,255,.95),rgba(255,255,255,0));border-radius:14px 14px 40% 40%/14px 14px 100% 100%}
.ev-btn .t{position:relative;font-weight:800;font-size:14.5px;color:#0f172a;letter-spacing:-.01em}
.ev-btn .s{position:relative;font-size:11.5px;color:var(--sub);margin-top:5px;line-height:1.45}
.ev-btn .go{position:absolute;top:16px;right:16px;color:#c3ceda;font-size:14px;transition:.2s;z-index:2}
.ev-btn:hover{transform:translateY(-3px);
  box-shadow:0 1px 0 #fff inset,0 16px 34px rgba(15,31,58,.14),0 0 0 1px rgba(15,147,137,.35)}
.ev-btn:hover .go{color:var(--teal-d);transform:translateX(3px)}
.ev-btn:active{transform:translateY(-1px)}
/* sheen sweep on hover */
.ev-btn::after{content:"";position:absolute;top:0;left:-80%;width:55%;height:100%;pointer-events:none;z-index:1;
  background:linear-gradient(120deg,transparent,rgba(255,255,255,.85),transparent);transform:skewX(-22deg)}
.ev-btn:hover::after{animation:evShine .8s ease forwards}
@keyframes evShine{to{left:135%}}
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
.strip{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px 15px;margin-bottom:18px;
  box-shadow:0 1px 2px rgba(15,31,58,.04)}
.strip-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:13px}
.strip-left{display:flex;align-items:baseline;gap:13px}
.strip-pct span{font-size:42px;font-weight:900;letter-spacing:-.035em;line-height:1;
  background:linear-gradient(95deg,#0f9389,#10b981);-webkit-background-clip:text;background-clip:text;color:transparent}
.strip-lbl{font-size:13px;font-weight:800;color:#334155;line-height:1.3}
.strip-lbl small{display:block;font-size:11.5px;font-weight:600;color:var(--sub);margin-top:3px}
.strip-lbl small b{font-weight:900;color:#0f172a}
.strip-chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.schip{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:700;color:#475569;
  background:#f8fafc;border:1px solid var(--line);border-radius:999px;padding:5px 11px;white-space:nowrap}
.schip b{font-weight:900;color:#0f172a}
.schip i{width:8px;height:8px;border-radius:50%;background:#cbd5e1;display:inline-block}
.schip.ok i{background:var(--green)}.schip.bad i{background:var(--red)}.schip.warn i{background:var(--red)}
.schip.warn{cursor:pointer}
.schip.warn.hot{background:#fee2e2;border-color:#fca5a5;color:#b91c1c}
.schip.warn.hot b{color:#b91c1c}
.schip.warn.on{background:var(--red);border-color:var(--red);color:#fff}.schip.warn.on b,.schip.warn.on i{color:#fff;background:#fff}
.schip.src{color:var(--teal-d);background:#f0faf9;border-color:#a7f3e6}
.schip.fu{cursor:pointer}.schip.fu i{background:#2563eb}
.schip.fu.hot{background:#eff6ff;border-color:#bfdbfe;color:#1d4ed8}.schip.fu.hot b{color:#1d4ed8}
.schip.fu.on{background:#2563eb;border-color:#2563eb;color:#fff}.schip.fu.on b{color:#fff}.schip.fu.on i{background:#fff}
/* evidence is in, assessor still Open → nudge them */
.fu-badge{display:inline-flex;align-items:center;gap:4px;margin-top:6px;font-size:9.5px;font-weight:800;
  letter-spacing:.03em;text-transform:uppercase;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;
  border-radius:999px;padding:2px 8px;cursor:pointer;white-space:nowrap}
.fu-badge:hover{background:#dbeafe;border-color:#93c5fd}
.pbar{position:relative;height:16px;border-radius:999px;background:#eef2f6;overflow:hidden}
.pfill{height:100%;border-radius:999px;width:0;transition:width .9s cubic-bezier(.4,0,.2,1);
  background:linear-gradient(90deg,#0f9389,#10b981,#34d399);box-shadow:0 1px 6px rgba(16,185,129,.4)}
/* ── roadmap chain: user-built phases from start to certification ── */
.chain{display:flex;align-items:flex-start;overflow-x:auto;padding:22px 2px 6px;gap:0}
.ph{flex:1 0 132px;min-width:132px;position:relative;padding:0 6px;text-align:center;cursor:grab}
.ph.drag{opacity:.4}.ph.over{background:#f0faf9;border-radius:10px}
.ph::before{content:"";position:absolute;top:11px;left:0;right:0;height:4px;background:#e2e8f0;border-radius:2px}
.ph:first-child::before{left:50%}.ph.flag::before{right:50%}
.ph.lit::before{background:var(--green)}
.ph-dot{position:absolute;top:0;left:50%;transform:translateX(-50%);width:26px;height:26px;border-radius:50%;
  background:#fff;border:3px solid #cbd5e1;z-index:2;display:grid;place-items:center;font-size:12px;font-weight:900;color:#94a3b8}
.ph.done .ph-dot{background:var(--green);border-color:var(--green);color:#fff}
.ph.flag .ph-dot{border-color:var(--teal);background:#fff;font-size:14px}
.ph.flag.done .ph-dot{background:var(--teal);border-color:var(--teal)}
.ph-body{margin-top:34px}
.ph-t{font-size:12.5px;font-weight:800;color:#334155;line-height:1.25;word-break:break-word}
.ph-n{font-size:10.5px;color:var(--sub);margin-top:3px;line-height:1.35;white-space:pre-wrap;word-break:break-word}
.ph-s{display:inline-block;font-size:9.5px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;
  padding:1px 7px;border-radius:999px;margin-top:5px;background:#f1f5f9;color:#64748b}
.ph:hover .ph-t{color:var(--teal-d)}
.ph-add{flex:0 0 96px;min-width:96px;display:grid;place-items:center;padding-top:2px}
.ph-add button{border:1.5px dashed var(--line);background:#fff;color:var(--sub);border-radius:10px;
  padding:7px 12px;font-size:12px;font-weight:700;cursor:pointer}
.ph-add button:hover{border-color:var(--teal);color:var(--teal-d);background:#f0faf9}
.sw{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.sw b{width:26px;height:26px;border-radius:50%;cursor:pointer;border:2px solid transparent;display:block}
.sw b.on{border-color:#0f172a;transform:scale(1.12)}
.fld{width:100%;border:1.5px solid var(--line);border-radius:10px;padding:9px 12px;font-size:14px;
  font-family:inherit;outline:none;margin-top:6px}
.fld:focus{border-color:var(--teal)}
.flab{font-size:11px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);margin-top:14px;display:block}
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
/* a missing client evidence link is flagged red; if FIB status says Done it pulses */
.wl-tk .none.warn{color:#dc2626;font-weight:800;background:#fee2e2;border:1px solid #fca5a5;
  padding:2px 8px;border-radius:7px;display:inline-block;font-size:10.5px}
@keyframes noLinkPulse{0%,100%{box-shadow:0 0 0 0 rgba(220,38,38,.55)}50%{box-shadow:0 0 0 7px rgba(220,38,38,0)}}
.wl-tk .none.warn.pulse{animation:noLinkPulse 1.7s ease-out infinite}
tr.needs-ev td{background:#fffafa}
.cl-chip{display:inline-block;font-family:ui-monospace,monospace;font-size:11.5px;font-weight:800;text-decoration:none;
  background:#ecfeff;color:#0e7490;padding:3px 8px;border-radius:7px;margin-right:4px;border:1px solid #a5f3fc}
.cl-chip:hover{background:#cffafe}
.cl-chip.txt{background:#f8fafc;color:#64748b;border-color:#e2e8f0;font-family:inherit}
.tk-live{display:inline-flex;align-items:center;gap:4px;font-size:10.5px;font-weight:700;margin-top:5px;color:#64748b}
.tk-dot{width:7px;height:7px;border-radius:50%;background:#f59e0b}
.tk-live.done .tk-dot{background:#10b981}.tk-live.done{color:#166534}
.tk-live.todo .tk-dot{background:#94a3b8}
.wl-more{display:none}.wl tr.exp .wl-more{display:block;margin-top:9px;padding-top:9px;border-top:1px dashed #e2e8f0}
.wl-more .m1{font-size:12.5px;color:#334155;line-height:1.5;margin-top:5px}.wl-more .m1 b{color:#0f172a}
.wl-more .m1.mx{color:#475569;border-left:2px solid #e2e8f0;padding-left:9px;margin-top:6px;word-break:break-word}
.wl-more .m1.mx b{color:#0f766e;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em}
.wl-acts{margin-top:9px;display:flex;gap:8px;flex-wrap:wrap}
.st-tag{font-size:10.5px;font-weight:800;letter-spacing:.03em;text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap;display:inline-block}
.st-tag.open{background:#fee2e2;color:#b91c1c}.st-tag.closed{background:#dcfce7;color:#166534}.st-tag.na{background:#f1f5f9;color:#64748b}
.fib-tag{font-size:11px;font-weight:700;color:#475569}
.fibsel{border:1px solid var(--line);border-radius:8px;padding:4px 6px;font-size:11.5px;font-weight:700;color:#334155;background:#fff;cursor:pointer;max-width:112px}
.fibsel:hover{border-color:var(--teal)}.fibsel:disabled{opacity:.5;cursor:wait}
.fibsel.v-done{background:#dcfce7;border-color:#86efac;color:#166534}
.fibsel.v-prog{background:#fef3c7;border-color:#fcd34d;color:#92400e}
.fibsel.v-hold{background:#ffedd5;border-color:#fdba74;color:#9a3412}
.fibsel.v-todo{background:#f1f5f9;border-color:#cbd5e1;color:#475569}
.fibsel.pend{border-color:var(--amber);box-shadow:0 0 0 2px #fde68a}
.pendtag{font-size:9.5px;font-weight:800;color:var(--amber);margin-top:3px;letter-spacing:.02em}
.pen{border:1px solid var(--line);background:#fff;color:#64748b;border-radius:6px;padding:1px 6px;font-size:11px;cursor:pointer;margin-left:5px}
.pen:hover{border-color:var(--teal);color:var(--teal-d)}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);background:#0b1f3a;color:#fff;
  font-size:13px;font-weight:700;padding:11px 20px;border-radius:11px;box-shadow:0 12px 34px rgba(11,31,58,.3);
  opacity:0;pointer-events:none;transition:.25s;z-index:1200;max-width:min(560px,92vw);text-align:center}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.bad{background:#b91c1c}
/* jira reference */
.jref{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}
.jr{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-radius:11px;padding:10px 13px}
.jr-key{font-family:ui-monospace,monospace;font-size:11.5px;font-weight:800;color:var(--teal-d);text-decoration:none;white-space:nowrap}
.jr-sum{flex:1;font-size:12.5px;color:#334155;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.jr-st{font-size:10.5px;font-weight:800;padding:2px 8px;border-radius:999px;white-space:nowrap}
.jr-st.done{background:#dcfce7;color:#166534}.jr-st.prog{background:#fef3c7;color:#92400e}.jr-st.over{background:#fee2e2;color:#b91c1c}
/* activity feed */
.act-filters{display:flex;gap:6px;flex-wrap:wrap}
.afb{border:1px solid var(--line);background:#fff;color:#475569;border-radius:999px;padding:5px 13px;font-size:12px;font-weight:700;cursor:pointer}
.afb:hover{border-color:var(--teal)}
.afb.on{background:var(--teal);border-color:var(--teal);color:#fff}
.act{display:flex;flex-direction:column}
.arow{display:grid;grid-template-columns:26px 1fr;gap:11px;padding:11px 2px;border-bottom:1px solid #f1f5f9}
.arow:last-child{border-bottom:none}
.aic{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:12px;margin-top:1px}
.aic.comment{background:#dbeafe;color:#1e40af}.aic.status{background:#dcfce7;color:#166534}.aic.edit{background:#f1f5f9;color:#64748b}
.ahead{font-size:12.5px;color:#334155;line-height:1.45}
.ahead b{color:#0f172a;font-weight:800}
.akey{font-family:ui-monospace,monospace;font-size:11px;font-weight:800;text-decoration:none;background:#eef2ff;color:#3730a3;padding:2px 7px;border-radius:6px}
.awhen{font-size:11px;color:var(--slate);font-weight:600;white-space:nowrap}
.atxt{margin-top:6px;font-size:12.5px;color:#475569;line-height:1.5;background:#f8fafc;border-left:3px solid #cbd5e1;border-radius:0 8px 8px 0;padding:8px 11px;white-space:pre-wrap;word-break:break-word}
.achg{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:4px}
.achip{font-size:10.5px;font-weight:800;padding:2px 8px;border-radius:999px;background:#f1f5f9;color:#475569}
.achip.to{background:#dcfce7;color:#166534}
.asum{color:var(--slate);font-size:11.5px}
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
  <!-- documents & evidence — first thing under the title -->
  <div class="ev-sec">
    <div class="ev-head">Documents &amp; evidence <small>opens full-screen from Box</small></div>
    <div class="ev-row" id="ev-row"></div>
  </div>
  <!-- remediation progress -->
  <div class="strip">
    <div class="strip-head">
      <div class="strip-left">
        <div class="strip-pct"><span id="gap-pct">0%</span></div>
        <div class="strip-lbl">Gap remediation<small><b id="sn-closed">0</b> of <b id="sn-total">0</b> findings closed</small></div>
      </div>
      <div class="strip-chips">
        <span class="schip ok"><i></i><b id="sn-closed2">0</b> closed</span>
        <span class="schip bad"><i></i><b id="sn-open">0</b> open</span>
        <span class="schip warn" id="chip-noev" onclick="toggleNoEv()"
              title="Marked Done in FIB status but no client evidence link — click to filter"><i></i><b id="sn-noev">0</b> done, no link</span>
        <span class="schip fu" id="chip-fu" onclick="toggleFu()"
              title="Evidence uploaded and work in progress, but the assessor still has it Open — click to filter"><i></i><b id="sn-fu">0</b> follow-up</span>
        <span class="schip src" id="gap-src">—</span>
      </div>
    </div>
    <div class="pbar"><div class="pfill" id="gap-barfill"></div></div>
  </div>
  <!-- roadmap: phases you build yourself, start → certification -->
  <div class="sec" id="ph-sec">
    <div class="sec-h"><div class="sec-t">Roadmap <small id="ph-sub">drag to reorder · click a phase to edit</small></div>
      <button class="cbtn" onclick="addPhase()">+ Add phase</button></div>
    <div class="chain" id="chain"></div>
  </div>
  <!-- findings worklist -->
  <div class="sec">
    <div class="sec-h"><div class="sec-t">Findings worklist <small id="wl-count"></small></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="cbtn" id="wl-mail" onclick="exportOutlook()" title="Outlook draft for the assessor — no Jira, evidence links only">✉ Email assessor (<span id="mail-n">0</span>)</button>
        <button class="cbtn" id="wl-mail-team" onclick="exportTeamEmail()" title="Outlook draft for the FIB team — includes Jira tickets, owners and the action required">✉ Email FIB team (<span id="mail-t">0</span>)</button>
        <button class="cbtn" id="wl-sync" onclick="syncFromJira()">⟳ Set FIB status from Jira</button>
        <button class="cbtn" id="wl-export" onclick="exportWorkbook()" style="display:none">⬇ Download updated workbook (<span id="pend-n">0</span>)</button>
        <button class="cbtn" id="wl-clear" onclick="clearPending()" style="display:none">✓ Mark as uploaded</button>
      </div></div>
    <div class="filters">
      <input id="f-search" class="f-search" placeholder="Search findings, evidence, ticket…" oninput="renderWorklist()">
      <select id="f-status" class="f-sel" onchange="renderWorklist()" title="Assessor decision">
        <option value="">All statuses</option><option value="Open">Open only</option><option value="Closed">Closed only</option></select>
      <select id="f-fib" class="f-sel" onchange="renderWorklist()" title="FIB status"><option value="">All FIB status</option></select>
      <select id="f-area" class="f-sel" onchange="renderWorklist()"><option value="">All areas</option></select>
    </div>
    <div class="wl-wrap"><table class="wl" id="wl"><thead><tr>
      <th style="width:150px">Area</th><th>Finding &amp; evidence required</th>
      <th style="width:112px">Ticket</th><th style="width:92px">Client</th>
      <th style="width:96px">Assessor</th><th style="width:118px">FIB status</th>
    </tr></thead><tbody id="wl-body"><tr><td colspan="6" style="color:#94a3b8;padding:16px">Loading live from Box…</td></tr></tbody></table></div>
  </div>
  <!-- Jira team-evidence tickets (compact side reference) -->
  <div class="sec" id="jira-sec" style="display:none"><div class="sec-h"><div class="sec-t">Team evidence tickets <small id="jira-sub">Jira epic FIBXPI-49</small></div></div>
    <div class="jref" id="jref"></div></div>
  <!-- latest activity on the epic -->
  <div class="sec" id="act-sec" style="display:none">
    <div class="sec-h"><div class="sec-t">Latest activity <small id="act-sub">FIBXPI-49 · status changes, edits &amp; comments</small></div>
      <div class="act-filters">
        <button class="afb on" onclick="actFilter(this,'')">All</button>
        <button class="afb" onclick="actFilter(this,'comment')">💬 Comments</button>
        <button class="afb" onclick="actFilter(this,'status')">✓ Status</button>
        <button class="afb" onclick="actFilter(this,'edit')">✎ Edits</button>
        <button class="afb bot on" id="act-bot" onclick="actBots(this)">🤖 Automation hidden</button>
      </div></div>
    <div class="act" id="act-list"></div>
    <div style="text-align:center;margin-top:14px"><button class="cbtn" id="act-more" onclick="actMore()" style="display:none">Show more</button></div>
  </div>
  <div class="foot">First Iraq Bank · PCI DSS Compliance Cockpit · generated <span id="gen2"></span></div>
</div></div>
<div class="ov" id="ov" onclick="if(event.target===this)closeOv()"><div class="modal" id="ov-modal">
  <div class="m-head"><h3 id="ov-title">Area</h3><button class="m-close" onclick="closeOv()">Close</button></div>
  <div class="m-body" id="ov-body"></div>
</div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
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
  document.getElementById('ev-row').innerHTML=EVIDENCE.map(e=>
    `<div class="ev-btn" onclick="openEvidence('${e.k}')"><span class="go">↗</span>
       <div class="t">${esc(e.t)}</div><div class="s">${esc(e.s)}</div></div>`).join('');
  loadPhases();   // roadmap chain (shared, editable)
  loadGaps();     // live gap workbook from Box → remediation strip + worklist
  loadEpic();     // live Jira epic FIBXPI-49 → team evidence tickets
  loadActivity(); // live epic activity → status changes, edits, comments
}

// ── Latest activity on FIBXPI-49 (+children): status, edits, comments ──
let ACT=[], ACT_K='', ACT_N=25, ACT_BOT=true;   // ACT_BOT: hide "Automation for Jira" noise
function ago(ts){
  const s=Math.max(0,(Date.now()-new Date(ts).getTime())/1000);
  if(s<60) return 'just now';
  if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  const d=Math.floor(s/86400);
  if(d<30) return d+'d ago';
  return new Date(ts).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'2-digit'});
}
async function loadActivity(){
  if(!GH_PROXY) return;
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'activity',limit:600})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json(); ACT=d.items||[];
    document.getElementById('act-sec').style.display='';
    renderActivity();
  }catch(e){}
}
function actFilter(btn,k){
  document.querySelectorAll('.afb:not(.bot)').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on'); ACT_K=k; ACT_N=25; renderActivity();
}
function actBots(btn){
  ACT_BOT=!ACT_BOT;                         // ACT_BOT = hide automation
  btn.classList.toggle('on',ACT_BOT);
  btn.textContent=ACT_BOT?'🤖 Automation hidden':'🤖 Automation shown';
  ACT_N=25; renderActivity();
}
function actMore(){ ACT_N+=25; renderActivity(); }
function renderActivity(){
  const base=ACT.filter(a=>!(ACT_BOT&&a.bot));
  const rows=base.filter(a=>!ACT_K||a.kind===ACT_K);
  const nC=base.filter(a=>a.kind==='comment').length, nS=base.filter(a=>a.kind==='status').length, nE=base.filter(a=>a.kind==='edit').length;
  const hidden=ACT.length-base.length;
  document.getElementById('act-sub').textContent='epic FIBXPI-49 tree · '+nC+' comments · '+nS+' status changes · '+nE+' edits'
    +(hidden?' · '+hidden+' automation hidden':'');
  const show=rows.slice(0,ACT_N);
  document.getElementById('act-list').innerHTML=show.map(a=>{
    const ic=a.kind==='comment'?'💬':(a.kind==='status'?'✓':'✎');
    const keyLink=`<a class="akey" href="https://fibtask.atlassian.net/browse/${esc(a.key)}" target="_blank" rel="noopener">${esc(a.key)}</a>`
      +(a.bot?' <span class="achip" style="background:#f1f5f9;color:#94a3b8">🤖 automation</span>':'');
    let head='';
    if(a.kind==='comment') head=`<b>${esc(a.who||'—')}</b> commented on ${keyLink}`;
    else if(a.kind==='status') head=`<b>${esc(a.who||'—')}</b> changed status on ${keyLink}`;
    else head=`<b>${esc(a.who||'—')}</b> edited <b>${esc(a.field||'field')}</b> on ${keyLink}`;
    let detail='';
    if(a.kind==='comment') detail=`<div class="atxt">${esc(a.text||'')}</div>`;
    else{
      const from=(a.from||'').slice(0,60), to=(a.to||'').slice(0,60);
      if(from||to) detail=`<div class="achg">${from?`<span class="achip">${esc(from)}</span> →`:''}<span class="achip to">${esc(to||'—')}</span></div>`;
    }
    return `<div class="arow"><div class="aic ${a.kind}">${ic}</div>
      <div><div class="ahead">${head} <span class="awhen">· ${esc(ago(a.ts))}</span>
        <button class="cbtn" style="padding:2px 8px;font-size:11px;margin-left:6px" onclick="commentOn('${esc(a.key)}')">💬 Reply</button></div>
        <div class="asum">${esc(a.summary||'')}</div>${detail}</div></div>`;
  }).join('')||'<div style="color:#94a3b8;font-size:13px;padding:10px 2px">No activity of this type.</div>';
  const more=document.getElementById('act-more');
  more.style.display=rows.length>ACT_N?'':'none';
  more.textContent='Show more ('+(rows.length-ACT_N)+' left)';
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
    const srCol=hdr.findIndex(h=>/^sr\.?\s*no/i.test(h));
    // Some sheets leave the FIB Status / Link headers blank (HR, SIEM). Infer
    // those columns from the data so they stay editable instead of turning up
    // as an unnamed "Column I".
    const dataRows=rows.slice(hi+1);
    if(ci.fib<0||ci.link<0){
      const taken=new Set([ci.section,ci.obs,ci.rec,ci.ev,ci.status,ci.assessor,ci.client,srCol].filter(x=>x>=0));
      const nk=s=>String(s==null?'':s).toLowerCase().replace(/[^a-z0-9]/g,'');
      const STAT=new Set(['done','inprogress','onhold','notstarted','completed','pending','na']);
      const width=Math.max(hdr.length,...dataRows.map(r=>r.length),0);
      const st={},lk={};
      for(const r of dataRows) for(let j=0;j<width;j++){
        const v=norm(r[j]); if(!v||taken.has(j)) continue;
        if(/atlassian\.net\/browse\//i.test(v)) lk[j]=(lk[j]||0)+1;
        else if(STAT.has(nk(v))) st[j]=(st[j]||0)+1;
      }
      // a jira browse URL is unambiguous on its own; status words need 2+ to be safe
      const best=(m,min)=>{ let b=-1,n=0; for(const j in m){ if(m[j]>n){n=m[j];b=+j;} } return n>=min?b:-1; };
      if(ci.fib<0){ const j=best(st,2); if(j>=0) ci.fib=j; }
      if(ci.link<0){ const j=best(lk,1); if(j>=0) ci.link=j; }
    }
    // Every "Client Comments" column (HR has two) gets its own compact chip
    // column next to the ticket, so they're excluded from the extras list.
    const clientIdx=hdr.map((h,j)=>/client\s*comment/i.test(h)?j:-1).filter(j=>j>=0);
    if(clientIdx.length) ci.client=clientIdx[0];
    // Columns already rendered in their own place; everything else that carries
    // text (Additional Comments, Evidences1/2 …) is surfaced as "extras".
    const used=new Set([ci.section,ci.obs,ci.rec,ci.ev,ci.status,ci.assessor,ci.fib,ci.link,srCol]
      .concat(clientIdx).filter(x=>x>=0));
    const colLetter=n=>{ let s=''; n=n+1; while(n>0){ const m=(n-1)%26; s=String.fromCharCode(65+m)+s; n=Math.floor((n-1)/26); } return s; };
    const findings=[];
    let _k=-1;
    for(const r of rows.slice(hi+1)){
      _k++;
      const section=ci.section>=0?norm(r[ci.section]):'', obs=ci.obs>=0?norm(r[ci.obs]):'';
      if(!section&&!obs) continue;
      // exact spreadsheet coordinates so edits can be written back to Box
      const _row=hi+_k+2, _cFib=ci.fib>=0?colLetter(ci.fib):'', _cLink=ci.link>=0?colLetter(ci.link):'';
      const stRaw=ci.status>=0?norm(r[ci.status]).toLowerCase():'';
      const status=stRaw.includes('clos')?'Closed':(stRaw.includes('open')?'Open':(ci.status>=0?norm(r[ci.status]):''));
      let jira=ci.link>=0&&/atlassian/.test(norm(r[ci.link]))?norm(r[ci.link]):'';
      if(!jira) for(const c of r){ const s=norm(c); if(/atlassian\.net\/browse\//.test(s)){ jira=s; break; } }
      const extras=[];
      for(let j=0;j<Math.max(hdr.length,r.length);j++){
        if(used.has(j)) continue;
        const v=norm(r[j]); if(!v) continue;
        const h=norm(rows[hi][j])||('Column '+colLetter(j));
        extras.push({h,v});
      }
      findings.push({section,observation:obs,recommendation:ci.rec>=0?norm(r[ci.rec]):'',
        evidence_required:ci.ev>=0?norm(r[ci.ev]):'',status,fib_status:ci.fib>=0?norm(r[ci.fib]):'',
        assessor_comments:ci.assessor>=0?norm(r[ci.assessor]):'',client_comments:ci.client>=0?norm(r[ci.client]):'',jira,
        clients:clientIdx.map(j=>({c:colLetter(j),h:norm(rows[hi][j])||'Client Comments',v:norm(r[j])})),
        extras,_sheet:sn,_row,_cFib,_cLink,_cClient:clientIdx.length?colLetter(clientIdx[0]):''});
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
  await loadOverlay();
  // Never leave the table stuck on "Loading…" if rendering hits a problem —
  // surface the reason instead of failing silently.
  try{ renderGaps(); }
  catch(err){
    console.error(err);
    document.getElementById('wl-body').innerHTML=
      '<tr><td colspan="6" style="color:#b91c1c;padding:16px">Could not display the findings: '+esc(err.message)+'</td></tr>';
  }
  loadFindingStatuses();
}
// Fetch live Jira status for every ticket referenced by a finding, in one call.
async function loadFindingStatuses(){
  if(!GH_PROXY||!WL_ALL.length) return;
  const keys=[...new Set(WL_ALL.map(f=>jiraKey(f.jira)).filter(Boolean))];
  if(!keys.length) return;
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'issues',keys})});
    if(!r.ok) return; const d=await r.json();
    (d.issues||[]).forEach(i=>_LIVE[i.key]=i);
    refreshNoEv();          // follow-up flags depend on live Jira status
    renderWorklist();
  }catch(e){}
}
let WL_ALL=[], FIB_OPTS=[''], OVERLAY={}, WL_NOEV=false, WL_FU=false, WL_VIEW=[];
/* ── Export the current worklist as an Outlook draft (.eml) ──
   Written for the follow-up you actually send: "here is what we have completed,
   please review the evidence and close them". X-Unsent:1 makes Outlook open it
   as an editable draft rather than a received message.                        */
function exportOutlook(){
  const rows=WL_VIEW.slice();
  if(!rows.length){ toast('Nothing to send — the current filter shows no findings.',1); return; }
  const doneOnly=rows.filter(f=>_norm(f.fib_status||'')==='done' && _norm(f.status||'')==='open');
  const useDone=doneOnly.length && doneOnly.length!==rows.length;
  let list=rows, note='';
  if(useDone){
    if(confirm(rows.length+' findings are shown.\n\n'+doneOnly.length+' of them are marked Done by FIB but still Open with the assessor'
      +' — those are the ones that need closing.\n\nOK = send only those '+doneOnly.length
      +'\nCancel = send all '+rows.length)){ list=doneOnly; note='completed and awaiting the assessor’s closure'; }
  }
  if(!note) note='from the PCI DSS assessment gap report';
  const esc2=s=>esc(s==null?'':String(s));
  const byArea={}; list.forEach(f=>{ (byArea[f.area]=byArea[f.area]||[]).push(f); });
  const today=new Date().toLocaleDateString(undefined,{day:'numeric',month:'long',year:'numeric'});
  let body=`<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937;line-height:1.55">
<p>Dear Assessor,</p>
<p>Please find below <b>${list.length}</b> finding${list.length>1?'s':''} ${note}. The supporting evidence is linked against each item in the Assessment Gap Report on Box.</p>
<p>Kindly review and confirm closure, or let us know if anything further is required.</p>`;
  Object.keys(byArea).sort().forEach(area=>{
    body+=`<h3 style="font-size:14px;margin:20px 0 7px;color:#0b1f3a;border-bottom:2px solid #0f9389;padding-bottom:4px">${esc2(area)} <span style="font-weight:400;color:#6b7280">(${byArea[area].length})</span></h3>
<table cellpadding="7" cellspacing="0" border="0" style="border-collapse:collapse;width:100%;font-size:13px">
<tr style="background:#f1f5f9">
  <th align="left" style="border:1px solid #dbe3ec;width:28%">Finding</th>
  <th align="left" style="border:1px solid #dbe3ec">Observation</th>
  <th align="left" style="border:1px solid #dbe3ec;width:15%">Evidence</th>
  <th align="left" style="border:1px solid #dbe3ec;width:12%">FIB status</th></tr>`;
    byArea[area].forEach(f=>{
      // no Jira ticket column here — the assessor has no access to our Jira
      const ev=(f.clients||[]).filter(c=>c.v&&/^https?:\/\//i.test(c.v))
        .map((c,n)=>`<a href="${esc2(c.v)}">Evidence${n?(' '+(n+1)):''}</a>`).join('<br>')||'<span style="color:#9ca3af">—</span>';
      body+=`<tr>
  <td style="border:1px solid #dbe3ec;vertical-align:top"><b>${esc2(f.section||'Finding')}</b></td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${esc2(f.observation||'')}</td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${ev}</td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${esc2(f.fib_status||'—')}</td></tr>`;
    });
    body+='</table>';
  });
  body+=`<p style="margin-top:22px">Best regards,<br>PMO — First Iraq Bank</p>
<p style="color:#9ca3af;font-size:11px;border-top:1px solid #e5e7eb;padding-top:8px">
Generated from the PCI DSS Compliance Cockpit on ${esc2(today)}.</p></div>`;
  // keep the Subject header pure ASCII — Outlook mangles raw UTF-8 in headers
  const subject='PCI DSS - '+list.length+' finding'+(list.length>1?'s':'')+' ready for your review and closure';
  downloadEml(subject,body,'PCI follow-up assessor '+new Date().toISOString().slice(0,10)+'.eml');
  toast('Outlook draft downloaded ('+list.length+' findings) — open the .eml, add the assessor and send.');
}
function downloadEml(subject,body,filename){
  const eml=['To: ','Subject: '+subject,'X-Unsent: 1','MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8','Content-Transfer-Encoding: 8bit','',body].join('\r\n');
  const blob=new Blob([eml],{type:'message/rfc822'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename;
  document.body.appendChild(a); a.click();
  setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},2000);
}
/* ── Internal action list for the FIB team ──
   Keeps the Jira ticket and owner (we have access), and states plainly what is
   still required — the key case being evidence that was submitted but did not
   satisfy the assessor.                                                       */
function exportTeamEmail(){
  const rows=WL_VIEW.slice();
  if(!rows.length){ toast('Nothing to send — the current filter shows no findings.',1); return; }
  const open=rows.filter(f=>_norm(f.status||'')==='open');
  let list=rows;
  if(open.length && open.length!==rows.length){
    list=confirm(rows.length+' findings are shown.\n\n'+open.length+' are still OPEN with the assessor and need action from the team.'
      +'\n\nOK = send only those '+open.length+'\nCancel = send all '+rows.length)?open:rows;
  }
  const esc2=s=>esc(s==null?'':String(s));
  const action=f=>{
    const hasEv=(f.clients||[]).some(c=>c.v);
    const closed=_norm(f.status||'')==='closed';
    if(closed) return {t:'Closed by the assessor — no further action.',c:'#166534',b:'#dcfce7'};
    if(hasEv) return {t:'Evidence submitted did not fully satisfy the requirement — additional or clarified evidence is required.',c:'#b45309',b:'#fef3c7'};
    return {t:'Evidence outstanding — please prepare, upload to Box and link it against this finding.',c:'#b91c1c',b:'#fee2e2'};
  };
  const nMore=list.filter(f=>_norm(f.status||'')!=='closed'&&(f.clients||[]).some(c=>c.v)).length;
  const nNone=list.filter(f=>_norm(f.status||'')!=='closed'&&!(f.clients||[]).some(c=>c.v)).length;
  const byArea={}; list.forEach(f=>{ (byArea[f.area]=byArea[f.area]||[]).push(f); });
  const today=new Date().toLocaleDateString(undefined,{day:'numeric',month:'long',year:'numeric'});
  let body=`<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937;line-height:1.55">
<p>Dear team,</p>
<p>Below are <b>${list.length}</b> PCI DSS finding${list.length>1?'s':''} requiring our action, taken from the assessor's gap report.</p>
<ul style="margin:10px 0 16px;padding-left:20px">
  ${nMore?`<li><b>${nMore}</b> where evidence was submitted but <b>did not fully satisfy the requirement</b> — additional or clarified evidence is needed.</li>`:''}
  ${nNone?`<li><b>${nNone}</b> where <b>no evidence has been provided yet</b>.</li>`:''}
</ul>
<p>Please action your assigned items via the linked Jira ticket, upload the evidence to Box, and link it in the gap report.</p>`;
  Object.keys(byArea).sort().forEach(area=>{
    body+=`<h3 style="font-size:14px;margin:20px 0 7px;color:#0b1f3a;border-bottom:2px solid #0f9389;padding-bottom:4px">${esc2(area)} <span style="font-weight:400;color:#6b7280">(${byArea[area].length})</span></h3>
<table cellpadding="7" cellspacing="0" border="0" style="border-collapse:collapse;width:100%;font-size:13px">
<tr style="background:#f1f5f9">
  <th align="left" style="border:1px solid #dbe3ec;width:24%">Finding</th>
  <th align="left" style="border:1px solid #dbe3ec">Evidence required</th>
  <th align="left" style="border:1px solid #dbe3ec;width:11%">Ticket</th>
  <th align="left" style="border:1px solid #dbe3ec;width:13%">Owner</th>
  <th align="left" style="border:1px solid #dbe3ec;width:26%">Action required</th></tr>`;
    byArea[area].forEach(f=>{
      const a=action(f), key=jiraKey(f.jira), live=key?_LIVE[key]:null;
      const tk=key?`<a href="${esc2(f.jira)}">${esc2(key)}</a>${live?`<div style="color:#6b7280;font-size:11px">${esc2(live.status)}</div>`:''}`
                  :'<span style="color:#9ca3af">no ticket</span>';
      const ev=(f.clients||[]).filter(c=>c.v&&/^https?:\/\//i.test(c.v))
        .map((c,n)=>`<a href="${esc2(c.v)}">evidence${n?(' '+(n+1)):''}</a>`).join(', ');
      body+=`<tr>
  <td style="border:1px solid #dbe3ec;vertical-align:top"><b>${esc2(f.section||'Finding')}</b>
    <div style="color:#6b7280;font-size:11.5px;margin-top:3px">${esc2((f.observation||'').slice(0,160))}${(f.observation||'').length>160?'…':''}</div></td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${esc2(f.evidence_required||'—')}
    ${ev?`<div style="margin-top:4px;font-size:11.5px">Submitted: ${ev}</div>`:''}</td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${tk}</td>
  <td style="border:1px solid #dbe3ec;vertical-align:top">${esc2((live&&live.assignee)||'—')}</td>
  <td style="border:1px solid #dbe3ec;vertical-align:top;background:${a.b};color:${a.c}">${esc2(a.t)}</td></tr>`;
    });
    body+='</table>';
  });
  body+=`<p style="margin-top:22px">Thank you,<br>PMO — First Iraq Bank</p>
<p style="color:#9ca3af;font-size:11px;border-top:1px solid #e5e7eb;padding-top:8px">
Generated from the PCI DSS Compliance Cockpit on ${esc2(today)}.</p></div>`;
  const subject='PCI DSS - action required on '+list.length+' finding'+(list.length>1?'s':'');
  downloadEml(subject,body,'PCI action list team '+new Date().toISOString().slice(0,10)+'.eml');
  toast('Outlook draft downloaded ('+list.length+' findings) — open the .eml, add the team and send.');
}
function toggleNoEv(){
  WL_NOEV=!WL_NOEV; if(WL_NOEV) WL_FU=false;
  const c=document.getElementById('chip-noev');
  c.classList.toggle('on',WL_NOEV); c.classList.toggle('hot',!WL_NOEV&&WL_ALL.some(f=>f._noEv));
  const g=document.getElementById('chip-fu');
  g.classList.remove('on'); g.classList.toggle('hot',WL_ALL.some(f=>f._fu));
  renderWorklist();
}
function toggleFu(){
  WL_FU=!WL_FU; if(WL_FU) WL_NOEV=false;
  const c=document.getElementById('chip-fu');
  c.classList.toggle('on',WL_FU); c.classList.toggle('hot',!WL_FU&&WL_ALL.some(f=>f._fu));
  const g=document.getElementById('chip-noev');
  g.classList.remove('on'); g.classList.toggle('hot',WL_ALL.some(f=>f._noEv));
  renderWorklist();
}
// One-click chase: ask the assessor to re-review the evidence already uploaded.
function followUp(i){
  const f=WL_ALL[i]; if(!f) return;
  const key=jiraKey(f.jira);
  if(!key){ toast('No Jira ticket linked to this finding — add one first.',1); return; }
  const pre='Follow-up: the requested evidence has been uploaded and is linked in the Assessment Gap Report'
    +' for "'+(f.section||f.area)+'". Could you please re-review and confirm whether anything further is required to close this finding? Thank you.';
  commentOn(key,pre);
}
function refreshNoEv(){
  WL_ALL.forEach(f=>{
    const hasEv=(f.clients||[]).some(c=>c.v);
    f._noEv=_norm(f.fib_status||'')==='done' && !hasEv;
    // evidence uploaded + work in progress, yet the assessor still has it Open
    const live=_LIVE[jiraKey(f.jira)];
    const moving=_norm(f.fib_status||'')==='inprogress' ||
                 (live && live.category!=='done' && /progress/i.test(live.status||''));
    f._fu=hasEv && moving && _norm(f.status||'')==='open';
  });
  const n=WL_ALL.filter(f=>f._noEv).length;
  const el=document.getElementById('sn-noev'); if(el) el.textContent=n;
  const c=document.getElementById('chip-noev'); if(c) c.classList.toggle('hot',n>0&&!WL_NOEV);
}
function filterArea(name){
  const sel=document.getElementById('f-area');
  sel.value=(sel.value===name)?'':name;      // click the same block again to clear
  renderWorklist();
  document.getElementById('wl-body').scrollIntoView({block:'nearest'});
}
// ── Write an edit back into the Box workbook (FIB Status / Link only) ──
function toast(msg,bad){
  let t=document.getElementById('toast');
  if(!t){ t=document.createElement('div'); t.id='toast'; document.body.appendChild(t); }
  t.textContent=msg; t.className='show'+(bad?' bad':'');
  clearTimeout(window._tt); window._tt=setTimeout(()=>{t.className='';},bad?6000:2600);
}
/* ─────────── Roadmap: phases you build, from start to certification ───────────
   Stored shared-side so everyone sees the same chain. The last node is the
   finish flag and is always kept at the end.                                  */
let PHASES=null;
const PH_COLORS=['#0f9389','#2563eb','#7c3aed','#db2777','#f59e0b','#ef4444','#0891b2','#64748b'];
const PH_DEFAULT=[
  {id:'p1',title:'Initiation',      note:'Kick-off, scope & team',        color:'#0f9389',status:'done'},
  {id:'p2',title:'Gap Assessment',  note:'Assessor review of all areas',  color:'#2563eb',status:'doing'},
  {id:'p3',title:'Remediation',     note:'Close findings, collect evidence',color:'#7c3aed',status:'todo'},
  {id:'p4',title:'Validation',      note:'Assessor re-check & sign-off',  color:'#f59e0b',status:'todo'},
  {id:'pf',title:'Certified',       note:'PCI DSS certification achieved',color:'#0f9389',status:'todo',flag:true},
];
async function loadPhases(){
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'phases_get'})});
    if(r.ok){ const d=await r.json(); PHASES=(d.phases&&d.phases.length)?d.phases:PH_DEFAULT.slice(); }
  }catch(e){}
  if(!PHASES) PHASES=PH_DEFAULT.slice();
  renderChain();
}
async function savePhases(){
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},
      body:JSON.stringify({action:'phases_set',phases:PHASES})});
    if(!r.ok){ const d=await r.json().catch(()=>({})); throw new Error(d.message||('HTTP '+r.status)); }
    toast('Roadmap saved ✓');
  }catch(e){ toast('Could not save roadmap: '+e.message,1); }
}
function renderChain(){
  const el=document.getElementById('chain'); if(!el||!PHASES) return;
  // keep the finish flag last
  const fi=PHASES.findIndex(p=>p.flag);
  if(fi>=0&&fi!==PHASES.length-1) PHASES.push(PHASES.splice(fi,1)[0]);
  const lastDone=PHASES.reduce((a,p,i)=>p.status==='done'?i:a,-1);
  const label={todo:'Not started',doing:'In progress',done:'Done'};
  el.innerHTML=PHASES.map((p,i)=>{
    const done=p.status==='done';
    const lit=i<=lastDone;                       // green line up to the last completed phase
    const mark=p.flag?'⚑':(done?'✓':(p.status==='doing'?'●':i+1));
    const dot=done?'':`style="border-color:${esc(p.color)};color:${esc(p.color)}"`;
    return `<div class="ph ${done?'done':''} ${lit?'lit':''} ${p.flag?'flag':''}" draggable="true" data-i="${i}"
              onclick="editPhase(${i})" title="Click to edit · drag to reorder">
      <div class="ph-dot" ${dot}>${mark}</div>
      <div class="ph-body"><div class="ph-t">${esc(p.title)}</div>
        ${p.note?`<div class="ph-n">${esc(p.note)}</div>`:''}
        <span class="ph-s" ${done?'style="background:#dcfce7;color:#166534"':(p.status==='doing'?`style="background:${esc(p.color)}1a;color:${esc(p.color)}"`:'')}>${label[p.status]}</span>
      </div></div>`;
  }).join('')+`<div class="ph-add"><button onclick="event.stopPropagation();addPhase()">+ Phase</button></div>`;
  const done=PHASES.filter(p=>p.status==='done').length;
  document.getElementById('ph-sub').textContent=done+' of '+PHASES.length+' phases complete · drag to reorder · click to edit';
  wireChainDrag();
}
let _drag=null;
function wireChainDrag(){
  document.querySelectorAll('#chain .ph').forEach(n=>{
    n.ondragstart=e=>{_drag=+n.dataset.i; n.classList.add('drag'); e.dataTransfer.effectAllowed='move';};
    n.ondragend=()=>{_drag=null; document.querySelectorAll('#chain .ph').forEach(x=>x.classList.remove('drag','over'));};
    n.ondragover=e=>{e.preventDefault(); n.classList.add('over');};
    n.ondragleave=()=>n.classList.remove('over');
    n.ondrop=e=>{e.preventDefault(); const to=+n.dataset.i;
      if(_drag===null||_drag===to) return;
      PHASES.splice(to,0,PHASES.splice(_drag,1)[0]);
      renderChain(); savePhases();};
  });
}
function addPhase(){
  if(!PHASES) return;
  const at=Math.max(0,PHASES.findIndex(p=>p.flag));           // insert before the finish flag
  PHASES.splice(at<0?PHASES.length:at,0,
    {id:'p'+Date.now(),title:'New phase',note:'',color:PH_COLORS[PHASES.length%PH_COLORS.length],status:'todo'});
  renderChain(); savePhases();
  editPhase(at<0?PHASES.length-1:at);
}
function editPhase(i){
  const p=PHASES[i]; if(!p) return;
  const m=document.getElementById('ov-modal'); m.classList.remove('full','wide');
  document.getElementById('ov-body').classList.remove('flush');
  document.getElementById('ov-title').textContent='Edit phase';
  document.getElementById('ov-body').innerHTML=`
    <label class="flab">Title</label>
    <input id="ph-title" class="fld" value="${esc(p.title)}" maxlength="80">
    <label class="flab">Note</label>
    <textarea id="ph-note" class="fld" rows="3" maxlength="400" placeholder="Optional detail…">${esc(p.note||'')}</textarea>
    <label class="flab">Status</label>
    <select id="ph-status" class="fld">
      <option value="todo"${p.status==='todo'?' selected':''}>Not started</option>
      <option value="doing"${p.status==='doing'?' selected':''}>In progress</option>
      <option value="done"${p.status==='done'?' selected':''}>Done (bullet turns green)</option>
    </select>
    <label class="flab">Colour</label>
    <div class="sw" id="ph-sw">${PH_COLORS.map(c=>`<b data-c="${c}" style="background:${c}" class="${c===p.color?'on':''}" onclick="phPick(this)"></b>`).join('')}</div>
    <div class="f-links" style="margin-top:20px">
      <button class="cbtn" onclick="phMove(${i},-1)">◀ Move left</button>
      <button class="cbtn" onclick="phMove(${i},1)">Move right ▶</button>
      ${p.flag?'':`<button class="cbtn" style="color:#b91c1c;border-color:#fca5a5" onclick="phDelete(${i})">Delete</button>`}
      <button class="cbtn" style="background:var(--teal);color:#fff;border-color:var(--teal)" onclick="phSave(${i})">Save phase</button>
    </div>`;
  document.getElementById('ov').classList.add('show');
}
function phPick(b){ document.querySelectorAll('#ph-sw b').forEach(x=>x.classList.remove('on')); b.classList.add('on'); }
function phSave(i){
  const p=PHASES[i]; if(!p) return;
  p.title=(document.getElementById('ph-title').value||'Phase').trim().slice(0,80);
  p.note=(document.getElementById('ph-note').value||'').trim().slice(0,400);
  p.status=document.getElementById('ph-status').value;
  const sw=document.querySelector('#ph-sw b.on'); if(sw) p.color=sw.dataset.c;
  closeOv(); renderChain(); savePhases();
}
function phMove(i,d){
  const j=i+d; if(j<0||j>=PHASES.length) return;
  PHASES.splice(j,0,PHASES.splice(i,1)[0]);
  closeOv(); renderChain(); savePhases();
}
function phDelete(i){
  if(!confirm('Delete phase "'+PHASES[i].title+'"?')) return;
  PHASES.splice(i,1); closeOv(); renderChain(); savePhases();
}
const ovKey=(sheet,cell)=>String(sheet).trim()+'!'+cell;   // must match the worker
async function loadOverlay(){
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'overlay_get'})});
    if(r.ok){ const d=await r.json(); OVERLAY=d.overlay||{}; }
  }catch(e){}
}
// Compare every pending edit with the value now in the Box workbook; anything
// that already matches has been uploaded, so it stops being "pending".
function reconcilePending(){
  if(!Object.keys(OVERLAY).length||!WL_ALL.length) return;
  const raw={};                                   // sheet!cell -> value as it is in Box
  WL_ALL.forEach(f=>{
    const s=String(f._sheet).trim();
    if(f._cFib)   raw[s+'!'+f._cFib+f._row]=f.fib_status||'';
    if(f._cLink)  raw[s+'!'+f._cLink+f._row]=f.jira||'';
    (f.clients||[]).forEach(c=>{ raw[s+'!'+c.c+f._row]=c.v||''; });
  });
  const landed=[];
  Object.keys(OVERLAY).forEach(k=>{
    const inBox=raw[k];
    if(inBox===undefined) return;                 // cell we can't see — leave it alone
    if(_norm(inBox)===_norm(OVERLAY[k].value)) landed.push(k);
  });
  if(!landed.length) return;
  landed.forEach(k=>delete OVERLAY[k]);
  const pw=sessionStorage.getItem('pci_pw')||'';
  fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},
    body:JSON.stringify({action:'overlay_clear',ids:landed})}).catch(()=>{});
  toast(landed.length+' edit'+(landed.length>1?'s':'')+' confirmed in Box ✓ — cleared from pending.');
}
function pendingCount(){ return Object.keys(OVERLAY).length; }
function updatePendingUI(){
  const n=pendingCount();
  document.getElementById('pend-n').textContent=n;
  document.getElementById('wl-export').style.display=n?'':'none';
  document.getElementById('wl-clear').style.display=n?'':'none';
}
async function saveCell(i,field,value,el){
  const f=WL_ALL[i]; if(!f) return;
  const col=field==='fib_status'?f._cFib:(field==='client'?f._cClient:f._cLink);
  if(!col){ toast('That column does not exist in this sheet.',1); return; }
  const prev=f[field]||'';
  const pw=sessionStorage.getItem('pci_pw')||'';
  if(el) el.disabled=true; toast('Saving…');
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},
      body:JSON.stringify({action:'overlay_set',sheet:f._sheet,cell:col+f._row,value,field})});
    const d=await r.json().catch(()=>({}));
    if(!r.ok){
      if(el){ el.disabled=false; if(el.tagName==='SELECT') el.value=prev; }
      toast('Save failed: '+(d.message||('HTTP '+r.status)),1); return;
    }
    OVERLAY[ovKey(f._sheet,col+f._row)]={sheet:f._sheet.trim(),cell:col+f._row,field,value};
    if(field==='client'){ if(f.clients&&f.clients[0]) f.clients[0].v=value; f.client_comments=value; f._pendClient=true; }
    else { f[field]=value; if(field==='link') f.jira=value; }
    if(el) el.disabled=false;
    refreshNoEv(); updatePendingUI(); renderWorklist();
    toast('Saved ✓ — everyone sees it now. Download the workbook to push it into Box.');
  }catch(e){ if(el) el.disabled=false; toast('Save failed: '+e.message,1); }
}
// ── Apply pending edits to the real .xlsx and hand it back for upload to Box ──
function _xmlEsc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function _colNum(ref){ let n=0; for(const ch of /^[A-Z]+/.exec(ref)[0]) n=n*26+(ch.charCodeAt(0)-64); return n; }
// Locate one <c> element exactly. A plain regex is unsafe here: cells are often
// self-closing (<c r="I13" s="144"/>) and a greedy [^>]* eats the "/" then runs
// on to the NEXT </c>, silently swallowing the following cell.
function _findCell(rowXml,cellRef){
  const m=new RegExp('<c\\s[^>]*r="'+cellRef+'"').exec(rowXml);
  if(!m) return null;
  const start=m.index, gt=rowXml.indexOf('>',start);
  if(gt<0) return null;
  if(rowXml[gt-1]==='/') return {start,end:gt+1};
  const close=rowXml.indexOf('</c>',gt);
  return {start,end:close<0?gt+1:close+4};
}
// Read a cell's text, resolving shared strings, so we can find a cell that
// already holds the value we're writing and borrow its formatting.
function _parseShared(xml){
  const out=[]; if(!xml) return out;
  for(const m of xml.matchAll(/<si>([\s\S]*?)<\/si>/g)){
    let s=''; for(const t of m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)) s+=t[1];
    out.push(s.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&'));
  }
  return out;
}
function _cellText(cx,shared){
  const t=/\st="([^"]+)"/.exec(cx), ty=t?t[1]:'';
  if(ty==='inlineStr'){ const m=/<is>[\s\S]*?<t[^>]*>([\s\S]*?)<\/t>/.exec(cx); return m?m[1]:''; }
  const v=/<v>([\s\S]*?)<\/v>/.exec(cx); if(!v) return '';
  if(ty==='s'){ const i=parseInt(v[1],10); return shared[i]!==undefined?shared[i]:''; }
  return v[1];
}
// Style index of an existing cell in the same column holding the same value —
// that's how "Done" keeps its green, "In progress" its amber, etc.
// "On Hold" / "ON-HOLD" / "on hold" are the same status as far as colour goes.
const _norm=s=>String(s).toLowerCase().replace(/[^a-z0-9]/g,'');
function _styleForValue(sheetXml,shared,col,value){
  const want=_norm(value); if(!want) return null;
  const re=new RegExp('<c\\s[^>]*r="'+(col||'[A-Z]+')+'\\d+"','g'); let m;
  while((m=re.exec(sheetXml))){
    const start=m.index, gt=sheetXml.indexOf('>',start); if(gt<0) continue;
    let end;
    if(sheetXml[gt-1]==='/') end=gt+1;
    else { const c=sheetXml.indexOf('</c>',gt); end=c<0?gt+1:c+4; }
    const cx=sheetXml.slice(start,end);
    if(_norm(_cellText(cx,shared))===want){
      const sm=/\ss="(\d+)"/.exec(cx); if(sm) return sm[1];
    }
  }
  return null;
}
function _patchCell(xml,cellRef,value,shared,styleHint){
  const rowNo=/^[A-Z]+(\d+)$/.exec(cellRef)[1];
  const col=/^[A-Z]+/.exec(cellRef)[0];
  const rm=new RegExp('<row [^>]*r="'+rowNo+'"[^>]*>[\\s\\S]*?</row>').exec(xml);
  if(!rm) throw new Error('row '+rowNo+' not found');
  const rowXml=rm[0];
  // this value's own look: same sheet+column first, else borrowed from any sheet
  const matched=_styleForValue(xml,shared||[],col,value)||styleHint||null;
  const inline=st=>'<c r="'+cellRef+'"'+st+' t="inlineStr"><is><t xml:space="preserve">'+_xmlEsc(value)+'</t></is></c>';
  const hit=_findCell(rowXml,cellRef);
  let newRow;
  if(hit){
    const old=rowXml.slice(hit.start,hit.end);
    const sm=/\ss="(\d+)"/.exec(old);
    const st=matched||(sm?sm[1]:null);
    newRow=rowXml.slice(0,hit.start)+inline(st?' s="'+st+'"':'')+rowXml.slice(hit.end);
  }else{
    // no cell yet — borrow the column's look from the row above so it isn't blank/white
    let st=matched;
    if(!st){
      const above=_findCell(rowXml,col+rowNo);
      if(!above){ const prev=new RegExp('<c\\s[^>]*r="'+col+'(\\d+)"[^>]*\\ss="(\\d+)"').exec(xml); if(prev) st=prev[2]; }
    }
    const target=_colNum(cellRef); let at=null;
    for(const c of rowXml.matchAll(/<c\s[^>]*r="([A-Z]+)\d+"/g)){ if(_colNum(c[1]+'1')>target){ at=c.index; break; } }
    if(at===null) at=rowXml.lastIndexOf('</row>');
    newRow=rowXml.slice(0,at)+inline(st?' s="'+st+'"':'')+rowXml.slice(at);
  }
  return xml.slice(0,rm.index)+newRow+xml.slice(rm.index+rowXml.length);
}
async function exportWorkbook(){
  const btn=document.getElementById('wl-export'); btn.disabled=true;
  toast('Building updated workbook…');
  try{
    const pw=sessionStorage.getItem('pci_pw')||'';
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw},body:JSON.stringify({action:'gaps'})});
    if(!r.ok) throw new Error('could not fetch the workbook');
    const zip=await JSZip.loadAsync(await r.arrayBuffer());
    const wbXml=await zip.file('xl/workbook.xml').async('string');
    const relsXml=await zip.file('xl/_rels/workbook.xml.rels').async('string');
    const pathFor=name=>{
      const want=name.trim().toLowerCase();
      for(const m of wbXml.matchAll(/<sheet[^>]*name="([^"]*)"[^>]*r:id="([^"]*)"[^>]*\/>/g)){
        const nm=m[1].replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>');
        if(nm.trim().toLowerCase()!==want) continue;
        const rel=new RegExp('<Relationship[^>]*Id="'+m[2]+'"[^>]*Target="([^"]*)"').exec(relsXml);
        return rel?('xl/'+rel[1].replace(/^\/?xl\//,'')):null;
      }
      return null;
    };
    const ssFile=zip.file('xl/sharedStrings.xml');
    const shared=_parseShared(ssFile?await ssFile.async('string'):'');
    // Style indexes are workbook-wide, so a colour used for "In Progress" on ANY
    // sheet can be reused here — that's how an edited cell keeps the right fill.
    const allXml=[];
    for(const m of wbXml.matchAll(/r:id="([^"]*)"/g)){
      const rel=new RegExp('<Relationship[^>]*Id="'+m[1]+'"[^>]*Target="([^"]*)"').exec(relsXml);
      const p=rel?('xl/'+rel[1].replace(/^\/?xl\//,'')):null;
      if(p&&/worksheets\//.test(p)&&zip.file(p)) allXml.push(await zip.file(p).async('string'));
    }
    const hints={};
    for(const k of Object.keys(OVERLAY)){
      const e=OVERLAY[k]; if(e.field!=='fib_status') continue;
      const key=String(e.value).trim().toLowerCase();
      if(!key||hints[key]!==undefined) continue;
      const col=/^[A-Z]+/.exec(e.cell)[0];
      let s=null;
      for(const sx of allXml){ s=_styleForValue(sx,shared,col,e.value); if(s) break; }
      if(!s) for(const sx of allXml){ s=_styleForValue(sx,shared,null,e.value); if(s) break; }
      hints[key]=s;
    }
    const byPath={};
    for(const k of Object.keys(OVERLAY)){
      const e=OVERLAY[k], p=pathFor(e.sheet);
      if(!p||!zip.file(p)) continue;
      if(!byPath[p]) byPath[p]=await zip.file(p).async('string');
      byPath[p]=_patchCell(byPath[p],e.cell,e.value,shared,hints[String(e.value).trim().toLowerCase()]);
    }
    let n=0;
    for(const p of Object.keys(byPath)){ zip.file(p,byPath[p]); n++; }
    const blob=await zip.generateAsync({type:'blob',compression:'DEFLATE',
      mimeType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
    a.download='Assessment Gap Report.xlsx'; document.body.appendChild(a); a.click();
    setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},2000);
    toast('Downloaded — upload it to Box as a new version, then hit "Mark as uploaded".');
  }catch(e){ toast('Export failed: '+e.message,1); }
  btn.disabled=false;
}
async function clearPending(){
  if(!confirm('Clear all '+pendingCount()+' pending edits?\n\nDo this only AFTER you have uploaded the updated workbook to Box, otherwise the changes will be lost.')) return;
  const pw=sessionStorage.getItem('pci_pw')||'';
  try{
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},body:JSON.stringify({action:'overlay_clear',all:true})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    OVERLAY={}; updatePendingUI(); loadGaps();
    toast('Pending edits cleared — now reading straight from Box.');
  }catch(e){ toast('Clear failed: '+e.message,1); }
}
// Map a live Jira status onto the workbook's FIB Status wording.
// "Open" in Jira means work is under way here, so it becomes In progress.
function fibFromJira(live){
  if(!live) return null;
  const done=live.category==='done';
  if(done) return FIB_OPTS.find(o=>_norm(o)==='done')||'Done';
  const s=_norm(live.status);
  if(s==='open') return FIB_OPTS.find(o=>_norm(o)==='inprogress')||'In progress';
  // any other Jira status that the workbook already uses (e.g. ON-HOLD) wins
  const exact=FIB_OPTS.find(o=>o&&_norm(o)===s);
  if(exact) return exact;
  if(s.includes('hold')) return FIB_OPTS.find(o=>_norm(o).includes('hold'))||'ON-HOLD';
  return FIB_OPTS.find(o=>_norm(o)==='inprogress')||'In progress';
}
async function syncFromJira(){
  const btn=document.getElementById('wl-sync');
  const changes=[];
  WL_ALL.forEach(f=>{
    if(!f._cFib) return;
    const key=jiraKey(f.jira); if(!key) return;
    const live=_LIVE[key]; if(!live) return;
    const target=fibFromJira(live); if(!target) return;
    if(_norm(target)===_norm(f.fib_status||'')) return;
    changes.push({f,target,from:f.fib_status||'(blank)',key,jira:live.status});
  });
  if(!changes.length){ toast('Every linked finding already matches Jira ✓'); return; }
  const sample=changes.slice(0,8).map(c=>`  ${c.f.area} r${c.f._row} · ${c.key} (${c.jira}) : ${c.from} → ${c.target}`).join('\n');
  if(!confirm('Set FIB Status from Jira for '+changes.length+' finding(s)?\n\n'+sample+
    (changes.length>8?`\n  …and ${changes.length-8} more`:'')+
    '\n\nThese become pending edits — download the workbook afterwards to push them into Box.')) return;
  btn.disabled=true; toast('Applying '+changes.length+' updates…');
  try{
    const pw=sessionStorage.getItem('pci_pw')||'';
    const items=changes.map(c=>({sheet:c.f._sheet,cell:c.f._cFib+c.f._row,field:'fib_status',value:c.target}));
    const r=await fetch(GH_PROXY,{method:'POST',headers:{'Content-Type':'application/json','X-Proxy-Auth':pw,'X-Comment-Auth':pw},
      body:JSON.stringify({action:'overlay_set_many',items})});
    const d=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(d.message||('HTTP '+r.status));
    changes.forEach(c=>{ c.f.fib_status=c.target; c.f._pendFib=true;
      OVERLAY[ovKey(c.f._sheet,c.f._cFib+c.f._row)]={sheet:c.f._sheet.trim(),cell:c.f._cFib+c.f._row,field:'fib_status',value:c.target}; });
    refreshNoEv(); updatePendingUI(); renderWorklist();
    toast('Updated '+d.applied+' FIB statuses from Jira ✓ — download the workbook to push them to Box.');
  }catch(e){ toast('Sync failed: '+e.message,1); }
  btn.disabled=false;
}
function editTicket(i){
  const f=WL_ALL[i]; if(!f) return;
  const cur=f.jira||'';
  const v=prompt('Jira ticket for this finding — paste a key (FIBXPI-123) or full URL.\nLeave empty to clear.',cur);
  if(v===null) return;
  let val=v.trim();
  if(val && /^[A-Za-z]+-\d+$/.test(val)) val='https://fibtask.atlassian.net/browse/'+val.toUpperCase();
  saveCell(i,'link',val,null);
}
function editClient(i){
  const f=WL_ALL[i]; if(!f||!f._cClient) return;
  const cur=(f.clients&&f.clients[0]&&f.clients[0].v)||'';
  const v=prompt('Client comment / evidence link (paste the full URL — the table shows only its last 3 characters).\nLeave empty to clear.',cur);
  if(v===null) return;
  saveCell(i,'client',v.trim(),null);
}
function renderGaps(){
  const gs=GAPS.summary||{}, areas=GAPS.areas||[];
  // progress strip
  document.getElementById('gap-pct').textContent=(gs.pct||0)+'%';
  setTimeout(()=>{document.getElementById('gap-barfill').style.width=(gs.pct||0)+'%';},60);
  document.getElementById('sn-closed').textContent=(gs.closed||0);
  document.getElementById('sn-closed2').textContent=(gs.closed||0);
  document.getElementById('sn-open').textContent=(gs.open||0);
  document.getElementById('sn-total').textContent=(gs.total||0);
  // flatten findings into one worklist
  WL_ALL=[]; areas.forEach(a=>(a.findings||[]).forEach((f,i)=>WL_ALL.push(Object.assign({},f,{area:a.name,n:i+1}))));
  WL_ALL.forEach((f,i)=>f._i=i);
  // Reconcile against Box: any pending edit whose value already matches the
  // freshly-downloaded workbook has clearly been uploaded, so drop it. That
  // keeps "not in Box yet" honest — it only ever means "still to upload".
  // Costs nothing: the workbook is already parsed, this is a string compare.
  reconcilePending();
  // lay pending edits over the values read from Box so everyone sees them now.
  // Keys use the TRIMMED sheet name to match how the worker stores them —
  // "HR & Access Control " has a trailing space in the workbook.
  WL_ALL.forEach(f=>{
    const a=f._cFib&&OVERLAY[ovKey(f._sheet,f._cFib+f._row)];
    if(a){ f.fib_status=a.value; f._pendFib=true; }
    const b=f._cLink&&OVERLAY[ovKey(f._sheet,f._cLink+f._row)];
    if(b){ f.jira=b.value; f._pendLink=true; }
    (f.clients||[]).forEach(c=>{
      const o=OVERLAY[ovKey(f._sheet,c.c+f._row)];
      if(o){ c.v=o.value; f._pendClient=true; if(c.c===f._cClient) f.client_comments=o.value; }
    });
  });
  // "Done" in FIB status but no client evidence link — the thing to chase
  WL_ALL.forEach(f=>{
    const hasEv=(f.clients||[]).some(c=>c.v);
    f._noEv=_norm(f.fib_status||'')==='done' && !hasEv;
    // evidence uploaded + work in progress, yet the assessor still has it Open
    const live=_LIVE[jiraKey(f.jira)];
    const moving=_norm(f.fib_status||'')==='inprogress' ||
                 (live && live.category!=='done' && /progress/i.test(live.status||''));
    f._fu=hasEv && moving && _norm(f.status||'')==='open';
  });
  const nNoEv=WL_ALL.filter(f=>f._noEv).length;
  document.getElementById('sn-noev').textContent=nNoEv;
  document.getElementById('chip-noev').classList.toggle('hot',nNoEv>0&&!WL_NOEV);
  const nFu=WL_ALL.filter(f=>f._fu).length;
  document.getElementById('sn-fu').textContent=nFu;
  document.getElementById('chip-fu').classList.toggle('hot',nFu>0&&!WL_FU);
  updatePendingUI();
  // FIB status choices = the workbook's own wording, de-duplicated across
  // spelling variants ("In Progress"/"In progress"), keeping the commonest.
  const counts={};
  WL_ALL.forEach(f=>{ const v=(f.fib_status||'').trim(); if(!v) return;
    const k=_norm(v); (counts[k]=counts[k]||{}); counts[k][v]=(counts[k][v]||0)+1; });
  ['Done','In Progress','On Hold','Not Started'].forEach(v=>{ const k=_norm(v); if(!counts[k]) counts[k]={[v]:0}; });
  FIB_OPTS=[''].concat(Object.values(counts)
    .map(m=>Object.entries(m).sort((a,b)=>b[1]-a[1])[0][0]).sort());
  // area filter options
  const sel=document.getElementById('f-area'), keepA=sel.value;
  sel.innerHTML='<option value="">All areas ('+WL_ALL.length+')</option>'+
    areas.map(a=>`<option value="${esc(a.name)}">${esc(a.name)} (${a.total})</option>`).join('');
  sel.value=keepA;
  const fsel=document.getElementById('f-fib'), keepF=fsel.value;
  const fibCount={}; WL_ALL.forEach(f=>{ const k=(f.fib_status||'').trim()||'—'; fibCount[k]=(fibCount[k]||0)+1; });
  fsel.innerHTML='<option value="">All FIB status</option>'+
    Object.keys(fibCount).sort().map(k=>`<option value="${esc(k)}">${esc(k)} (${fibCount[k]})</option>`).join('');
  fsel.value=keepF;
  renderWorklist();
}
function renderWorklist(){
  const q=(document.getElementById('f-search').value||'').toLowerCase().trim();
  const fst=document.getElementById('f-status').value;
  const far=document.getElementById('f-area').value;
  const ffib=document.getElementById('f-fib').value;
  let rows=WL_ALL.filter(f=>{
    if(WL_NOEV && !f._noEv) return false;
    if(WL_FU && !f._fu) return false;
    if(far && f.area!==far) return false;
    if(fst && f.status!==fst) return false;
    if(ffib){ const cur=(f.fib_status||'').trim()||'—'; if(cur!==ffib) return false; }
    if(q){ const hay=(f.area+' '+f.section+' '+f.observation+' '+f.evidence_required+' '+f.recommendation+' '+f.jira+' '+f.fib_status).toLowerCase(); if(!hay.includes(q)) return false; }
    return true;
  });
  WL_VIEW=rows;                                  // what the Outlook export sends
  document.getElementById('wl-count').textContent=rows.length+' of '+WL_ALL.length+' findings';
  const mn=document.getElementById('mail-n'); if(mn) mn.textContent=rows.length;
  const mt=document.getElementById('mail-t'); if(mt) mt.textContent=rows.length;
  const body=document.getElementById('wl-body');
  if(!rows.length){ body.innerHTML='<tr><td colspan="6" style="color:#94a3b8;padding:16px">No findings match.</td></tr>'; return; }
  body.innerHTML=rows.map(f=>{
    const st=(f.status||'').toLowerCase();
    const stTag=st==='closed'?'<span class="st-tag closed">Closed</span>':(st==='open'?'<span class="st-tag open">Open</span>':`<span class="st-tag na">${esc(f.status||'—')}</span>`);
    const key=jiraKey(f.jira);
    const live=key&&_LIVE[key]?_LIVE[key]:null;
    const liveChip=live?`<div class="tk-live ${live.category==='done'?'done':(live.category==='new'?'todo':'prog')}"><span class="tk-dot"></span>${esc(live.status)}</div>`:'';
    const pen=f._cLink?`<button class="pen" title="Edit ticket — saves to the Box workbook" onclick="event.stopPropagation();editTicket(${f._i})">✎</button>`:'';
    const tk=(key?`<a class="wl-tk-a" href="${esc(f.jira)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(key)}</a>`:'<span class="none">no ticket</span>')+pen+liveChip;
    // Client comments: show only the last 3 characters of each link, like a tag.
    const chips=(f.clients||[]).map((c,ci2)=>{
      if(!c.v) return '';
      const url=/^https?:\/\//i.test(c.v);
      const tail=c.v.replace(/[\/\s]+$/,'').slice(-3);
      return url
        ? `<a class="cl-chip" href="${esc(c.v)}" target="_blank" rel="noopener" title="${esc(c.h)}: ${esc(c.v)}" onclick="event.stopPropagation()">${esc(tail)}</a>`
        : `<span class="cl-chip txt" title="${esc(c.h)}: ${esc(c.v)}">${esc(c.v.slice(0,3))}</span>`;
    }).filter(Boolean).join('');
    const noLink=`<span class="none warn${f._noEv?' pulse':''}"${f._noEv?' title="FIB status is Done but no evidence link — add one"':''}>no link</span>`;
    const clientCell=(chips||noLink)
      +(f._cClient?`<button class="pen" title="Edit client comment link" onclick="event.stopPropagation();editClient(${f._i})">✎</button>`:'')
      +(f._pendClient?'<div class="pendtag">● not in Box yet</div>':'');
    const fs=(f.fib_status||'').toLowerCase();
    const fcls=fs.includes('done')?' v-done':(fs.includes('progress')?' v-prog':(fs.includes('hold')?' v-hold':(fs.includes('not start')?' v-todo':'')));
    const fibCell=(f._cFib
      ? `<select class="fibsel${fcls}${f._pendFib?' pend':''}" onclick="event.stopPropagation()" onchange="saveCell(${f._i},'fib_status',this.value,this)">`+
        FIB_OPTS.map(o=>`<option value="${esc(o)}"${(f.fib_status||'')===o?' selected':''}>${esc(o||'—')}</option>`).join('')+`</select>`
      : `<span class="fib-tag">${esc(f.fib_status||'—')}</span>`)
      +(f._pendFib?'<div class="pendtag">● not in Box yet</div>':'')
      +(f._fu?`<div><span class="fu-badge" title="Evidence is uploaded but the assessor still has this Open — click to ask them to re-review" onclick="event.stopPropagation();followUp(${f._i})">⚑ Quick follow-up</span></div>`:'');
    const sec=f.section?`<span style="color:#64748b">${esc(f.section)} · </span>`:'';
    return `<tr class="f-open${f._noEv?' needs-ev':''}" onclick="this.classList.toggle('exp')">
      <td><div class="wl-area">${esc(f.area)}</div></td>
      <td><div class="wl-obs">${sec}${esc(f.observation||'—')}</div>
        ${f.evidence_required?`<div class="wl-ev"><b>Evidence:</b> ${esc(f.evidence_required)}</div>`:''}
        <div class="wl-more">
          ${f.recommendation?`<div class="m1"><b>Recommendation:</b> ${esc(f.recommendation)}</div>`:''}
          ${f.assessor_comments?`<div class="m1" style="color:#64748b"><b>Assessor:</b> ${esc(f.assessor_comments)}</div>`:''}
          ${(f.extras||[]).map(x=>{
            const link=/^https?:\/\//i.test(x.v);
            const val=link?`<a href="${esc(x.v)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(x.v.length>70?x.v.slice(0,70)+'…':x.v)}</a>`:esc(x.v);
            return `<div class="m1 mx"><b>${esc(x.h)}:</b> ${val}</div>`;}).join('')}
          <div class="wl-acts">${key?`<a class="cbtn" href="${esc(f.jira)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="text-decoration:none">Open ${esc(key)} ↗</a><button class="cbtn" onclick="event.stopPropagation();commentOn('${esc(key)}')">💬 Comment</button>`:'<span style="font-size:11.5px;color:#94a3b8">No linked Jira ticket</span>'}</div>
        </div></td>
      <td class="wl-tk">${tk}</td>
      <td class="wl-tk">${clientCell}</td>
      <td>${stTag}</td>
      <td>${fibCell}</td></tr>`;
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
