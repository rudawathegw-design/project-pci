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

# Box evidence embeds (share links).
EVIDENCE = {
    "evidences": "https://app.box.com/embed/s/698kt3rxy7akyza01za5lmtr68t6zdq4?sortColumn=date",
    "whole":     "https://app.box.com/embed/s/cjmt5wsne4qd585uaqfqf2n1jmocx6qx?sortColumn=date",
}

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
#gate{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#0b1f3a,#0a1830);overflow:hidden}
#gate::before{content:"";position:absolute;inset:0;opacity:.14;background-image:linear-gradient(#ffffff22 1px,transparent 1px),linear-gradient(90deg,#ffffff22 1px,transparent 1px);background-size:40px 40px}
.gate-card{position:relative;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:20px;padding:34px;width:min(400px,92vw);backdrop-filter:blur(8px);color:#fff;box-shadow:0 30px 80px rgba(0,0,0,.45)}
.gate-badge{font-size:11px;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#5eead4}
.gate-title{font-size:23px;font-weight:800;margin-top:8px}
.gate-sub{color:#a9b7cc;font-size:13.5px;margin-top:8px;line-height:1.5}
.gate-inp{width:100%;margin-top:18px;border:1.5px solid rgba(255,255,255,.2);background:rgba(0,0,0,.25);color:#fff;border-radius:11px;padding:13px 15px;font-size:15px;outline:none;letter-spacing:2px}
.gate-inp:focus{border-color:#5eead4}
.gate-btn{width:100%;margin-top:12px;border:none;border-radius:11px;padding:13px;font-weight:800;font-size:15px;color:#04231f;background:linear-gradient(90deg,#2dd4bf,#0f9389);cursor:pointer}
.gate-btn:disabled{opacity:.7;cursor:wait}
.gate-err{color:#fca5a5;font-size:12.5px;height:16px;margin-top:8px}
.gate-foot{color:#7c8aa3;font-size:11px;margin-top:18px}
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
.foot{color:var(--slate);font-size:11.5px;text-align:center;margin:24px 0 8px}
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
  <video id="introv" src="intro.mp4" muted playsinline preload="auto"></video>
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
  <div class="hero">
    <div class="hcard dark"><div class="hflex">
      <div><div class="hlbl">Journey to certification</div><div class="hbig" id="road-pct">0%</div><div class="hsub" id="road-sub">—</div></div>
      <div class="ring" id="road-ring"><i id="road-ring-n">0%</i></div></div></div>
    <div class="hcard"><div class="hlbl">Gap remediation</div><div class="hbig" id="gap-pct" style="color:var(--teal-d)">0%</div><div class="hsub" id="gap-sub">—</div></div>
    <div class="hcard"><div class="hlbl">Current phase</div><div class="hbig" id="cur-phase" style="font-size:22px;line-height:1.15;margin-top:12px">—</div><div class="hsub" id="cur-sub">—</div></div>
  </div>
  <div class="sec"><div class="sec-h"><div class="sec-t">Project journey <small>start → certification</small></div></div><div class="journey" id="journey"></div></div>
  <div class="sec"><div class="sec-h"><div class="sec-t">Gap remediation by area <small id="gap-count"></small></div></div><div class="gaps" id="gaps"></div></div>
  <div class="sec"><div class="sec-h"><div class="sec-t">Evidence <small>documents & proofs on Box</small></div></div>
    <div class="ev-row">
      <div class="ev-btn" onclick="openEvidence('evidences')"><div class="t">📁 Evidence library</div><div class="s">Screenshots, configs & supporting proofs</div></div>
      <div class="ev-btn" onclick="openEvidence('whole')"><div class="t">🗂️ Full evidence set</div><div class="s">Complete shared evidence folder</div></div>
    </div>
  </div>
  <div class="foot">First Iraq Bank · PCI DSS Compliance Cockpit · generated <span id="gen2"></span></div>
</div></div>
<div class="ov" id="ov" onclick="if(event.target===this)closeOv()"><div class="modal" id="ov-modal">
  <div class="m-head"><h3 id="ov-title">Area</h3><button class="m-close" onclick="closeOv()">Close</button></div>
  <div class="m-body" id="ov-body"></div>
</div></div>
<script>
const ENC = /*__ENC__*/{};
const EVIDENCE = /*__EVIDENCE__*/{};
const GH_PROXY = "__GH_PROXY__";
let PCI = null;
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
function render(){
  document.getElementById('proj').textContent=PCI.project||'';
  document.getElementById('gen').textContent='Updated '+(PCI.generated||'');
  document.getElementById('gen2').textContent=PCI.generated||'';
  document.getElementById('app').style.display='block';
  const phases=(PCI.roadmap&&PCI.roadmap.phases)||[];
  let td=0,tt=0; phases.forEach(p=>{td+=p.done||0;tt+=p.total||0;});
  const roadPct=tt?Math.round(100*td/tt):0;
  document.getElementById('road-pct').textContent=roadPct+'%';
  document.getElementById('road-ring').style.setProperty('--p',roadPct);
  document.getElementById('road-ring-n').textContent=roadPct+'%';
  document.getElementById('road-sub').textContent=td+' of '+tt+' plan tasks complete · '+phases.length+' phases';
  const gs=(PCI.gaps&&PCI.gaps.summary)||{};
  document.getElementById('gap-pct').textContent=(gs.pct||0)+'%';
  document.getElementById('gap-sub').textContent=(gs.closed||0)+' of '+(gs.total||0)+' findings closed';
  const active=[...phases].reverse().find(p=>p.status==='In Progress')||phases.find(p=>p.status!=='Completed')||phases[phases.length-1];
  document.getElementById('cur-phase').textContent=active?active.title:'—';
  document.getElementById('cur-sub').textContent=active?(active.pct+'% · '+active.done+'/'+active.total+' tasks'):'';
  document.getElementById('journey').innerHTML=phases.map((p,i)=>{
    const done=p.status==='Completed', act=p===active&&!done, cls=done?'done':(act?'active':'');
    return `<div class="jp ${cls}"><div class="bar"><i style="width:${p.pct||0}%"></i></div>
      <div class="dot">${done?'✓':(i+1)}</div><div class="jp-name">${esc(p.title)}</div>
      <div class="jp-meta">${p.pct||0}% · ${p.done||0}/${p.total||0}</div></div>`;
  }).join('');
  const areas=(PCI.gaps&&PCI.gaps.areas)||[];
  document.getElementById('gap-count').textContent=areas.length+' areas · '+(gs.total||0)+' findings';
  document.getElementById('gaps').innerHTML=areas.map((a,idx)=>{
    const col=statusColor(a.pct);
    return `<div class="gcard" onclick="openArea(${idx})"><div class="gc-top"><div class="gc-name">${esc(a.name)}</div>
      <div class="gc-pct" style="color:${col}">${a.pct}%</div></div>
      <div class="gc-bar"><i style="width:${a.pct}%;background:${col}"></i></div>
      <div class="gc-meta"><span class="pill"><span class="dot-o"></span> <b>${a.open}</b> open</span>
      <span class="pill"><span class="dot-c"></span> <b>${a.closed}</b> closed</span>
      <span style="margin-left:auto">${a.total} total</span></div></div>`;
  }).join('');
}
function openArea(idx){
  const a=(PCI.gaps.areas||[])[idx]; if(!a) return;
  document.getElementById('ov-modal').classList.remove('wide');
  document.getElementById('ov-body').classList.remove('flush');
  document.getElementById('ov-title').textContent=a.name+' — '+a.closed+'/'+a.total+' closed ('+a.pct+'%)';
  document.getElementById('ov-body').innerHTML=(a.findings||[]).map((f,i)=>{
    const st=(f.status||'').toLowerCase();
    const stTag=st==='closed'?'<span class="tag closed">Closed</span>':(st==='open'?'<span class="tag open">Open</span>':'');
    const fib=f.fib_status?`<span class="tag fib">${esc(f.fib_status)}</span>`:'';
    const key=jiraKey(f.jira);
    const links=f.jira?`<div class="f-links"><a href="${esc(f.jira)}" target="_blank" rel="noopener">Jira ${esc(key||'ticket')} ↗</a></div>`:'';
    return `<div class="finding"><div class="f-top"><span class="f-sec">${i+1}. ${esc(f.section||'Finding')}</span>${stTag}${fib}</div>
      ${f.observation?`<div class="f-row"><b>Observation:</b> ${esc(f.observation)}</div>`:''}
      ${f.recommendation?`<div class="f-row"><b>Recommendation:</b> ${esc(f.recommendation)}</div>`:''}
      ${f.evidence_required?`<div class="f-row"><b>Evidence required:</b> ${esc(f.evidence_required)}</div>`:''}
      ${f.assessor_comments?`<div class="f-row" style="color:#64748b"><b>Assessor:</b> ${esc(f.assessor_comments)}</div>`:''}
      ${links}</div>`;
  }).join('')||'<div style="padding:20px;color:#94a3b8">No findings.</div>';
  document.getElementById('ov').classList.add('show');
}
function openEvidence(which){
  const url=EVIDENCE[which]; if(!url) return;
  document.getElementById('ov-modal').classList.add('wide');
  document.getElementById('ov-title').textContent = which==='whole'?'Full evidence set':'Evidence library';
  const b=document.getElementById('ov-body'); b.classList.add('flush');
  b.innerHTML=`<iframe src="${esc(url)}" style="width:100%;height:70vh;border:0;display:block" allowfullscreen></iframe>`;
  document.getElementById('ov').classList.add('show');
}
function closeOv(){ document.getElementById('ov').classList.remove('show'); document.getElementById('ov-body').innerHTML=''; }
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
