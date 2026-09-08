/**
 * project-pci-proxy — Cloudflare Worker for the PCI DSS cockpit.
 * Holds the Jira token server-side (never in the page). Read-only FIBXPI status
 * for the cockpit, plus comment posting. Gated by the cockpit password
 * (X-Proxy-Auth == SITE_PASSWORD). Comments also require X-Comment-Auth.
 *
 * Secrets: JIRA_EMAIL, JIRA_API_TOKEN, SITE_PASSWORD (="pci"), COMMENT_PASSWORD (optional)
 * Vars: ALLOWED_ORIGIN, JIRA_BASE_URL, JIRA_PROJECT
 */
import { unzipSync, zipSync, strToU8, strFromU8 } from "fflate";

const DEFAULT_BASE = "https://fibtask.atlassian.net";
const DEFAULT_PROJECT = "FIBXPI";

/* ─────────────── Box write-back helpers ───────────────
   The cockpit edits only two columns (FIB Status, Link). We patch the single
   cell inside the .xlsx zip rather than re-writing the workbook, so formulas,
   styles, merges and the logo all survive untouched. Verified against the real
   workbook: =COUNTIF(...) formulas and cell styles are preserved.            */

function xmlEsc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function colNum(ref) {
  const letters = /^[A-Z]+/.exec(ref)[0];
  let n = 0; for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n;
}
// Locate one <c> element exactly. A plain regex is unsafe: cells are often
// self-closing (<c r="I13" s="144"/>) and a greedy [^>]* eats the "/" then runs
// on to the NEXT </c>, silently swallowing the following cell.
function findCell(rowXml, cellRef) {
  const m = new RegExp(`<c\\s[^>]*r="${cellRef}"`).exec(rowXml);
  if (!m) return null;
  const start = m.index, gt = rowXml.indexOf(">", start);
  if (gt < 0) return null;
  if (rowXml[gt - 1] === "/") return { start, end: gt + 1 };
  const close = rowXml.indexOf("</c>", gt);
  return { start, end: close < 0 ? gt + 1 : close + 4 };
}
function parseShared(xml) {
  const out = []; if (!xml) return out;
  for (const m of xml.matchAll(/<si>([\s\S]*?)<\/si>/g)) {
    let s = ""; for (const t of m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)) s += t[1];
    out.push(s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
  }
  return out;
}
function cellText(cx, shared) {
  const t = /\st="([^"]+)"/.exec(cx), ty = t ? t[1] : "";
  if (ty === "inlineStr") { const m = /<is>[\s\S]*?<t[^>]*>([\s\S]*?)<\/t>/.exec(cx); return m ? m[1] : ""; }
  const v = /<v>([\s\S]*?)<\/v>/.exec(cx); if (!v) return "";
  if (ty === "s") { const i = parseInt(v[1], 10); return shared[i] !== undefined ? shared[i] : ""; }
  return v[1];
}
// Borrow the style of an existing cell in the same column that already holds
// this value, so "Done" keeps its green, "In progress" its amber, etc.
const normVal = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
function styleForValue(sheetXml, shared, col, value) {
  const want = normVal(value); if (!want) return null;
  const re = new RegExp(`<c\\s[^>]*r="${col}\\d+"`, "g"); let m;
  while ((m = re.exec(sheetXml))) {
    const start = m.index, gt = sheetXml.indexOf(">", start); if (gt < 0) continue;
    let end;
    if (sheetXml[gt - 1] === "/") end = gt + 1;
    else { const c = sheetXml.indexOf("</c>", gt); end = c < 0 ? gt + 1 : c + 4; }
    const cx = sheetXml.slice(start, end);
    if (normVal(cellText(cx, shared)) === want) {
      const sm = /\ss="(\d+)"/.exec(cx); if (sm) return sm[1];
    }
  }
  return null;
}
// Replace (or insert) one cell as an inline string, keeping its style index.
function patchCell(sheetXml, cellRef, value, shared) {
  const rowNo = /^[A-Z]+(\d+)$/.exec(cellRef)[1];
  const col = /^[A-Z]+/.exec(cellRef)[0];
  const rm = new RegExp(`<row [^>]*r="${rowNo}"[^>]*>[\\s\\S]*?</row>`).exec(sheetXml);
  if (!rm) throw new Error(`row ${rowNo} not found`);
  const rowXml = rm[0];
  const matched = styleForValue(sheetXml, shared || [], col, value);
  const inline = (style) =>
    `<c r="${cellRef}"${style} t="inlineStr"><is><t xml:space="preserve">${xmlEsc(value)}</t></is></c>`;
  const hit = findCell(rowXml, cellRef);
  let newRow;
  if (hit) {
    const old = rowXml.slice(hit.start, hit.end);
    const sm = /\ss="(\d+)"/.exec(old);
    const st = matched || (sm ? sm[1] : null);
    newRow = rowXml.slice(0, hit.start) + inline(st ? ` s="${st}"` : "") + rowXml.slice(hit.end);
  } else {
    const target = colNum(cellRef);
    let at = null;
    for (const c of rowXml.matchAll(/<c\s[^>]*r="([A-Z]+)\d+"/g)) {
      if (colNum(c[1] + "1") > target) { at = c.index; break; }
    }
    if (at === null) at = rowXml.lastIndexOf("</row>");
    let st = matched;
    if (!st) { const prev = new RegExp(`<c\\s[^>]*r="${col}(\\d+)"[^>]*\\ss="(\\d+)"`).exec(sheetXml); if (prev) st = prev[2]; }
    newRow = rowXml.slice(0, at) + inline(st ? ` s="${st}"` : "") + rowXml.slice(at);
  }
  return sheetXml.slice(0, rm.index) + newRow + sheetXml.slice(rm.index + rowXml.length);
}
// Map a sheet's display name to its xl/worksheets/sheetN.xml entry.
function sheetPathFor(files, sheetName) {
  const wb = strFromU8(files["xl/workbook.xml"]);
  const rels = strFromU8(files["xl/_rels/workbook.xml.rels"]);
  const want = sheetName.trim().toLowerCase();
  for (const m of wb.matchAll(/<sheet[^>]*name="([^"]*)"[^>]*r:id="([^"]*)"[^>]*\/>/g)) {
    const nm = m[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
    if (nm.trim().toLowerCase() !== want) continue;
    const rel = new RegExp(`<Relationship[^>]*Id="${m[2]}"[^>]*Target="([^"]*)"`).exec(rels);
    if (!rel) return null;
    return "xl/" + rel[1].replace(/^\/?xl\//, "");
  }
  return null;
}

// ── Box OAuth: refresh token lives in KV; access tokens are short-lived ──
async function boxAccessToken(env) {
  const refresh = await env.BOXTOK.get("refresh_token");
  if (!refresh) throw new Error("Box not connected — visit /box/auth on this worker to authorize.");
  const r = await fetch("https://api.box.com/oauth2/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token", refresh_token: refresh,
      client_id: env.BOX_CLIENT_ID, client_secret: env.BOX_CLIENT_SECRET,
    }),
  });
  if (!r.ok) throw new Error("Box token refresh failed: " + (await r.text()).slice(0, 200));
  const d = await r.json();
  if (d.refresh_token) await env.BOXTOK.put("refresh_token", d.refresh_token); // Box rotates these
  return d.access_token;
}

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Proxy-Auth, X-Comment-Auth",
    "Access-Control-Max-Age": "86400", "Vary": "Origin",
  };
}
function eq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0;
}
function adf(text) {
  return { type: "doc", version: 1, content: String(text).split(/\n/).map(line => ({
    type: "paragraph", content: line ? [{ type: "text", text: line }] : [] })) };
}
// Flatten an Atlassian Document Format body back to plain text for the feed.
function adfToText(node) {
  if (!node) return "";
  if (typeof node === "string") return node;
  if (Array.isArray(node)) return node.map(adfToText).join("");
  let out = "";
  if (node.type === "text" && node.text) out += node.text;
  if (node.type === "mention" && node.attrs) {
    const m = String(node.attrs.text || node.attrs.displayName || "");
    out += m.startsWith("@") ? m : "@" + m;              // attrs.text often already has the @
  }
  if (node.content) out += adfToText(node.content);
  if (node.type === "paragraph" || node.type === "heading" || node.type === "listItem") out += "\n";
  return out;
}

export default {
  async fetch(request, env) {
    const allow = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin");
    const ok = allow.length === 0 || (origin && allow.includes(origin));
    const co = (origin && ok) ? origin : (allow[0] || "*");
    const H = cors(co);
    const json = (s, o) => new Response(JSON.stringify(o), { status: s, headers: { ...H, "Content-Type": "application/json" } });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: H });

    // ── One-time Box authorization (browser GET, not part of the JSON API) ──
    const url = new URL(request.url);
    if (url.pathname === "/box/auth") {
      if (!env.BOX_CLIENT_ID) return new Response("BOX_CLIENT_ID not set", { status: 500 });
      const redirect = `${url.origin}/box/callback`;
      const auth = new URL("https://account.box.com/api/oauth2/authorize");
      auth.searchParams.set("client_id", env.BOX_CLIENT_ID);
      auth.searchParams.set("response_type", "code");
      auth.searchParams.set("redirect_uri", redirect);
      return Response.redirect(auth.toString(), 302);
    }
    if (url.pathname === "/box/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("Missing code", { status: 400 });
      const r = await fetch("https://api.box.com/oauth2/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code", code,
          client_id: env.BOX_CLIENT_ID, client_secret: env.BOX_CLIENT_SECRET,
          redirect_uri: `${url.origin}/box/callback`,
        }),
      });
      const t = await r.text();
      if (!r.ok) return new Response("Box authorization failed: " + t.slice(0, 300), { status: 502 });
      const d = JSON.parse(t);
      await env.BOXTOK.put("refresh_token", d.refresh_token);
      return new Response(
        "<h2 style='font-family:system-ui'>✅ Box connected</h2><p style='font-family:system-ui'>" +
        "The PCI cockpit can now save edits back to the gap workbook. You can close this tab.</p>",
        { headers: { "Content-Type": "text/html" } });
    }

    if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: H });
    if (allow.length && origin && !ok) return new Response("Forbidden origin", { status: 403, headers: H });

    const auth = (request.headers.get("X-Proxy-Auth") || "").trim().toLowerCase();
    if (!env.SITE_PASSWORD || !eq(auth, env.SITE_PASSWORD)) {
      await new Promise(r => setTimeout(r, 300));
      return json(401, { message: "Unauthorized" });
    }
    let body = {}; try { body = await request.json(); } catch {}
    const base = String(env.JIRA_BASE_URL || DEFAULT_BASE).replace(/\/+$/, "");
    const project = String(env.JIRA_PROJECT || DEFAULT_PROJECT);
    const jauth = "Basic " + btoa(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`);
    const jhdr = { Accept: "application/json", Authorization: jauth };

    if (body.action === "verify") return json(200, { ok: true });

    // ── Live gap workbook: stream the public Box .xlsx to the cockpit ──
    // Box blocks cross-origin browser fetches, but the Worker has no CORS, so
    // it pulls the file and re-serves the raw bytes with our own CORS headers.
    // The cockpit parses the workbook client-side (SheetJS). Cached briefly so
    // repeated unlocks don't hammer Box.
    if (body.action === "gaps") {
      const url = env.BOX_GAPS_URL;
      if (!url) return json(500, { message: "BOX_GAPS_URL not configured" });
      const r = await fetch(url, { redirect: "follow", cf: { cacheTtl: 15, cacheEverything: true } });
      if (!r.ok) return json(502, { message: "Box fetch failed", status: r.status });
      const buf = await r.arrayBuffer();
      return new Response(buf, { status: 200, headers: {
        ...H,
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Cache-Control": "public, max-age=10",
      }});
    }

    // ── Live FIBXPI issues (slim) — whole project, one epic's children, or specific keys ──
    if (body.action === "issues") {
      const parent = String(body.parent || "").trim();
      const keys = Array.isArray(body.keys) ? body.keys
        .map(k => String(k).trim().toUpperCase()).filter(k => /^[A-Z]+-\d+$/.test(k)).slice(0, 300) : [];
      const jql = keys.length
        ? `key in (${keys.map(k => `"${k}"`).join(",")}) ORDER BY key ASC`
        : (parent || env.JIRA_EPIC)
          ? `parent = "${parent || env.JIRA_EPIC}" ORDER BY duedate ASC, key ASC`
          : `project = "${project}" ORDER BY updated DESC`;
      let issues = [], token = null;
      for (let i = 0; i < 12; i++) {           // cap ~1200 issues
        const qs = new URLSearchParams({ jql, maxResults: "100",
          fields: "summary,status,duedate,assignee,priority,issuetype,updated,resolutiondate" });
        if (token) qs.set("nextPageToken", token);
        const r = await fetch(`${base}/rest/api/3/search/jql?${qs}`, { headers: jhdr });
        if (!r.ok) return json(502, { message: "Jira error", status: r.status, detail: (await r.text()).slice(0, 300) });
        const d = await r.json();
        for (const it of (d.issues || [])) {
          const f = it.fields || {};
          issues.push({
            key: it.key, summary: (f.summary || "").slice(0, 200),
            status: (f.status && f.status.name) || "",
            category: (f.status && f.status.statusCategory && f.status.statusCategory.key) || "",
            due: f.duedate || "", resolved: f.resolutiondate ? true : false,
            assignee: (f.assignee && f.assignee.displayName) || "",
            priority: (f.priority && f.priority.name) || "",
            type: (f.issuetype && f.issuetype.name) || "", updated: f.updated || "",
          });
        }
        token = d.nextPageToken; if (!token || d.isLast) break;
      }
      return json(200, { project, issues, count: issues.length });
    }

    // ── Shared edit overlay (pending changes not yet pushed into the Box file) ──
    // Box blocks app config for this account, so edits live here and are applied
    // on top of the workbook for every viewer, then exported as a new .xlsx.
    const OV_KEY = "overlay";
    if (body.action === "overlay_get") {
      const raw = await env.BOXTOK.get(OV_KEY);
      return json(200, { overlay: raw ? JSON.parse(raw) : {} });
    }
    // ── Roadmap phases (user-built chain shown at the top of the cockpit) ──
    const PH_KEY = "phases";
    if (body.action === "phases_get") {
      const raw = await env.BOXTOK.get(PH_KEY);
      return json(200, { phases: raw ? JSON.parse(raw) : null });
    }
    if (body.action === "phases_set") {
      const cP = (request.headers.get("X-Comment-Auth") || "").trim().toLowerCase();
      const okP = (env.COMMENT_PASSWORD && eq(cP, env.COMMENT_PASSWORD)) ||
                  (!env.COMMENT_PASSWORD && eq(cP, env.SITE_PASSWORD));
      if (!okP) { await new Promise(r => setTimeout(r, 300)); return json(401, { message: "Edit password required" }); }
      const list = Array.isArray(body.phases) ? body.phases.slice(0, 40) : [];
      const clean = list.map((p, i) => ({
        id: String(p.id || ("p" + i)).slice(0, 40),
        title: String(p.title || "Phase").slice(0, 80),
        note: String(p.note || "").slice(0, 400),
        color: /^#[0-9a-fA-F]{6}$/.test(String(p.color || "")) ? p.color : "#0f9389",
        status: ["todo", "doing", "done"].includes(p.status) ? p.status : "todo",
        flag: !!p.flag,
      }));
      await env.BOXTOK.put(PH_KEY, JSON.stringify(clean));
      return json(200, { ok: true, count: clean.length });
    }
    if (body.action === "overlay_set_many") {
      const cA = (request.headers.get("X-Comment-Auth") || "").trim().toLowerCase();
      const ok2 = (env.COMMENT_PASSWORD && eq(cA, env.COMMENT_PASSWORD)) ||
                  (!env.COMMENT_PASSWORD && eq(cA, env.SITE_PASSWORD));
      if (!ok2) { await new Promise(r => setTimeout(r, 300)); return json(401, { message: "Edit password required" }); }
      const items = Array.isArray(body.items) ? body.items.slice(0, 500) : [];
      const raw0 = await env.BOXTOK.get(OV_KEY);
      const ov0 = raw0 ? JSON.parse(raw0) : {};
      let n = 0;
      for (const it of items) {
        const field = String(it.field || "");
        if (!["fib_status", "link", "client"].includes(field)) continue;
        const sheet = String(it.sheet || "").trim();
        const cell = String(it.cell || "").trim().toUpperCase();
        if (!sheet || !/^[A-Z]+\d+$/.test(cell)) continue;
        ov0[`${sheet}!${cell}`] = { sheet, cell, field,
          value: String(it.value == null ? "" : it.value).slice(0, 500), at: new Date().toISOString() };
        n++;
      }
      if (Object.keys(ov0).length > 2000) return json(400, { message: "Too many pending edits" });
      await env.BOXTOK.put(OV_KEY, JSON.stringify(ov0));
      return json(200, { ok: true, applied: n, count: Object.keys(ov0).length });
    }
    if (body.action === "overlay_set" || body.action === "overlay_clear") {
      const cAuth = (request.headers.get("X-Comment-Auth") || "").trim().toLowerCase();
      const okC = (env.COMMENT_PASSWORD && eq(cAuth, env.COMMENT_PASSWORD)) ||
                  (!env.COMMENT_PASSWORD && eq(cAuth, env.SITE_PASSWORD));
      if (!okC) { await new Promise(r => setTimeout(r, 300)); return json(401, { message: "Edit password required" }); }
      const raw = await env.BOXTOK.get(OV_KEY);
      const ov = raw ? JSON.parse(raw) : {};
      if (body.action === "overlay_clear") {
        if (body.all) { await env.BOXTOK.delete(OV_KEY); return json(200, { ok: true, overlay: {} }); }
        delete ov[String(body.id || "")];
      } else {
        const field = String(body.field || "");
        if (!["fib_status", "link", "client"].includes(field)) return json(403, { message: "Only FIB Status and Link are editable" });
        const sheet = String(body.sheet || "").trim();
        const cell = String(body.cell || "").trim().toUpperCase();
        if (!sheet || !/^[A-Z]+\d+$/.test(cell)) return json(400, { message: "Bad sheet/cell" });
        const value = String(body.value == null ? "" : body.value).slice(0, 500);
        ov[`${sheet}!${cell}`] = { sheet, cell, field, value, at: new Date().toISOString() };
        if (Object.keys(ov).length > 2000) return json(400, { message: "Too many pending edits" });
      }
      await env.BOXTOK.put(OV_KEY, JSON.stringify(ov));
      return json(200, { ok: true, count: Object.keys(ov).length });
    }

    // ── Write one cell back into the Box gap workbook (FIB Status / Link only) ──
    if (body.action === "gap_edit") {
      const cAuth = (request.headers.get("X-Comment-Auth") || "").trim().toLowerCase();
      const okC = (env.COMMENT_PASSWORD && eq(cAuth, env.COMMENT_PASSWORD)) ||
                  (!env.COMMENT_PASSWORD && eq(cAuth, env.SITE_PASSWORD));
      if (!okC) { await new Promise(r => setTimeout(r, 300)); return json(401, { message: "Edit password required" }); }
      const sheet = String(body.sheet || "").trim();
      const cell = String(body.cell || "").trim().toUpperCase();
      const value = String(body.value == null ? "" : body.value);
      const field = String(body.field || "");
      if (!sheet || !/^[A-Z]+\d+$/.test(cell)) return json(400, { message: "Bad sheet/cell" });
      if (!["fib_status", "link", "client"].includes(field)) return json(403, { message: "Only FIB Status and Link are editable" });
      if (value.length > 500) return json(400, { message: "Value too long" });
      const fileId = env.BOX_FILE_ID;
      if (!fileId) return json(500, { message: "BOX_FILE_ID not set" });

      let token;
      try { token = await boxAccessToken(env); }
      catch (e) { return json(409, { message: String(e.message || e), needsAuth: true }); }
      const bh = { Authorization: `Bearer ${token}` };

      // current version (etag) so a concurrent assessor edit can't be clobbered
      const info = await fetch(`https://api.box.com/2.0/files/${fileId}?fields=etag,name,sha1`, { headers: bh });
      if (!info.ok) return json(502, { message: "Box file info failed", detail: (await info.text()).slice(0, 200) });
      const meta = await info.json();
      if (body.baseEtag && String(body.baseEtag) !== String(meta.etag)) {
        return json(409, { message: "The workbook changed in Box since you loaded it. Refresh and retry.", etag: meta.etag });
      }

      const dl = await fetch(`https://api.box.com/2.0/files/${fileId}/content`, { headers: bh, redirect: "follow" });
      if (!dl.ok) return json(502, { message: "Box download failed", status: dl.status });
      const files = unzipSync(new Uint8Array(await dl.arrayBuffer()));
      const path = sheetPathFor(files, sheet);
      if (!path || !files[path]) return json(400, { message: `Sheet "${sheet}" not found` });
      let xml;
      try { xml = patchCell(strFromU8(files[path]), cell, value, parseShared(files["xl/sharedStrings.xml"] ? strFromU8(files["xl/sharedStrings.xml"]) : "")); }
      catch (e) { return json(400, { message: "Patch failed: " + (e.message || e) }); }
      files[path] = strToU8(xml);
      const out = zipSync(files, { level: 6 });

      // upload as a NEW VERSION, guarded by If-Match
      const fd = new FormData();
      fd.append("attributes", JSON.stringify({ name: meta.name }));
      fd.append("file", new Blob([out],
        { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), meta.name);
      const up = await fetch(`https://upload.box.com/api/2.0/files/${fileId}/content`, {
        method: "POST", headers: { ...bh, "If-Match": meta.etag }, body: fd,
      });
      const ut = await up.text();
      if (up.status === 412) return json(409, { message: "Someone else saved the workbook first. Refresh and retry." });
      if (!up.ok) return json(502, { message: "Box upload failed", status: up.status, detail: ut.slice(0, 300) });
      const ud = JSON.parse(ut);
      const nv = (ud.entries && ud.entries[0]) || {};
      return json(200, { ok: true, cell, sheet, value, version: nv.etag, name: nv.name });
    }

    // ── Activity across the whole epic tree: epic → tasks → subtasks ──
    // Uses bulk search with expand=changelog + fields=comment so ~113 issues cost
    // ~3 subrequests instead of one per issue (Workers caps subrequests per request).
    if (body.action === "activity") {
      const epic = String(body.epic || env.JIRA_EPIC || "FIBXPI-49").trim();
      const isBot = (n) => /automation for jira|^automation$|\bbot\b|jira automation/i.test(String(n || ""));
      const items = [];
      const seen = new Set();

      async function harvest(jql) {
        let token = null, keys = [];
        for (let page = 0; page < 6; page++) {                 // cap 600 issues
          const qs = new URLSearchParams({ jql, maxResults: "100", fields: "summary,comment", expand: "changelog" });
          if (token) qs.set("nextPageToken", token);
          const r = await fetch(`${base}/rest/api/3/search/jql?${qs}`, { headers: jhdr });
          if (!r.ok) break;
          const d = await r.json();
          for (const it of (d.issues || [])) {
            keys.push(it.key);
            const summary = (it.fields && it.fields.summary) || "";
            for (const h of ((it.changelog && it.changelog.histories) || [])) {
              for (const ch of (h.items || [])) {
                const field = ch.field || "";
                if (field === "Comment") continue;             // comments handled below
                const id = "c:" + it.key + h.created + field;
                if (seen.has(id)) continue; seen.add(id);
                const who = (h.author && h.author.displayName) || "";
                items.push({
                  ts: h.created, key: it.key, summary, who, bot: isBot(who),
                  kind: field.toLowerCase() === "status" ? "status" : "edit",
                  field, from: ch.fromString || "", to: ch.toString || "",
                });
              }
            }
            for (const c of (((it.fields || {}).comment || {}).comments || [])) {
              const id = "m:" + c.id;
              if (seen.has(id)) continue; seen.add(id);
              const who = (c.author && c.author.displayName) || "";
              items.push({
                ts: c.created, key: it.key, summary, who, bot: isBot(who),
                kind: "comment", text: adfToText(c.body).replace(/\n{2,}/g, "\n").trim().slice(0, 1200),
              });
            }
          }
          token = d.nextPageToken;
          if (!token || d.isLast) break;
        }
        return keys;
      }

      // level 1+2: the epic itself and its direct children
      const childKeys = (await harvest(`key = "${epic}" OR parent = "${epic}"`)).filter(k => k !== epic);
      // level 3: subtasks of those children
      if (childKeys.length) {
        const list = childKeys.map(k => `"${k}"`).join(",");
        await harvest(`parent in (${list})`);
      }
      items.sort((a, b) => (a.ts < b.ts ? 1 : -1));
      const real = items.filter(i => !i.bot).length;
      return json(200, {
        epic, count: items.length, human: real, bots: items.length - real,
        scope: 1 + childKeys.length, items: items.slice(0, Number(body.limit) || 400),
      });
    }

    // ── Post a comment to a FIBXPI issue ──
    if (body.action === "comment") {
      const cAuth = (request.headers.get("X-Comment-Auth") || "").trim().toLowerCase();
      const okC = (env.COMMENT_PASSWORD && eq(cAuth, env.COMMENT_PASSWORD)) ||
                  (!env.COMMENT_PASSWORD && eq(cAuth, env.SITE_PASSWORD));
      if (!okC) { await new Promise(r => setTimeout(r, 300)); return json(401, { message: "Comment password required or incorrect" }); }
      const key = String(body.key || "").trim().toUpperCase();
      const text = String(body.text || "").trim();
      if (!/^[A-Z]+-\d+$/.test(key)) return json(400, { message: "Invalid issue key" });
      if (!text) return json(400, { message: "Empty comment" });
      const r = await fetch(`${base}/rest/api/3/issue/${key}/comment`, {
        method: "POST", headers: { ...jhdr, "Content-Type": "application/json" },
        body: JSON.stringify({ body: adf(text) }),
      });
      if (!r.ok) return json(502, { message: "Jira comment failed", status: r.status, detail: (await r.text()).slice(0, 300) });
      const d = await r.json();
      return json(200, { ok: true, id: d.id, key });
    }

    return json(400, { message: "Unknown action" });
  },
};
