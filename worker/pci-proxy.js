/**
 * project-pci-proxy — Cloudflare Worker for the PCI DSS cockpit.
 * Holds the Jira token server-side (never in the page). Read-only FIBXPI status
 * for the cockpit, plus comment posting. Gated by the cockpit password
 * (X-Proxy-Auth == SITE_PASSWORD). Comments also require X-Comment-Auth.
 *
 * Secrets: JIRA_EMAIL, JIRA_API_TOKEN, SITE_PASSWORD (="pci"), COMMENT_PASSWORD (optional)
 * Vars: ALLOWED_ORIGIN, JIRA_BASE_URL, JIRA_PROJECT
 */
const DEFAULT_BASE = "https://fibtask.atlassian.net";
const DEFAULT_PROJECT = "FIBXPI";

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

export default {
  async fetch(request, env) {
    const allow = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin");
    const ok = allow.length === 0 || (origin && allow.includes(origin));
    const co = (origin && ok) ? origin : (allow[0] || "*");
    const H = cors(co);
    const json = (s, o) => new Response(JSON.stringify(o), { status: s, headers: { ...H, "Content-Type": "application/json" } });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: H });
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
