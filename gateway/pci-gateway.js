// Serves fibpmo.com/pci* by proxying to the project-pci GitHub Pages site.
// Keeps the fibpmo.com/pci URL and hides the github.io origin from visitors.
const ORIGIN = "https://rudawathegw-design.github.io/project-pci";
const PREFIX = "/pci";
export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Normalise /pci -> /pci/ so the page's relative assets resolve under /pci/.
    if (url.pathname === PREFIX) {
      return Response.redirect(url.origin + PREFIX + "/" + url.search, 301);
    }
    let rest = url.pathname.slice(PREFIX.length) || "/";
    const target = ORIGIN + rest + url.search;
    const upstream = await fetch(target, {
      method: request.method,
      headers: request.headers,
      body: (request.method === "GET" || request.method === "HEAD") ? undefined : request.body,
      redirect: "follow",
    });
    const h = new Headers(upstream.headers);
    h.delete("content-security-policy");
    h.set("X-Frame-Options", "SAMEORIGIN");
    return new Response(upstream.body, { status: upstream.status, headers: h });
  },
};
