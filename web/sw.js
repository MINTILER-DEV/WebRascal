// Scramjet-style shape: route same-origin navigations through proxy tokens.
// This is intentionally minimal and should be expanded with route policies.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);

  // Skip proxy internals/static files.
  if (
    url.pathname.startsWith("/proxy/") ||
    url.pathname.startsWith("/web/") ||
    url.pathname.startsWith("/api/") ||
    url.pathname === "/healthz"
  ) {
    return;
  }

  // Intercept top-level navigations only.
  if (request.mode !== "navigate") return;

  const token = base64Url(url.href);
  const proxied = `/proxy/${token}`;
  event.respondWith(fetch(proxied).catch(() => fetch(request)));
});

function base64Url(input) {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
