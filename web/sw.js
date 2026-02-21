// Scramjet-style shape: route same-origin navigations through proxy tokens.
// This is intentionally minimal and should be expanded with route policies.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  const selfOrigin = self.location.origin;

  // Skip proxy internals/static files.
  if (
    url.origin === selfOrigin &&
    (
      url.pathname.startsWith("/proxy/") ||
      url.pathname.startsWith("/web/") ||
      url.pathname.startsWith("/api/") ||
      url.pathname === "/healthz" ||
      url.pathname === "/sw.js"
    )
  ) {
    return;
  }

  // Do not intercept same-origin requests to avoid proxying our own local routes.
  if (url.origin === selfOrigin) return;

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
