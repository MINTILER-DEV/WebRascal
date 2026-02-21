// Scramjet-style shape: route same-origin navigations through proxy tokens.
// This is intentionally minimal and should be expanded with route policies.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  let url;
  try {
    url = new URL(request.url);
  } catch (_) {
    return;
  }
  const selfOrigin = self.location.origin;

  if (url.protocol !== "http:" && url.protocol !== "https:") return;

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
  event.respondWith((async () => {
    try {
      return await fetch(proxied);
    } catch (_) {
      try {
        return await fetch(request);
      } catch (_) {
        return Response.error();
      }
    }
  })());
});

function base64Url(input) {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
