const INTERNAL_PREFIXES = ["/web/", "/sw.js", "/healthz", "/api/"];
const clientContexts = new Map();
let defaultSid = "default";

self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type !== "wr:session") return;

  const sid = sanitizeSid(data.sid);
  defaultSid = sid;
  if (event.source && event.source.id) {
    const existing = clientContexts.get(event.source.id) || { base: null, sid };
    existing.sid = sid;
    clientContexts.set(event.source.id, existing);
  }
});

self.addEventListener("fetch", (event) => {
  event.respondWith(handleFetch(event));
});

async function handleFetch(event) {
  const request = event.request;
  const requestUrl = safeUrl(request.url);
  if (!requestUrl) return fetch(request);
  if (!isHttp(requestUrl)) return fetch(request);

  if (isInternalRequest(requestUrl, request)) {
    return fetch(request);
  }

  const sidFromUrl = sanitizeSid(requestUrl.searchParams.get("sid"));
  const sid = sidFromUrl || resolveSidForClient(event.clientId) || defaultSid;

  if (requestUrl.origin === self.location.origin && requestUrl.pathname.startsWith("/proxy/")) {
    const upstream = upstreamFromProxyUrl(requestUrl);
    if (upstream && event.clientId && isDocumentLike(request)) {
      clientContexts.set(event.clientId, { base: upstream.toString(), sid });
    }

    const response = await fetch(request);
    return rewriteResponseIfNeeded(request, response, upstream, sid);
  }

  const target = resolveTargetUrl(event, request, requestUrl);
  if (!target) {
    return fetch(request);
  }

  const proxiedUrl = buildProxyPath(target.toString(), sid);
  const proxiedRequest = new Request(proxiedUrl, request);
  const response = await fetch(proxiedRequest);

  if (event.clientId && isDocumentLike(request)) {
    clientContexts.set(event.clientId, { base: target.toString(), sid });
  }

  return rewriteResponseIfNeeded(proxiedRequest, response, target, sid);
}

function resolveTargetUrl(event, request, requestUrl) {
  if (requestUrl.origin !== self.location.origin) {
    return requestUrl;
  }

  if (requestUrl.pathname.startsWith("/proxy/")) {
    return null;
  }

  if (requestUrl.pathname === "/" || requestUrl.pathname === "/index.html") {
    return null;
  }

  if (isInternalPath(requestUrl.pathname)) {
    return null;
  }

  const contextBase = contextBaseFromRequest(event, request);
  if (!contextBase) {
    return null;
  }

  try {
    return new URL(requestUrl.pathname + requestUrl.search + requestUrl.hash, contextBase);
  } catch (_) {
    return null;
  }
}

function contextBaseFromRequest(event, request) {
  const ref = safeUrl(request.referrer);
  if (ref && ref.origin === self.location.origin && ref.pathname.startsWith("/proxy/")) {
    const upstream = upstreamFromProxyUrl(ref);
    if (upstream) return upstream.toString();
  }

  const fromClient = event.clientId ? clientContexts.get(event.clientId) : null;
  return fromClient?.base || null;
}

async function rewriteResponseIfNeeded(request, response, upstream, sid) {
  if (!response) return response;

  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  if (!shouldRewriteContent(contentType)) {
    return response;
  }

  const source = upstream || upstreamFromProxyUrl(safeUrl(request.url));
  if (!source) {
    return response;
  }

  let rewrittenBody;
  const rawText = await response.text();

  if (contentType.includes("text/html")) {
    rewrittenBody = rewriteHtml(rawText, source, sid);
  } else if (contentType.includes("text/css")) {
    rewrittenBody = rewriteCss(rawText, source, sid);
  } else {
    rewrittenBody = rewriteJs(rawText, source, sid);
  }

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("x-frame-options");
  headers.set("x-wr-rewritten", "1");

  return new Response(rewrittenBody, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function rewriteHtml(html, baseUrl, sid) {
  const base = baseUrl.toString();
  let out = html;

  out = out.replace(/\sintegrity=("[^"]*"|'[^']*')/gi, "");

  out = out.replace(
    /(href|src|action|poster|data|formaction|srcset|ping)=("([^"]*)"|'([^']*)')/gi,
    (_, attr, whole, dqVal, sqVal) => {
      const raw = dqVal ?? sqVal ?? "";
      const quote = whole.startsWith("\"") ? "\"" : "'";
      const mapped = rewriteAttributeValue(attr.toLowerCase(), raw, base, sid);
      return `${attr}=${quote}${mapped}${quote}`;
    }
  );

  const nonceMatch = out.match(/<script[^>]*\bnonce=("([^"]*)"|'([^']*)')/i);
  const nonce = nonceMatch ? (nonceMatch[2] || nonceMatch[3] || "") : "";
  const nonceAttr = nonce ? ` nonce="${escapeHtml(nonce)}"` : "";
  const runtimeTag = `<script src="/web/runtime.js" data-wr-base="${escapeHtml(base)}" data-wr-sid="${escapeHtml(sid)}"${nonceAttr}></script>`;

  const headOpen = out.match(/<head[^>]*>/i);
  if (headOpen && headOpen.index != null) {
    const insertAt = headOpen.index + headOpen[0].length;
    return out.slice(0, insertAt) + runtimeTag + out.slice(insertAt);
  }

  return runtimeTag + out;
}

function rewriteCss(css, baseUrl, sid) {
  const base = baseUrl.toString();
  let out = css;

  out = out.replace(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi, (_, quote, raw) => {
    const mapped = proxify(raw, base, sid);
    if (!mapped) return `url(${quote}${raw}${quote})`;
    return `url(${quote}${mapped}${quote})`;
  });

  out = out.replace(/@import\s+(?:url\()?\s*(["'])([^"']+)\1\s*\)?/gi, (_, quote, raw) => {
    const mapped = proxify(raw, base, sid);
    if (!mapped) return `@import ${quote}${raw}${quote}`;
    return `@import ${quote}${mapped}${quote}`;
  });

  return out;
}

function rewriteJs(js, baseUrl, sid) {
  const base = baseUrl.toString();
  const bootstrap = `;(()=>{try{if(self.__WR_INSTALL){self.__WR_INSTALL({base:${JSON.stringify(base)},sid:${JSON.stringify(sid)}});}}catch(_){}})();\n`;

  const out = js.replace(/(["'`])((?:https?:|wss?:)\/\/[^"'`\s]+)\1/g, (full, quote, raw) => {
    const mapped = proxify(raw, base, sid);
    if (!mapped) return full;
    return `${quote}${mapped}${quote}`;
  });

  return bootstrap + out;
}

function rewriteAttributeValue(attr, value, base, sid) {
  if (attr === "srcset") {
    return value
      .split(",")
      .map((candidate) => {
        const trimmed = candidate.trim();
        if (!trimmed) return candidate;
        const parts = trimmed.split(/\s+/);
        const mapped = proxify(parts[0], base, sid);
        if (mapped) parts[0] = mapped;
        return parts.join(" ");
      })
      .join(", ");
  }

  if (attr === "ping") {
    return value
      .split(/\s+/)
      .map((entry) => proxify(entry, base, sid) || entry)
      .join(" ");
  }

  const mapped = proxify(value, base, sid);
  return mapped || value;
}

function proxify(raw, base, sid) {
  if (!raw) return null;
  if (raw.startsWith("#")) return raw;
  if (SKIP_SCHEMES.test(raw)) return raw;

  try {
    const resolved = new URL(raw, base);
    if (resolved.origin === self.location.origin && resolved.pathname.startsWith("/proxy/")) {
      return resolved.pathname + resolved.search + resolved.hash;
    }
    return buildProxyPath(resolved.toString(), sid);
  } catch (_) {
    return null;
  }
}

function buildProxyPath(targetUrl, sid) {
  return `/proxy/${base64Url(targetUrl)}?sid=${encodeURIComponent(sid || defaultSid)}`;
}

function upstreamFromProxyUrl(url) {
  if (!url || !url.pathname.startsWith("/proxy/")) return null;
  const token = url.pathname.slice("/proxy/".length);
  if (!token) return null;
  const decoded = decodeBase64Url(token);
  if (!decoded) return null;
  try {
    return new URL(decoded);
  } catch (_) {
    return null;
  }
}

function isDocumentLike(request) {
  return request.mode === "navigate" || ["document", "iframe", "frame"].includes(request.destination);
}

function shouldRewriteContent(contentType) {
  if (!contentType) return false;
  if (contentType.includes("text/html")) return true;
  if (contentType.includes("text/css")) return true;
  return (
    contentType.includes("javascript") ||
    contentType.includes("ecmascript") ||
    contentType.includes("application/x-javascript")
  );
}

function isInternalRequest(url, request) {
  if (url.origin !== self.location.origin) {
    return false;
  }

  if (request.mode === "navigate" && (url.pathname === "/" || url.pathname === "/index.html")) {
    return true;
  }

  return isInternalPath(url.pathname);
}

function isInternalPath(pathname) {
  return INTERNAL_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(prefix));
}

function resolveSidForClient(clientId) {
  if (!clientId) return null;
  return clientContexts.get(clientId)?.sid || null;
}

function sanitizeSid(input) {
  const raw = String(input || "");
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  return cleaned || "default";
}

function safeUrl(value) {
  try {
    return new URL(value);
  } catch (_) {
    return null;
  }
}

function isHttp(url) {
  return url.protocol === "http:" || url.protocol === "https:";
}

function base64Url(input) {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(input) {
  try {
    const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
    const padLen = normalized.length % 4;
    const padded = normalized + (padLen ? "=".repeat(4 - padLen) : "");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch (_) {
    return null;
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

const SKIP_SCHEMES = /^(data:|blob:|javascript:|about:|mailto:|tel:)/i;
