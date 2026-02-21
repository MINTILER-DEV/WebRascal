use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::HeaderMap;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

#[derive(Debug)]
pub enum RewriteError {
    InvalidToken,
    InvalidUrl(url::ParseError),
}

impl From<url::ParseError> for RewriteError {
    fn from(value: url::ParseError) -> Self {
        Self::InvalidUrl(value)
    }
}

pub fn encode_target(target: &Url) -> String {
    URL_SAFE_NO_PAD.encode(target.as_str().as_bytes())
}

pub fn decode_target(token: &str) -> Result<Url, RewriteError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| RewriteError::InvalidToken)?;
    let decoded = String::from_utf8(bytes).map_err(|_| RewriteError::InvalidToken)?;
    Ok(Url::parse(&decoded)?)
}

pub fn rewrite_html(html: &str, upstream: &Url, proxy_origin: &Url) -> String {
    let attr_re = attr_regex();
    let rewritten = attr_re
        .replace_all(html, |caps: &regex::Captures<'_>| {
            let attr = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();

            if should_skip_rewrite(raw) {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            }

            let Some(joined) = resolve_url(raw, upstream) else {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            };

            let rewritten = proxy_url(proxy_origin, &joined);
            format!(r#"{attr}="{rewritten}""#)
        })
        .to_string();
    inject_runtime_shim(&rewritten, upstream, proxy_origin)
}

pub fn rewrite_location_header(headers: &mut HeaderMap, upstream: &Url, proxy_origin: &Url) {
    let Some(location) = headers.get("location").cloned() else {
        return;
    };

    let Ok(location_str) = location.to_str() else {
        return;
    };

    let target = Url::parse(location_str)
        .or_else(|_| upstream.join(location_str))
        .ok();
    let Some(target) = target else {
        return;
    };

    let rewritten = proxy_url(proxy_origin, &target);
    if let Ok(value) = rewritten.parse() {
        headers.insert("location", value);
    }
}

pub fn proxy_url(proxy_origin: &Url, target: &Url) -> String {
    format!("{}/proxy/{}", proxy_origin.as_str().trim_end_matches('/'), encode_target(target))
}

fn should_skip_rewrite(raw: &str) -> bool {
    raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("data:")
        || raw.starts_with("javascript:")
        || raw.starts_with("mailto:")
}

fn resolve_url(raw: &str, upstream: &Url) -> Option<Url> {
    if let Ok(abs) = Url::parse(raw) {
        return Some(abs);
    }
    upstream.join(raw).ok()
}

fn attr_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(href|src|action)=['"]([^'"]+)['"]"#)
            .expect("attribute rewrite regex must compile")
    })
}

fn inject_runtime_shim(html: &str, upstream: &Url, proxy_origin: &Url) -> String {
    let script = runtime_shim_script(upstream, proxy_origin);
    if let Some(idx) = html.find("</head>") {
        let mut out = String::with_capacity(html.len() + script.len() + 1);
        out.push_str(&html[..idx]);
        out.push_str(&script);
        out.push_str(&html[idx..]);
        return out;
    }
    let mut out = String::with_capacity(html.len() + script.len() + 1);
    out.push_str(&script);
    out.push_str(html);
    out
}

fn runtime_shim_script(upstream: &Url, proxy_origin: &Url) -> String {
    let upstream_js = js_string_escape(upstream.as_str());
    let proxy_origin_js = js_string_escape(proxy_origin.as_str().trim_end_matches('/'));
    format!(
        r#"<script>
(() => {{
  const upstreamBase = new URL("{upstream_js}");
  const proxyOrigin = "{proxy_origin_js}";
  const proxyPrefix = proxyOrigin + "/proxy/";
  const upstreamContext = upstreamBase.toString();
  const contextHeader = "x-webrascal-upstream";
  const skip = /^(data:|blob:|javascript:|about:|mailto:)/i;
  const b64url = (input) => {{
    const bytes = new TextEncoder().encode(input);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }};
  const toProxy = (input) => {{
    try {{
      const raw = typeof input === "string" ? input : (input && input.url) ? input.url : "";
      if (!raw || skip.test(raw)) return null;
      const resolved = new URL(raw, upstreamBase);
      if (resolved.origin === proxyOrigin) {{
        if (resolved.pathname.startsWith("/proxy/")) return resolved.toString();
        const mapped = new URL(resolved.pathname + resolved.search + resolved.hash, upstreamBase.origin);
        return proxyPrefix + b64url(mapped.toString());
      }}
      const abs = resolved.toString();
      if (abs.startsWith(proxyPrefix)) return abs;
      return proxyPrefix + b64url(abs);
    }} catch (_) {{
      return null;
    }}
  }};
  const toAppPath = (input) => {{
    try {{
      const raw = typeof input === "string" ? input : (input && input.url) ? input.url : "";
      if (!raw || skip.test(raw)) return null;
      const resolved = new URL(raw, upstreamBase);
      if (resolved.origin !== upstreamBase.origin) return null;
      return resolved.pathname + resolved.search + resolved.hash;
    }} catch (_) {{
      return null;
    }}
  }};
  const toNavigable = (input) => {{
    const appPath = toAppPath(input);
    if (appPath) return appPath;
    return toProxy(input);
  }};
  const currentPath = () => window.location.pathname + window.location.search + window.location.hash;
  const softNavigate = (input, mode) => {{
    const appPath = toAppPath(input);
    if (!appPath) return false;
    if (appPath === currentPath()) return true;
    try {{
      if (!window.history) return false;
      if (mode === "replace" && typeof window.history.replaceState === "function") {{
        window.history.replaceState(window.history.state, "", appPath);
      }} else if (typeof window.history.pushState === "function") {{
        window.history.pushState(window.history.state, "", appPath);
      }} else {{
        return false;
      }}
      window.dispatchEvent(new PopStateEvent("popstate", {{ state: window.history.state }}));
      return true;
    }} catch (_) {{
      return false;
    }}
  }};
  const origFetch = window.fetch;
  window.fetch = function(input, init) {{
    let nextInit = init;
    try {{
      if (input instanceof Request) {{
        const proxied = toProxy(input.url);
        if (proxied) input = new Request(proxied, input);
      }} else {{
        const proxied = toProxy(input);
        if (proxied) input = proxied;
      }}
      const req = input instanceof Request ? input : null;
      const headers = new Headers((nextInit && nextInit.headers) || (req ? req.headers : undefined));
      headers.set(contextHeader, upstreamContext);
      nextInit = Object.assign({{}}, nextInit || {{}}, {{ headers }});
    }} catch (_) {{}}
    return origFetch.call(this, input, nextInit);
  }};
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    this.__wrHasContextHeader = false;
    const proxied = toProxy(url);
    return origOpen.call(this, method, proxied || url, ...Array.prototype.slice.call(arguments, 2));
  }};
  const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {{
    if (String(name).toLowerCase() === contextHeader) {{
      this.__wrHasContextHeader = true;
    }}
    return origSetRequestHeader.call(this, name, value);
  }};
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {{
    try {{
      if (!this.__wrHasContextHeader) {{
        origSetRequestHeader.call(this, contextHeader, upstreamContext);
      }}
    }} catch (_) {{}}
    return origSend.call(this, body);
  }};
  if (navigator.sendBeacon) {{
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {{
      const proxied = toProxy(url);
      return origBeacon(proxied || url, data);
    }};
  }}
  const origWindowOpen = window.open;
  if (typeof origWindowOpen === "function") {{
    window.open = function(url) {{
      const nextUrl = toNavigable(url);
      return origWindowOpen.call(this, nextUrl || url, ...Array.prototype.slice.call(arguments, 1));
    }};
  }}
  if (window.history && typeof window.history.pushState === "function") {{
    const origPushState = window.history.pushState;
    window.history.pushState = function(state, title, url) {{
      const nextUrl = url == null ? url : (toAppPath(String(url)) || url);
      return origPushState.call(this, state, title, nextUrl);
    }};
  }}
  if (window.history && typeof window.history.replaceState === "function") {{
    const origReplaceState = window.history.replaceState;
    window.history.replaceState = function(state, title, url) {{
      const nextUrl = url == null ? url : (toAppPath(String(url)) || url);
      return origReplaceState.call(this, state, title, nextUrl);
    }};
  }}
  try {{
    const locProto = window.Location && window.Location.prototype;
    if (locProto && typeof locProto.assign === "function") {{
      const origAssign = locProto.assign;
      locProto.assign = function(url) {{
        if (softNavigate(url, "push")) return;
        const nextUrl = toNavigable(url);
        return origAssign.call(this, nextUrl || url);
      }};
    }}
    if (locProto && typeof locProto.replace === "function") {{
      const origReplace = locProto.replace;
      locProto.replace = function(url) {{
        if (softNavigate(url, "replace")) return;
        const nextUrl = toNavigable(url);
        return origReplace.call(this, nextUrl || url);
      }};
    }}
    if (locProto) {{
      const hrefDescriptor = Object.getOwnPropertyDescriptor(locProto, "href");
      if (hrefDescriptor && typeof hrefDescriptor.set === "function" && hrefDescriptor.configurable) {{
        const origHrefSet = hrefDescriptor.set;
        Object.defineProperty(locProto, "href", Object.assign({{}}, hrefDescriptor, {{
          set(value) {{
            if (softNavigate(value, "push")) return;
            const nextUrl = toNavigable(value);
            return origHrefSet.call(this, nextUrl || value);
          }}
        }}));
      }}

      const pathnameDescriptor = Object.getOwnPropertyDescriptor(locProto, "pathname");
      if (pathnameDescriptor && typeof pathnameDescriptor.set === "function" && pathnameDescriptor.configurable) {{
        const origPathSet = pathnameDescriptor.set;
        Object.defineProperty(locProto, "pathname", Object.assign({{}}, pathnameDescriptor, {{
          set(value) {{
            if (softNavigate(String(value || ""), "push")) return;
            return origPathSet.call(this, value);
          }}
        }}));
      }}
    }}
  }} catch (_) {{}}
  document.addEventListener("submit", (event) => {{
    try {{
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const action = form.getAttribute("action") || window.location.href;
      const proxied = toProxy(action);
      if (proxied) form.setAttribute("action", proxied);
    }} catch (_) {{}}
  }}, true);
  document.addEventListener("click", (event) => {{
    try {{
      const target = event.target;
      const link = target && target.closest ? target.closest("a[href]") : null;
      if (!link) return;
      const raw = link.getAttribute("href") || link.href;
      const proxied = toProxy(raw);
      if (proxied) link.setAttribute("href", proxied);
    }} catch (_) {{}}
  }}, true);
}})();
</script>"#
    )
}

fn js_string_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_token() {
        let url = Url::parse("https://example.com/a?x=1").unwrap();
        let encoded = encode_target(&url);
        let decoded = decode_target(&encoded).unwrap();
        assert_eq!(decoded.as_str(), url.as_str());
    }

    #[test]
    fn html_rewrite_rewrites_links() {
        let upstream = Url::parse("https://example.com/docs/page.html").unwrap();
        let proxy = Url::parse("http://127.0.0.1:8080").unwrap();

        let input = r#"<a href="/next">n</a><img src="https://cdn.example.com/a.png">"#;
        let out = rewrite_html(input, &upstream, &proxy);

        assert!(out.contains("http://127.0.0.1:8080/proxy/"));
        assert!(!out.contains("href=\"/next\""));
    }

    #[test]
    fn html_rewrite_injects_runtime_shim() {
        let upstream = Url::parse("https://example.com/").unwrap();
        let proxy = Url::parse("http://127.0.0.1:8080").unwrap();
        let input = r#"<html><head></head><body>ok</body></html>"#;
        let out = rewrite_html(input, &upstream, &proxy);
        assert!(out.contains("window.fetch = function"));
        assert!(out.contains("document.addEventListener(\"submit\""));
        assert!(out.contains("window.history.pushState"));
        assert!(out.contains("const softNavigate = (input, mode) =>"));
        assert!(out.contains("window.dispatchEvent(new PopStateEvent(\"popstate\""));
        assert!(out.contains("</script></head>"));
    }
}
