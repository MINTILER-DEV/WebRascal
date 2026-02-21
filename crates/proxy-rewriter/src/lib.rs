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
    attr_re
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
        .to_string()
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
}
