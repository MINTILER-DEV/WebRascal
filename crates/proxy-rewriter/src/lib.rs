use proxy_core::proxy_path;
use regex::Regex;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum RewriteError {
    #[error("failed to rewrite link target")]
    InvalidLink(#[from] url::ParseError),
    #[error("failed to create proxied URL")]
    ProxyEncode(#[from] proxy_core::ProxyError),
    #[error("failed to decode upstream HTML as UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub fn rewrite_response_body(
    body: Vec<u8>,
    content_type: Option<&str>,
    origin: &Url,
    mount_path: &str,
) -> Result<Vec<u8>, RewriteError> {
    if !is_html(content_type) {
        return Ok(body);
    }

    let input = String::from_utf8(body)?;
    let attr_pattern = Regex::new(r#"(?i)(href|src|action)=["']([^"']+)["']"#)
        .expect("attribute regex must compile");

    let rewritten = attr_pattern.replace_all(&input, |caps: &regex::Captures| {
        let attr = caps.get(1).map_or("", |m| m.as_str());
        let value = caps.get(2).map_or("", |m| m.as_str());

        match rewrite_link(value, origin, mount_path) {
            Ok(next) => format!(r#"{attr}="{next}""#),
            Err(_) => caps.get(0).map_or("", |m| m.as_str()).to_string(),
        }
    });

    Ok(rewritten.into_owned().into_bytes())
}

fn is_html(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

fn rewrite_link(value: &str, origin: &Url, mount_path: &str) -> Result<String, RewriteError> {
    if value.is_empty()
        || value.starts_with('#')
        || value.starts_with("javascript:")
        || value.starts_with("data:")
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
    {
        return Ok(value.to_string());
    }

    let absolute = origin.join(value)?;
    Ok(proxy_path(mount_path, absolute.as_str())?)
}
