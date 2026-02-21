use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid target URL: {0}")]
    InvalidTargetUrl(#[from] url::ParseError),
    #[error("invalid proxy mount path")]
    InvalidMountPath,
    #[error("invalid encoded URL payload")]
    InvalidEncodedPayload,
    #[error("encoded URL payload is not UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

pub fn normalize_mount_path(mount_path: &str) -> Result<String, ProxyError> {
    let trimmed = mount_path.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidMountPath);
    }

    let with_leading = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };

    let normalized = if with_leading.ends_with('/') {
        with_leading
    } else {
        format!("{with_leading}/")
    };

    Ok(normalized)
}

pub fn encode_target_url(target: &str) -> Result<String, ProxyError> {
    let parsed = Url::parse(target)?;
    Ok(URL_SAFE_NO_PAD.encode(parsed.as_str().as_bytes()))
}

pub fn decode_target_url(payload: &str) -> Result<Url, ProxyError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| ProxyError::InvalidEncodedPayload)?;
    let as_string = String::from_utf8(decoded)?;
    Ok(Url::parse(&as_string)?)
}

pub fn proxy_path(mount_path: &str, target: &str) -> Result<String, ProxyError> {
    let normalized = normalize_mount_path(mount_path)?;
    let payload = encode_target_url(target)?;
    Ok(format!("{normalized}{payload}"))
}
