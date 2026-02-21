use proxy_rewriter::{decode_target, encode_target, rewrite_html};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_target_url(input: &str) -> Result<String, String> {
    let url = url::Url::parse(input).map_err(|e| format!("invalid url: {e}"))?;
    Ok(encode_target(&url))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_target_url(token: &str) -> Result<String, String> {
    let decoded = decode_target(token).map_err(|e| format!("decode error: {e:?}"))?;
    Ok(decoded.into())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn rewrite_document_html(
    html: &str,
    upstream_origin: &str,
    proxy_origin: &str,
) -> Result<String, String> {
    let upstream = url::Url::parse(upstream_origin).map_err(|e| format!("invalid upstream: {e}"))?;
    let proxy = url::Url::parse(proxy_origin).map_err(|e| format!("invalid proxy: {e}"))?;
    Ok(rewrite_html(html, &upstream, &proxy))
}
