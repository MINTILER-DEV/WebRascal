use anyhow::Context;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{any, get};
use axum::{Json, Router};
use clap::Parser;
use proxy_rewriter::{decode_target, encode_target, rewrite_html, rewrite_location_header};
use reqwest::Client;
use serde::Deserialize;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{error, info};
use url::Url;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    public_origin: Url,
    #[arg(long, default_value_t = false)]
    insecure: bool,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    public_origin: Url,
}

#[derive(Debug, Deserialize)]
struct EncodeQuery {
    url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let mut client_builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    if args.insecure {
        info!("TLS certificate verification disabled via --insecure");
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let client = client_builder
        .build()
        .context("failed building reqwest client")?;

    let state = AppState {
        client,
        public_origin: args.public_origin,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/sw.js", get(service_worker))
        .route("/healthz", get(healthz))
        .route("/api/encode", get(encode))
        .route("/proxy/:token", any(proxy))
        .nest_service("/web", ServeDir::new("web"))
        .route("/*path", any(proxy_relative))
        .with_state(Arc::new(state));

    info!("proxy server listening on {}", args.listen);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../../web/index.html"))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn service_worker() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("../../../web/sw.js"),
    )
}

async fn encode(Query(query): Query<EncodeQuery>) -> Result<Json<serde_json::Value>, ProxyError> {
    let target = Url::parse(&query.url).map_err(|_| ProxyError::BadRequest("invalid url".to_string()))?;
    Ok(Json(serde_json::json!({
        "token": encode_target(&target),
    })))
}

async fn proxy(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let upstream = decode_target(&token).map_err(|_| ProxyError::BadRequest("invalid proxy token".to_string()))?;
    let method = request.method().clone();
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed reading request body: {e}")))?;
    dispatch_upstream(&state, upstream, method, headers, body_bytes).await
}

async fn proxy_relative(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let upstream_context = upstream_from_context(&headers)
        .ok_or_else(|| ProxyError::BadRequest("missing proxy context (referer/cookie)".to_string()))?;
    let upstream = absolutize_relative_target(&upstream_context, &uri)
        .map_err(|e| ProxyError::BadRequest(format!("invalid relative proxy target: {e}")))?;
    let body_bytes = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed reading request body: {e}")))?;
    dispatch_upstream(&state, upstream, method, headers, body_bytes).await
}

async fn dispatch_upstream(
    state: &AppState,
    upstream: Url,
    method: Method,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<Response<Body>, ProxyError> {
    let is_googlevideo = upstream
        .host_str()
        .map(|h| h.ends_with("googlevideo.com"))
        .unwrap_or(false);

    let mut outgoing = state.client.request(method_from_axum(&method), upstream.clone());
    outgoing = outgoing.headers(filtered_request_headers(
        &headers,
        &upstream,
        &state.public_origin,
        is_googlevideo,
    ));
    if !body_bytes.is_empty() {
        outgoing = outgoing.body(body_bytes);
    } else if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        // Some upstreams require explicit content-length for empty entity requests.
        outgoing = outgoing.body(Vec::new());
    }

    let upstream_res = outgoing
        .send()
        .await
        .map_err(|e| {
            let detail = describe_reqwest_error("send", &method, &upstream, &e);
            error!("{detail}");
            ProxyError::Upstream(detail)
        })?;

    let status = upstream_res.status();
    let mut response_headers = filtered_response_headers(upstream_res.headers());
    rewrite_location_header(&mut response_headers, &upstream, &state.public_origin);

    let content_type = upstream_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if content_type.contains("text/html") {
        apply_proxy_context_headers(&mut response_headers, &upstream);
    }

    let body = upstream_res
        .bytes()
        .await
        .map_err(|e| {
            let detail = format!("failed reading upstream body: {e}");
            error!("{detail}");
            ProxyError::Upstream(detail)
        })?;

    if content_type.contains("text/html") {
        let html = String::from_utf8_lossy(&body);
        let rewritten = rewrite_html(&html, &upstream, &state.public_origin);
        let mut response = Response::new(Body::from(rewritten));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        return Ok(response);
    }

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}

fn upstream_from_referer(headers: &HeaderMap) -> Option<Url> {
    let referer = headers.get(header::REFERER)?.to_str().ok()?;
    let referer_url = Url::parse(referer).ok()?;
    let mut parts = referer_url.path().trim_start_matches('/').split('/');
    let first = parts.next()?;
    if first != "proxy" {
        return None;
    }
    let token = parts.next()?;
    decode_target(token).ok()
}

fn upstream_from_context(headers: &HeaderMap) -> Option<Url> {
    if let Some(url) = upstream_from_header(headers) {
        return Some(url);
    }

    if let Some(url) = upstream_from_referer(headers) {
        return Some(url);
    }

    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let trimmed = part.trim();
        if let Some(token) = trimmed.strip_prefix("wr_ctx=") {
            if let Ok(url) = decode_target(token) {
                return Some(url);
            }
        }
    }
    None
}

fn upstream_from_header(headers: &HeaderMap) -> Option<Url> {
    let value = headers.get("x-webrascal-upstream")?.to_str().ok()?;
    Url::parse(value).ok()
}

fn absolutize_relative_target(upstream_context: &Url, uri: &axum::http::Uri) -> Result<Url, url::ParseError> {
    let mut origin = upstream_context.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let path_q = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    origin.join(path_q)
}

fn method_from_axum(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

fn filtered_request_headers(
    input: &HeaderMap,
    target_upstream: &Url,
    proxy_origin: &Url,
    is_googlevideo: bool,
) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    let context_upstream = upstream_from_context(input);
    let referer_base = context_upstream.as_ref().unwrap_or(target_upstream);
    let rewritten_referer = input
        .get(header::REFERER)
        .and_then(|v| rewrite_referer_for_upstream(v, referer_base, proxy_origin));

    for (name, value) in input.iter() {
        if is_hop_by_hop(name)
            || name == header::HOST
            || name == header::CONTENT_LENGTH
            || name.as_str().eq_ignore_ascii_case("x-webrascal-upstream")
        {
            continue;
        }

        if name == header::COOKIE {
            if let Some(cookie) = sanitize_cookie_header(value) {
                out.insert(reqwest::header::COOKIE, cookie);
            }
            continue;
        }

        if name == header::ORIGIN {
            if let Some(mut origin) = rewrite_origin_for_upstream(
                value,
                context_upstream.as_ref(),
                rewritten_referer.as_ref(),
                target_upstream,
                proxy_origin,
            ) {
                if is_googlevideo {
                    let gv_origin = googlevideo_origin(context_upstream.as_ref());
                    if let Ok(v) = reqwest::header::HeaderValue::from_str(&gv_origin) {
                        origin = v;
                    }
                }
                out.insert(reqwest::header::ORIGIN, origin);
            }
            continue;
        }

        if name == header::REFERER {
            if let Some(mut referrer) = rewritten_referer.clone() {
                if is_googlevideo {
                    let gv_referrer = googlevideo_referer(context_upstream.as_ref());
                    if let Ok(v) = reqwest::header::HeaderValue::from_str(&gv_referrer) {
                        referrer = v;
                    }
                }
                out.insert(reqwest::header::REFERER, referrer);
            }
            continue;
        }

        if let (Ok(parsed_name), Ok(parsed_value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.insert(parsed_name, parsed_value);
        }
    }
    out
}

fn googlevideo_origin(context_upstream: Option<&Url>) -> String {
    if let Some(ctx) = context_upstream {
        if ctx.host_str().map(|h| h.ends_with("youtube.com")).unwrap_or(false) {
            return ctx.origin().ascii_serialization();
        }
    }
    "https://www.youtube.com".to_string()
}

fn googlevideo_referer(context_upstream: Option<&Url>) -> String {
    if let Some(ctx) = context_upstream {
        if ctx.host_str().map(|h| h.ends_with("youtube.com")).unwrap_or(false) {
            let mut base = ctx.clone();
            base.set_fragment(None);
            return base.to_string();
        }
    }
    "https://www.youtube.com/".to_string()
}

fn sanitize_cookie_header(value: &HeaderValue) -> Option<reqwest::header::HeaderValue> {
    let raw = value.to_str().ok()?;
    let mut kept = Vec::new();
    for part in raw.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() || trimmed.starts_with("wr_ctx=") {
            continue;
        }
        kept.push(trimmed);
    }
    if kept.is_empty() {
        return None;
    }
    reqwest::header::HeaderValue::from_str(&kept.join("; ")).ok()
}

fn rewrite_referer_for_upstream(
    value: &HeaderValue,
    context_upstream: &Url,
    proxy_origin: &Url,
) -> Option<reqwest::header::HeaderValue> {
    let raw = value.to_str().ok()?;
    let parsed = Url::parse(raw).ok();

    let rewritten = if let Some(ref_url) = parsed {
        if same_origin(&ref_url, proxy_origin) {
            if let Some(token) = ref_url.path().strip_prefix("/proxy/") {
                decode_target(token).ok().map(|u| u.to_string()).unwrap_or_else(|| raw.to_string())
            } else {
                let mut mapped = context_upstream.clone();
                mapped.set_path(ref_url.path());
                mapped.set_query(ref_url.query());
                mapped.set_fragment(ref_url.fragment());
                mapped.to_string()
            }
        } else {
            raw.to_string()
        }
    } else {
        raw.to_string()
    };

    reqwest::header::HeaderValue::from_str(&rewritten).ok()
}

fn rewrite_origin_for_upstream(
    value: &HeaderValue,
    context_upstream: Option<&Url>,
    rewritten_referer: Option<&reqwest::header::HeaderValue>,
    target_upstream: &Url,
    proxy_origin: &Url,
) -> Option<reqwest::header::HeaderValue> {
    let raw = value.to_str().ok()?;
    let parsed_origin = Url::parse(raw).ok();

    if let Some(origin_url) = parsed_origin {
        if same_origin(&origin_url, proxy_origin) {
            if let Some(referrer_value) = rewritten_referer {
                if let Ok(referrer_str) = referrer_value.to_str() {
                    if let Ok(referrer_url) = Url::parse(referrer_str) {
                        let origin = referrer_url.origin().ascii_serialization();
                        return reqwest::header::HeaderValue::from_str(&origin).ok();
                    }
                }
            }
            let fallback = context_upstream.unwrap_or(target_upstream);
            let origin = fallback.origin().ascii_serialization();
            return reqwest::header::HeaderValue::from_str(&origin).ok();
        }
    }

    reqwest::header::HeaderValue::from_bytes(value.as_bytes()).ok()
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn filtered_response_headers(input: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in input.iter() {
        if is_hop_by_hop(name) || name == reqwest::header::CONTENT_LENGTH || is_strict_security_response_header(name) {
            continue;
        }
        if let (Ok(parsed_name), Ok(parsed_value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if parsed_name == header::SET_COOKIE {
                out.append(parsed_name, parsed_value);
            } else {
                out.insert(parsed_name, parsed_value);
            }
        }
    }
    out
}

fn is_strict_security_response_header(name: &reqwest::header::HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "x-frame-options"
            | "content-security-policy"
            | "content-security-policy-report-only"
            | "referrer-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-embedder-policy"
            | "cross-origin-resource-policy"
    )
}

fn apply_proxy_context_headers(headers: &mut HeaderMap, upstream: &Url) {
    let token = encode_target(upstream);
    let cookie = format!("wr_ctx={token}; Path=/; HttpOnly; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }

    if !headers.contains_key(header::REFERRER_POLICY) {
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn describe_reqwest_error(stage: &str, method: &Method, upstream: &Url, err: &reqwest::Error) -> String {
    let mut flags = Vec::new();
    if err.is_connect() {
        flags.push("connect");
    }
    if err.is_timeout() {
        flags.push("timeout");
    }
    if err.is_request() {
        flags.push("request");
    }
    if err.is_decode() {
        flags.push("decode");
    }
    if err.is_redirect() {
        flags.push("redirect");
    }
    if err.is_builder() {
        flags.push("builder");
    }
    if err.is_body() {
        flags.push("body");
    }

    let mut message = format!("{stage} failed for {} {}: {err}", method, upstream);
    if !flags.is_empty() {
        message.push_str(" [kind=");
        message.push_str(&flags.join("|"));
        message.push(']');
    }

    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(" | cause: ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    if message.contains("UnknownIssuer") {
        message.push_str(
            " | hint: untrusted TLS issuer. Use system root certs, trust your network's root CA, or use --insecure for local debugging only.",
        );
    }

    message
}

#[derive(Debug)]
enum ProxyError {
    BadRequest(String),
    Upstream(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::Upstream(msg) => (StatusCode::BAD_GATEWAY, msg).into_response(),
        }
    }
}
