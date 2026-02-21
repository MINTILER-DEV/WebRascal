use anyhow::Context;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{any, get};
use axum::{Json, Router};
use clap::Parser;
use proxy_rewriter::{decode_target, encode_target};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;
use tracing::{error, info};
use url::Url;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[derive(Default)]
struct CookieStore {
    sessions: HashMap<String, SessionCookies>,
}

#[derive(Default)]
struct SessionCookies {
    domains: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    cookies: Arc<Mutex<CookieStore>>,
}

#[derive(Debug, Deserialize)]
struct EncodeQuery {
    url: String,
}

#[derive(Debug, Deserialize)]
struct ProxyQuery {
    sid: Option<String>,
}

#[derive(Debug)]
struct ParsedSetCookie {
    domain: String,
    name: String,
    value: String,
    delete: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed building reqwest client")?;

    let state = AppState {
        client,
        cookies: Arc::new(Mutex::new(CookieStore::default())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/sw.js", get(service_worker))
        .route("/healthz", get(healthz))
        .route("/api/encode", get(encode))
        .route("/proxy/:token", any(proxy))
        .nest_service("/web", ServeDir::new("web"))
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
    Query(query): Query<ProxyQuery>,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let upstream = decode_target(&token).map_err(|_| ProxyError::BadRequest("invalid proxy token".to_string()))?;
    let sid = sanitize_sid(query.sid);

    let method = request.method().clone();
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), 32 * 1024 * 1024)
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed reading request body: {e}")))?;

    dispatch_upstream(&state, &sid, upstream, method, headers, body).await
}

async fn dispatch_upstream(
    state: &AppState,
    sid: &str,
    upstream: Url,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response<Body>, ProxyError> {
    let mut outgoing = state.client.request(method_from_axum(&method), upstream.clone());
    outgoing = outgoing.headers(filtered_request_headers(&headers, &upstream, sid, &state.cookies)?);

    if !body.is_empty() {
        outgoing = outgoing.body(body);
    } else if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        outgoing = outgoing.header(reqwest::header::CONTENT_LENGTH, "0");
        outgoing = outgoing.body(Vec::new());
    }

    let upstream_res = outgoing.send().await.map_err(|e| {
        let detail = describe_reqwest_error("send", &method, &upstream, &e);
        error!("{detail}");
        ProxyError::Upstream(detail)
    })?;

    store_set_cookies(&state.cookies, sid, &upstream, upstream_res.headers());

    let status = upstream_res.status();
    let mut out_headers = filtered_response_headers(upstream_res.headers());
    rewrite_location_header(&mut out_headers, &upstream, sid);
    if let Ok(value) = HeaderValue::from_str(upstream.as_str()) {
        out_headers.insert(HeaderName::from_static("x-wr-upstream"), value);
    }

    let body = upstream_res
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed reading upstream body: {e}")))?;

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    Ok(response)
}

fn sanitize_sid(raw: Option<String>) -> String {
    let mut out = String::new();
    for ch in raw.unwrap_or_default().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        }
        if out.len() >= 64 {
            break;
        }
    }
    if out.is_empty() {
        "default".to_string()
    } else {
        out
    }
}

fn filtered_request_headers(
    input: &HeaderMap,
    upstream: &Url,
    sid: &str,
    cookies: &Arc<Mutex<CookieStore>>,
) -> Result<reqwest::header::HeaderMap, ProxyError> {
    let mut out = reqwest::header::HeaderMap::new();

    for (name, value) in input {
        if is_hop_by_hop(name)
            || name == header::HOST
            || name == header::COOKIE
            || name == header::CONTENT_LENGTH
            || name.as_str().eq_ignore_ascii_case("x-wr-session")
        {
            continue;
        }

        if name == header::ORIGIN {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&upstream.origin().ascii_serialization()) {
                out.insert(reqwest::header::ORIGIN, value);
            }
            continue;
        }

        if name == header::REFERER {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(upstream.as_str()) {
                out.insert(reqwest::header::REFERER, value);
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

    if let Some(cookie_header) = build_cookie_header(cookies, sid, upstream) {
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&cookie_header) {
            out.insert(reqwest::header::COOKIE, value);
        }
    }

    Ok(out)
}

fn build_cookie_header(cookies: &Arc<Mutex<CookieStore>>, sid: &str, upstream: &Url) -> Option<String> {
    let host = upstream.host_str()?.to_ascii_lowercase();
    let mut merged: HashMap<String, String> = HashMap::new();

    let store = cookies.lock().ok()?;
    let session = store.sessions.get(sid)?;
    for (domain, jar) in &session.domains {
        if domain_matches(&host, domain) {
            for (name, value) in jar {
                merged.insert(name.clone(), value.clone());
            }
        }
    }

    if merged.is_empty() {
        return None;
    }

    let mut parts = Vec::with_capacity(merged.len());
    for (name, value) in merged {
        parts.push(format!("{name}={value}"));
    }
    Some(parts.join("; "))
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn store_set_cookies(cookies: &Arc<Mutex<CookieStore>>, sid: &str, upstream: &Url, headers: &reqwest::header::HeaderMap) {
    let default_domain = upstream
        .host_str()
        .map(|h| h.to_ascii_lowercase())
        .unwrap_or_default();

    let mut parsed = Vec::new();
    for value in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(raw) = value.to_str() {
            if let Some(cookie) = parse_set_cookie(raw, &default_domain) {
                parsed.push(cookie);
            }
        }
    }

    if parsed.is_empty() {
        return;
    }

    if let Ok(mut store) = cookies.lock() {
        let session = store
            .sessions
            .entry(sid.to_string())
            .or_insert_with(SessionCookies::default);
        for cookie in parsed {
            let jar = session
                .domains
                .entry(cookie.domain)
                .or_insert_with(HashMap::new);
            if cookie.delete {
                jar.remove(&cookie.name);
            } else {
                jar.insert(cookie.name, cookie.value);
            }
        }
    }
}

fn parse_set_cookie(raw: &str, default_domain: &str) -> Option<ParsedSetCookie> {
    let mut parts = raw.split(';');
    let first = parts.next()?.trim();
    let mut kv = first.splitn(2, '=');
    let name = kv.next()?.trim().to_string();
    let value = kv.next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut domain = default_domain.to_string();
    let mut delete = false;

    for attr in parts {
        let trimmed = attr.trim();
        let mut attr_kv = trimmed.splitn(2, '=');
        let key = attr_kv.next().unwrap_or("").trim().to_ascii_lowercase();
        let val = attr_kv.next().unwrap_or("").trim();
        if key == "domain" && !val.is_empty() {
            domain = val.trim_start_matches('.').to_ascii_lowercase();
        }
        if key == "max-age" && val == "0" {
            delete = true;
        }
        if key == "expires" && val.contains("1970") {
            delete = true;
        }
    }

    Some(ParsedSetCookie {
        domain,
        name,
        value,
        delete,
    })
}

fn filtered_response_headers(input: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in input {
        if is_hop_by_hop(name)
            || name == reqwest::header::CONTENT_LENGTH
            || name == reqwest::header::SET_COOKIE
        {
            continue;
        }

        if let (Ok(parsed_name), Ok(parsed_value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.insert(parsed_name, parsed_value);
        }
    }
    out
}

fn rewrite_location_header(headers: &mut HeaderMap, upstream: &Url, sid: &str) {
    let Some(location) = headers.get(header::LOCATION).cloned() else {
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

    let rewritten = format!("/proxy/{}?sid={sid}", encode_target(&target));
    if let Ok(value) = HeaderValue::from_str(&rewritten) {
        headers.insert(header::LOCATION, value);
    }
}

fn method_from_axum(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
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
