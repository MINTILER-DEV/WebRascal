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
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::info;
use url::Url;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    public_origin: Url,
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
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed building reqwest client")?;

    let state = AppState {
        client,
        public_origin: args.public_origin,
    };

    let app = Router::new()
        .route("/", get(index))
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

    let mut outgoing = state.client.request(method_from_axum(&method), upstream.clone());
    outgoing = outgoing.headers(filtered_request_headers(&headers));
    if !body_bytes.is_empty() {
        outgoing = outgoing.body(body_bytes.clone());
    }

    let upstream_res = outgoing
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(format!("request failed: {e}")))?;

    let status = upstream_res.status();
    let mut response_headers = filtered_response_headers(upstream_res.headers());
    rewrite_location_header(&mut response_headers, &upstream, &state.public_origin);

    let content_type = upstream_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = upstream_res
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed reading upstream body: {e}")))?;

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

fn method_from_axum(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

fn filtered_request_headers(input: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (name, value) in input.iter() {
        if is_hop_by_hop(name) || name == header::HOST || name == header::CONTENT_LENGTH {
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

fn filtered_response_headers(input: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in input.iter() {
        if is_hop_by_hop(name) || name == reqwest::header::CONTENT_LENGTH {
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
