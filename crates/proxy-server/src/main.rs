use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use proxy_core::{decode_target_url, normalize_mount_path};
use proxy_rewriter::rewrite_response_body;
use reqwest::Client;
use std::env;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{debug, error, info};

#[derive(Clone)]
struct AppState {
    http: Client,
    mount_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "proxy_server=debug,tower_http=info".into()),
        )
        .init();

    let mount_path =
        normalize_mount_path(&env::var("PROXY_MOUNT").unwrap_or_else(|_| "/proxy/".to_string()))?;
    let bind_addr = env::var("PROXY_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let proxy_route = format!("{mount_path}{{payload}}");

    let state = Arc::new(AppState {
        http: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        mount_path: mount_path.clone(),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/bootstrap.js", get(bootstrap_js))
        .route("/sw.js", get(sw_js))
        .route("/api/health", get(health))
        .route(&proxy_route, any(proxy_handler))
        .nest_service("/pkg", ServeDir::new("pkg"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("proxy listening on http://{bind_addr} with mount path {mount_path}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../../web/index.html"))
}

async fn bootstrap_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../../../web/bootstrap.js"),
    )
}

async fn sw_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../../../web/sw.js"),
    )
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path(payload): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match proxy_once(&state, payload, method, headers, body).await {
        Ok(response) => response,
        Err(err) => {
            error!("proxy failure: {err:#}");
            (
                StatusCode::BAD_GATEWAY,
                "proxy request failed; check server logs for details",
            )
                .into_response()
        }
    }
}

async fn proxy_once(
    state: &AppState,
    payload: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> anyhow::Result<Response> {
    let target = decode_target_url(&payload)?;
    debug!(%target, "forwarding request");

    let mut request = state.http.request(method, target.as_str());
    for (name, value) in &headers {
        if name == header::HOST || name == header::CONTENT_LENGTH {
            continue;
        }
        request = request.header(name, value);
    }

    let upstream = request.body(body).send().await?;
    let status = StatusCode::from_u16(upstream.status().as_u16())?;
    let upstream_headers = upstream.headers().clone();
    let content_type = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let upstream_body = upstream.bytes().await?.to_vec();
    let rewritten_body = match rewrite_response_body(
        upstream_body.clone(),
        content_type.as_deref(),
        &target,
        &state.mount_path,
    ) {
        Ok(body) => body,
        Err(err) => {
            debug!("rewrite fallback: {err}");
            upstream_body
        }
    };

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(rewritten_body))?;
    let response_headers = response.headers_mut();

    for (name, value) in &upstream_headers {
        if name == header::CONTENT_LENGTH || name == header::CONTENT_ENCODING {
            continue;
        }
        response_headers.insert(name, value.clone());
    }
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );

    Ok(response)
}
