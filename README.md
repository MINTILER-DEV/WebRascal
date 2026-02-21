# WebRascal

Scramjet-inspired web proxy outline in Rust with a WASM runtime for browser integration.

## Workspace Layout

```
.
|- crates/
|  |- proxy-core/      # shared URL encoding, mount path normalization
|  |- proxy-rewriter/  # HTML link rewriting into proxy routes
|  |- proxy-server/    # Axum server, upstream fetch, static shell serving
|  `- proxy-wasm/      # wasm-bindgen interface for browser-side URL building/SW registration
|- web/
|  |- index.html       # basic browser shell
|  |- bootstrap.js     # initializes wasm and launches proxied iframe
|  `- sw.js            # service worker outline hooks
`- Cargo.toml          # workspace manifest
```

## Architecture Outline

1. Browser shell loads `proxy-wasm` and builds a proxied URL path (`/proxy/{base64url}`).
2. Browser navigates to proxied route.
3. `proxy-server` decodes URL payload, fetches upstream response, and returns it.
4. `proxy-rewriter` rewrites HTML `href/src/action` attributes so in-page navigation stays inside the proxy.
5. Service worker is scaffolded for future request virtualization/caching logic.

## Run Locally

1. Build wasm bindings:
   ```powershell
   wasm-pack build crates/proxy-wasm --target web --out-dir pkg --out-name proxy_wasm
   ```
2. Start proxy server:
   ```powershell
   cargo run -p proxy-server
   ```
3. Open:
   `http://127.0.0.1:3000`

## Environment Variables

- `PROXY_BIND` (default: `127.0.0.1:3000`)
- `PROXY_MOUNT` (default: `/proxy/`)

## Notes

- This is intentionally a scaffold, not a hardened production proxy.
- Add production controls before use: auth, target allowlists, CSP/header strategy, request limits, abuse protections, and robust JS/CSS rewriting.

