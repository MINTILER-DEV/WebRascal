# WebRascal

Rust + WASM outline for a Scramjet-inspired web proxy.

## Layout

```text
.
+- crates/
|  +- proxy-rewriter/   # URL tokenization + HTML/link rewrite
|  +- proxy-wasm/       # wasm-bindgen wrapper around rewriter core
|  +- proxy-server/     # Axum proxy server and static web host
+- web/
   +- index.html        # Proxy UI layout
   +- app.js            # Browser bootstrap + wasm usage
   +- sw.js             # Service worker interception skeleton
```

## Quick start

1. Build and run the server:

```bash
cargo run -p proxy-server
```

2. Optional: build WASM helpers into `web/pkg`:

```bash
wasm-pack build crates/proxy-wasm --target web --out-dir ../../web/pkg
```

3. Open `http://127.0.0.1:8080`.

## Notes

- This is an architecture scaffold, not a production-safe proxy.
- Missing pieces for production: CSP/sandbox hardening, cookie/session isolation, websocket piping, full JS/CSS rewriting, and abuse controls.
