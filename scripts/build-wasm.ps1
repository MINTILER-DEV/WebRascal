$ErrorActionPreference = "Stop"

wasm-pack build crates/proxy-wasm --target web --out-dir pkg --out-name proxy_wasm

