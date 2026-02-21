#[cfg(not(target_arch = "wasm32"))]
pub fn build_proxy_url(mount_path: &str, target: &str) -> Result<String, String> {
    proxy_core::proxy_path(mount_path, target).map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn register_service_worker(_script_url: &str) -> Result<(), String> {
    Err("register_service_worker is only available for wasm32 targets".to_string())
}

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::window;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn build_proxy_url(mount_path: &str, target: &str) -> Result<String, JsValue> {
    proxy_core::proxy_path(mount_path, target).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn register_service_worker(script_url: String) -> Result<(), JsValue> {
    let Some(browser_window) = window() else {
        return Err(JsValue::from_str("window is not available"));
    };

    browser_window
        .navigator()
        .service_worker()
        .register(&script_url)
        .map(|_| ())
}
