let wasm = null;

const statusEl = document.getElementById("status");
const form = document.getElementById("proxy-form");
const input = document.getElementById("target-url");
const viewer = document.getElementById("viewer");
const swButton = document.getElementById("install-sw");
const overlay = document.getElementById("overlay");
const hideOverlayButton = document.getElementById("hide-overlay");
const showOverlayButton = document.getElementById("show-overlay");

bootWasm();
setOverlayVisible(true);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawUrl = input.value.trim();
  if (!rawUrl) return;

  try {
    const token = await buildProxyToken(rawUrl);
    viewer.src = `/proxy/${token}`;
    status("Proxying: " + rawUrl);
  } catch (error) {
    status("Could not proxy URL: " + String(error));
  }
});

swButton.addEventListener("click", async () => {
  if (!("serviceWorker" in navigator)) {
    status("Service worker is not supported in this browser.");
    return;
  }
  try {
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    status("Service worker registered.");
  } catch (error) {
    status("Service worker registration failed: " + String(error));
  }
});

hideOverlayButton.addEventListener("click", () => setOverlayVisible(false));
showOverlayButton.addEventListener("click", () => setOverlayVisible(true));
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  setOverlayVisible(overlay.classList.contains("hidden"));
});

async function bootWasm() {
  try {
    const module = await import("/web/pkg/proxy_wasm.js");
    await module.default();
    wasm = module;
    status("WASM helper loaded.");
  } catch (_) {
    status("WASM helper not found. Falling back to server encode API.");
  }
}

async function buildProxyToken(url) {
  if (wasm?.encode_target_url) {
    return wasm.encode_target_url(url);
  }

  const response = await fetch(`/api/encode?url=${encodeURIComponent(url)}`);
  if (!response.ok) {
    throw new Error(`encode API failed with ${response.status}`);
  }
  const data = await response.json();
  return data.token;
}

function status(message) {
  statusEl.textContent = message;
}

function setOverlayVisible(visible) {
  overlay.classList.toggle("hidden", !visible);
  showOverlayButton.classList.toggle("visible", !visible);
  if (visible) input.focus();
}
