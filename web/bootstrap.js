import init, { build_proxy_url, register_service_worker } from "/pkg/proxy_wasm.js";

const mountPath = "/proxy/";
const statusNode = document.querySelector("#status");
const form = document.querySelector("#proxy-form");
const targetInput = document.querySelector("#target-url");
const proxyFrame = document.querySelector("#proxy-view");

function setStatus(message) {
  statusNode.textContent = message;
}

function openTarget(target) {
  const proxied = build_proxy_url(mountPath, target);
  proxyFrame.src = proxied;
  setStatus(`Proxy route: ${proxied}`);
}

async function boot() {
  await init();
  setStatus("WASM runtime loaded.");

  if ("serviceWorker" in navigator) {
    try {
      register_service_worker("/sw.js");
      setStatus("WASM ready. Service worker registered.");
    } catch (error) {
      setStatus(`WASM ready. SW registration skipped: ${error}`);
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    openTarget(targetInput.value);
  });

  openTarget(targetInput.value);
}

boot().catch((error) => setStatus(`Boot failure: ${error}`));

