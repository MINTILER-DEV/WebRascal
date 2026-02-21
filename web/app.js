const form = document.getElementById("proxy-form");
const input = document.getElementById("target-url");
const viewer = document.getElementById("viewer");
const statusEl = document.getElementById("status");
const swButton = document.getElementById("install-sw");
const overlay = document.getElementById("overlay");
const hideOverlayButton = document.getElementById("hide-overlay");
const showOverlayButton = document.getElementById("show-overlay");

const SESSION_KEY = "wr.sid";
const sessionId = ensureSessionId();
let currentRegistration = null;

boot();

async function boot() {
  setOverlayVisible(true);
  await ensureServiceWorker();
  postSessionToServiceWorker();
  if (!navigator.serviceWorker.controller) {
    status("Service worker installed. Reload this page once to fully activate proxy interception.");
    return;
  }
  status(`Session ${sessionId.slice(0, 8)} ready.`);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const raw = normalizeUrl(input.value.trim());
  if (!raw) return;

  viewer.src = buildProxyPath(raw, sessionId);
  status("Proxying: " + raw);
});

swButton.addEventListener("click", async () => {
  try {
    await ensureServiceWorker(true);
    postSessionToServiceWorker();
    status("Service worker refreshed.");
  } catch (error) {
    status("Service worker install failed: " + String(error));
  }
});

hideOverlayButton.addEventListener("click", () => setOverlayVisible(false));
showOverlayButton.addEventListener("click", () => setOverlayVisible(true));
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  setOverlayVisible(overlay.classList.contains("hidden"));
});

function ensureSessionId() {
  const existing = sessionStorage.getItem(SESSION_KEY);
  if (existing) return existing;

  const raw = crypto.randomUUID().replace(/[^a-zA-Z0-9_-]/g, "");
  const sid = raw.slice(0, 32) || `sid${Date.now()}`;
  sessionStorage.setItem(SESSION_KEY, sid);
  return sid;
}

async function ensureServiceWorker(force = false) {
  if (!("serviceWorker" in navigator)) {
    throw new Error("Service worker unsupported in this browser.");
  }

  const registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  currentRegistration = registration;
  if (force) {
    await registration.update();
  }

  return registration;
}

function postSessionToServiceWorker() {
  const payload = {
    type: "wr:session",
    sid: sessionId,
  };

  if (navigator.serviceWorker?.controller) {
    navigator.serviceWorker.controller.postMessage(payload);
    return;
  }

  const fallback = currentRegistration?.active || currentRegistration?.waiting || currentRegistration?.installing;
  fallback?.postMessage(payload);
}

function normalizeUrl(raw) {
  if (!raw) return "";
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(raw)) return raw;
  return `https://${raw}`;
}

function buildProxyPath(targetUrl, sid) {
  return `/proxy/${base64Url(targetUrl)}?sid=${encodeURIComponent(sid)}`;
}

function base64Url(input) {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function status(message) {
  statusEl.textContent = message;
}

function setOverlayVisible(visible) {
  overlay.classList.toggle("hidden", !visible);
  showOverlayButton.classList.toggle("visible", !visible);
  if (visible) input.focus();
}
