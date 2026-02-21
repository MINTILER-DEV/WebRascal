(() => {
  const SKIP_SCHEMES = /^(data:|blob:|javascript:|about:|mailto:|tel:)/i;
  const INTERNAL_PATHS = ["/web/", "/sw.js", "/healthz", "/api/"];

  const state = {
    installed: false,
    base: null,
    sid: "default",
  };

  function sanitizeSid(input) {
    const cleaned = String(input || "").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
    return cleaned || "default";
  }

  function toRaw(input) {
    if (input == null) return "";
    if (typeof input === "string") return input;
    if (typeof URL !== "undefined" && input instanceof URL) return input.href;
    if (typeof Request !== "undefined" && input instanceof Request) return input.url || "";
    if (typeof input === "object") {
      if (typeof input.url === "string") return input.url;
      if (typeof input.href === "string") return input.href;
    }
    try {
      return String(input);
    } catch (_) {
      return "";
    }
  }

  function base64Url(input) {
    const bytes = new TextEncoder().encode(input);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  function buildProxyPath(target) {
    return `/proxy/${base64Url(target)}?sid=${encodeURIComponent(state.sid)}`;
  }

  function resolve(input) {
    if (!state.base) return null;
    const raw = toRaw(input);
    if (!raw || SKIP_SCHEMES.test(raw)) return null;

    try {
      const resolved = new URL(raw, state.base);
      return resolved;
    } catch (_) {
      return null;
    }
  }

  function isInternalPath(pathname) {
    return INTERNAL_PATHS.some((prefix) => pathname === prefix || pathname.startsWith(prefix));
  }

  function toProxy(input) {
    const resolved = resolve(input);
    if (!resolved) return null;

    if (resolved.origin === location.origin && resolved.pathname.startsWith("/proxy/")) {
      return resolved.pathname + resolved.search + resolved.hash;
    }

    if (resolved.origin === location.origin && isInternalPath(resolved.pathname)) {
      return resolved.pathname + resolved.search + resolved.hash;
    }

    return buildProxyPath(resolved.toString());
  }

  function toAppPath(input) {
    const resolved = resolve(input);
    if (!resolved) return null;

    try {
      const base = new URL(state.base);
      if (resolved.origin !== base.origin) return null;
      return resolved.pathname + resolved.search + resolved.hash;
    } catch (_) {
      return null;
    }
  }

  function toNavigable(input) {
    return toAppPath(input) || toProxy(input) || toRaw(input);
  }

  function patchLocationHistory() {
    if (!history || !location) return;

    const origPush = history.pushState?.bind(history);
    if (origPush) {
      history.pushState = function (stateObj, title, url) {
        const mapped = url == null ? url : toAppPath(url) || url;
        return origPush(stateObj, title, mapped);
      };
    }

    const origReplace = history.replaceState?.bind(history);
    if (origReplace) {
      history.replaceState = function (stateObj, title, url) {
        const mapped = url == null ? url : toAppPath(url) || url;
        return origReplace(stateObj, title, mapped);
      };
    }

    const locProto = location && location.constructor && location.constructor.prototype;
    if (!locProto) return;

    if (typeof locProto.assign === "function") {
      const origAssign = locProto.assign;
      locProto.assign = function (url) {
        return origAssign.call(this, toNavigable(url));
      };
    }

    if (typeof locProto.replace === "function") {
      const origLocReplace = locProto.replace;
      locProto.replace = function (url) {
        return origLocReplace.call(this, toNavigable(url));
      };
    }
  }

  function patchFetch() {
    if (typeof fetch !== "function") return;
    const origFetch = fetch.bind(globalThis);

    globalThis.fetch = function (input, init) {
      try {
        if (input instanceof Request) {
          const mapped = toProxy(input.url);
          if (mapped) input = new Request(mapped, input);
        } else {
          const mapped = toProxy(input);
          if (mapped) input = mapped;
        }
      } catch (_) {}
      return origFetch(input, init);
    };
  }

  function patchXhr() {
    if (typeof XMLHttpRequest === "undefined") return;

    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      const mapped = toProxy(url);
      return origOpen.call(this, method, mapped || url, ...Array.prototype.slice.call(arguments, 2));
    };
  }

  function patchBeacon() {
    if (!navigator || typeof navigator.sendBeacon !== "function") return;

    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      const mapped = toProxy(url);
      return origBeacon(mapped || url, data);
    };
  }

  function patchWebSocket() {
    if (typeof WebSocket !== "function") return;

    const NativeWebSocket = WebSocket;
    const toWsProxy = (url) => {
      const resolved = resolve(url);
      if (!resolved) return url;
      if (!(resolved.protocol === "ws:" || resolved.protocol === "wss:")) {
        return url;
      }

      const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
      const token = base64Url(resolved.toString());
      return `${wsProtocol}//${location.host}/proxy-ws/${token}?sid=${encodeURIComponent(state.sid)}`;
    };

    globalThis.WebSocket = function (url, protocols) {
      const mapped = toWsProxy(url);
      if (protocols === undefined) return new NativeWebSocket(mapped);
      return new NativeWebSocket(mapped, protocols);
    };
    globalThis.WebSocket.prototype = NativeWebSocket.prototype;
  }

  function patchSetAttribute() {
    if (typeof Element === "undefined") return;

    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      const attr = String(name || "").toLowerCase();
      let mapped = value;

      if (["src", "poster", "data", "srcset"].includes(attr)) {
        mapped = toProxy(value) || value;
      } else if (["href", "action", "formaction", "ping"].includes(attr)) {
        mapped = toNavigable(value) || value;
      }

      return origSetAttribute.call(this, name, mapped);
    };
  }

  function patchResourceSetters() {
    const patch = (proto, prop, mapper) => {
      if (!proto) return;
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || typeof desc.set !== "function" || !desc.configurable) return;
      const origSet = desc.set;
      Object.defineProperty(proto, prop, Object.assign({}, desc, {
        set(value) {
          const mapped = mapper(value);
          return origSet.call(this, mapped || value);
        },
      }));
    };

    patch(typeof HTMLIFrameElement !== "undefined" ? HTMLIFrameElement.prototype : null, "src", toNavigable);
    patch(typeof HTMLImageElement !== "undefined" ? HTMLImageElement.prototype : null, "src", toProxy);
    patch(typeof HTMLScriptElement !== "undefined" ? HTMLScriptElement.prototype : null, "src", toProxy);
    patch(typeof HTMLLinkElement !== "undefined" ? HTMLLinkElement.prototype : null, "href", toProxy);
    patch(typeof HTMLFormElement !== "undefined" ? HTMLFormElement.prototype : null, "action", toNavigable);
    patch(typeof HTMLAnchorElement !== "undefined" ? HTMLAnchorElement.prototype : null, "href", toNavigable);
  }

  function patchForms() {
    if (typeof HTMLFormElement === "undefined") return;

    const origSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      try {
        const action = this.getAttribute("action") || location.href;
        const mapped = toNavigable(action);
        if (mapped) this.setAttribute("action", mapped);
      } catch (_) {}
      return origSubmit.call(this);
    };

    if (typeof HTMLFormElement.prototype.requestSubmit === "function") {
      const origRequestSubmit = HTMLFormElement.prototype.requestSubmit;
      HTMLFormElement.prototype.requestSubmit = function (submitter) {
        try {
          const action = this.getAttribute("action") || location.href;
          const mapped = toNavigable(action);
          if (mapped) this.setAttribute("action", mapped);
        } catch (_) {}
        return origRequestSubmit.call(this, submitter);
      };
    }
  }

  function patchWindowOpen() {
    if (typeof open !== "function") return;
    const origOpen = open.bind(globalThis);
    globalThis.open = function (url) {
      const mapped = toNavigable(url);
      return origOpen(mapped || url, ...Array.prototype.slice.call(arguments, 1));
    };
  }

  function install(config = {}) {
    if (config.base) {
      state.base = String(config.base);
    }
    if (config.sid) {
      state.sid = sanitizeSid(config.sid);
    }

    if (!state.base || state.installed) {
      return;
    }

    patchLocationHistory();
    patchFetch();
    patchXhr();
    patchBeacon();
    patchWebSocket();
    patchSetAttribute();
    patchResourceSetters();
    patchForms();
    patchWindowOpen();

    state.installed = true;
  }

  globalThis.__WR_INSTALL = install;

  try {
    if (typeof document !== "undefined") {
      const script = document.currentScript;
      if (script && script.dataset) {
        install({
          base: script.dataset.wrBase,
          sid: script.dataset.wrSid,
        });
      }
    }
  } catch (_) {}
})();
