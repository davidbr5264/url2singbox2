/* ============================================================
   Config Forge — vless:// -> sing-box client config (Windows)
   Pure client-side. No network calls, no data leaves the tab.
   ============================================================ */

// ---------- DoH provider table ----------
// Each entry gives the DoH domain + a hosts-style predefined IP set,
// so the bootstrap lookup of the resolver's own hostname never needs
// an unencrypted DNS query (matches sing-box's recommended "hosts" pattern).
const DOH_PROVIDERS = {
  cloudflare: {
    domain: "cloudflare-dns.com",
    ips: ["104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"]
  },
  google: {
    domain: "dns.google",
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]
  },
  quad9: {
    domain: "dns.quad9.net",
    ips: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
  },
  alidns: {
    domain: "dns.alidns.com",
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"]
  }
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------- state ----------
let parsedOutbounds = [];   // array of { tag, config, warnings: [] }
let lastConfig = null;

// ============================================================
// VLESS URL PARSING
// ============================================================
function parseVlessLink(raw, index) {
  raw = raw.trim();
  const warnings = [];
  if (!raw) return null;

  const m = raw.match(/^vless:\/\/([^@]+)@([^:/?#\s]+):(\d+)(\?[^#]*)?(#.*)?$/i);
  if (!m) {
    return { ok: false, raw, error: "Doesn't match vless://uuid@host:port shape." };
  }

  const uuid = decodeURIComponent(m[1]);
  const host = m[2];
  const port = parseInt(m[3], 10);
  const query = new URLSearchParams(m[4] ? m[4].slice(1) : "");
  const remarkRaw = m[5] ? decodeURIComponent(m[5].slice(1)) : "";
  const tag = sanitizeTag(remarkRaw || `proxy-${index + 1}`, index);

  if (!UUID_RE.test(uuid)) {
    warnings.push(`UUID "${uuid}" doesn't look like a standard UUID — double check the link.`);
  }
  if (!port || port < 1 || port > 65535) {
    warnings.push(`Port "${m[3]}" is out of range.`);
  }

  const security = (query.get("security") || "none").toLowerCase();
  const network = (query.get("type") || "tcp").toLowerCase();
  const flow = query.get("flow") || "";
  const sni = query.get("sni") || query.get("peer") || "";
  const fp = query.get("fp") || "chrome";
  const alpnParam = query.get("alpn");

  const outbound = {
    type: "vless",
    tag,
    server: host,
    server_port: port,
    uuid,
    packet_encoding: "xudp"
  };

  if (flow) {
    if (security !== "reality" && security !== "tls") {
      warnings.push(`"flow=${flow}" normally requires TLS/Reality; the link has security=${security}.`);
    }
    if (network !== "tcp" && network !== "raw") {
      warnings.push(`"flow" only applies to raw TCP transport; this link uses "${network}" and flow will be dropped.`);
    } else {
      outbound.flow = flow;
    }
  }

  // ---- TLS / Reality ----
  if (security === "tls" || security === "reality") {
    const tls = {
      enabled: true,
      server_name: sni || outbound.server,
      insecure: query.get("allowInsecure") === "1"
    };
    if (alpnParam) tls.alpn = alpnParam.split(",").map(s => s.trim()).filter(Boolean);
    tls.utls = { enabled: true, fingerprint: fp };

    if (security === "reality") {
      const pbk = query.get("pbk") || "";
      const sid = query.get("sid") || "";
      if (!pbk) warnings.push("Reality is enabled but the link has no pbk (public key) — the outbound will fail to connect.");
      tls.reality = { enabled: true, public_key: pbk, short_id: sid };
    }
    outbound.tls = tls;
  } else if (security && security !== "none") {
    warnings.push(`Unrecognized security="${security}" — treated as no TLS.`);
  }

  // ---- Transport ----
  if (network === "ws") {
    let path = query.get("path") || "/";
    let earlyData = null;
    const edMatch = path.match(/[?&]ed=(\d+)/);
    if (edMatch) {
      earlyData = parseInt(edMatch[1], 10);
      path = path.replace(/[?&]ed=\d+/, "") || "/";
    }
    const transport = { type: "ws", path };
    const hostHeader = query.get("host");
    if (hostHeader) transport.headers = { Host: hostHeader };
    if (earlyData) {
      transport.max_early_data = earlyData;
      transport.early_data_header_name = "Sec-WebSocket-Protocol";
    }
    outbound.transport = transport;
  } else if (network === "grpc") {
    outbound.transport = {
      type: "grpc",
      service_name: query.get("serviceName") || query.get("path") || ""
    };
  } else if (network === "http" || network === "h2") {
    const hostHeader = query.get("host") || sni || outbound.server;
    outbound.transport = {
      type: "http",
      host: [hostHeader],
      path: query.get("path") || "/"
    };
  } else if (network === "httpupgrade") {
    outbound.transport = {
      type: "httpupgrade",
      host: query.get("host") || sni || outbound.server,
      path: query.get("path") || "/"
    };
  } else if (network === "tcp" || network === "raw" || network === "") {
    const headerType = query.get("headerType");
    if (headerType && headerType !== "none") {
      warnings.push(`headerType="${headerType}" (raw TCP obfuscation) has no direct sing-box equivalent and was skipped.`);
    }
  } else {
    warnings.push(`Transport "${network}" isn't handled by this tool yet — generated as raw TCP.`);
  }

  return {
    ok: true,
    tag,
    name: remarkRaw || tag,
    host: outbound.server,
    port,
    security,
    network,
    outbound,
    warnings
  };
}

function sanitizeTag(name, index) {
  let t = name.trim().toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!t) t = `proxy-${index + 1}`;
  return t.slice(0, 40);
}

// ============================================================
// CONFIG BUILDER
// ============================================================
function buildConfig(entries, opts) {
  const okEntries = entries.filter(e => e.ok);
  const outbounds = okEntries.map(e => e.outbound);

  // dedupe tags
  const seen = new Map();
  outbounds.forEach(o => {
    const base = o.tag;
    let n = seen.get(base) || 0;
    if (n > 0) o.tag = `${base}-${n + 1}`;
    seen.set(base, n + 1);
  });

  const useSelector = outbounds.length > 1;
  const proxyTag = "proxy";

  // ---------- DNS ----------
  const remoteProvider = DOH_PROVIDERS[opts.remoteDns] ||
    { domain: opts.remoteDnsCustom || "cloudflare-dns.com", ips: [] };

  const hostsEntries = {};
  Object.values(DOH_PROVIDERS).forEach(p => { hostsEntries[p.domain] = p.ips; });
  if (opts.remoteDns === "custom" && opts.remoteDnsCustom) {
    hostsEntries[opts.remoteDnsCustom] = [];
  }

  const localDnsServer = opts.localDns === "custom" ? opts.localDnsCustom
    : opts.localDns === "system" ? null
    : opts.localDns;

  const dnsServers = [];

  if (localDnsServer) {
    dnsServers.push({ server: localDnsServer, type: "udp", tag: "local_local" });
  }
  dnsServers.push({
    server: remoteProvider.domain,
    domain_resolver: "hosts_dns",
    path: "/dns-query",
    type: "https",
    tag: "remote_dns",
    detour: proxyTag
  });
  if (localDnsServer) {
    dnsServers.push({ server: localDnsServer, domain_resolver: "local_local", type: "udp", tag: "direct_dns" });
  }
  dnsServers.push({
    predefined: hostsEntries,
    type: "hosts",
    tag: "hosts_dns"
  });

  const dnsRules = [
    { server: "hosts_dns", ip_accept_any: true },
    { server: "remote_dns", clash_mode: "Global" }
  ];
  if (localDnsServer) dnsRules.push({ server: "direct_dns", clash_mode: "Direct" });
  dnsRules.push({ action: "predefined", rcode: "NOERROR", query_type: [64, 65] });
  dnsRules.push({ server: localDnsServer ? "direct_dns" : "remote_dns", rule_set: ["geosite-private"] });

  const dns = {
    servers: dnsServers,
    rules: dnsRules,
    final: "remote_dns",
    independent_cache: true
  };

  // ---------- inbounds ----------
  const inbounds = [];
  if (opts.socksEnable) {
    inbounds.push({
      type: "mixed",
      tag: "socks",
      listen: "127.0.0.1",
      listen_port: opts.socksPort
    });
  }
  inbounds.push({
    type: "tun",
    tag: "tun",
    interface_name: opts.tunName,
    address: [opts.tunAddr],
    mtu: opts.tunMtu,
    auto_route: true,
    strict_route: opts.strictRoute,
    stack: opts.tunStack
  });

  // ---------- outbounds ----------
  const finalOutbounds = [...outbounds];
  if (useSelector) {
    finalOutbounds.unshift({
      type: "selector",
      tag: proxyTag,
      outbounds: outbounds.map(o => o.tag),
      default: outbounds[0].tag
    });
  } else if (outbounds.length === 1) {
    outbounds[0].tag = proxyTag;
  }
  finalOutbounds.push({ type: "direct", tag: "direct" });

  // ---------- route ----------
  const ruleSet = opts.ruleSetMode === "remote"
    ? {
        tag: "geosite-private",
        type: "remote",
        format: "binary",
        url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
        download_detour: "direct"
      }
    : {
        tag: "geosite-private",
        type: "local",
        format: "binary",
        path: opts.ruleSetPath
      };

  const routeRules = [
    { action: "sniff" },
    {
      type: "logical", mode: "or",
      rules: [{ port: [53] }, { protocol: ["dns"] }],
      action: "hijack-dns"
    },
    { outbound: "direct", clash_mode: "Direct" },
    { outbound: proxyTag, clash_mode: "Global" }
  ];
  if (opts.blockQuic) {
    routeRules.push({ network: ["udp"], port: [443], action: "reject" });
  }
  if (opts.blockIpv6) {
    routeRules.push({ ip_version: 6, action: "reject" });
  }
  routeRules.push({ outbound: "direct", ip_is_private: true });
  routeRules.push({ outbound: "direct", rule_set: ["geosite-private"] });
  routeRules.push({ outbound: proxyTag, port_range: ["0:65535"] });

  const route = {
    default_domain_resolver: { server: localDnsServer ? "direct_dns" : "remote_dns" },
    auto_detect_interface: true,
    rules: routeRules,
    rule_set: [ruleSet],
    final: proxyTag
  };

  // ---------- experimental ----------
  const experimental = {};
  if (opts.cacheFile) {
    experimental.cache_file = { enabled: true, path: "cache.db", store_fakeip: false };
  }
  if (opts.clashApi) {
    experimental.clash_api = { external_controller: `127.0.0.1:${opts.clashPort}` };
    if (opts.clashSecret) experimental.clash_api.secret = opts.clashSecret;
  }

  const config = {
    log: { level: opts.logLevel, timestamp: true },
    dns,
    inbounds,
    outbounds: finalOutbounds,
    endpoints: [],
    route,
    experimental
  };

  return config;
}

// ============================================================
// JSON SYNTAX HIGHLIGHT (lightweight, no deps)
// ============================================================
function highlightJson(json) {
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(
    /("(\\.|[^"\\])*"(\s*:)?|\b(true|false|null)\b|-?\d+\.?\d*(e[+-]?\d+)?)/gi,
    (match) => {
      if (/^"/.test(match)) {
        return /:$/.test(match)
          ? `<span class="tok-key">${match.slice(0, -1)}</span><span class="tok-punc">:</span>`
          : `<span class="tok-str">${match}</span>`;
      }
      if (/true|false/.test(match)) return `<span class="tok-bool">${match}</span>`;
      if (/null/.test(match)) return `<span class="tok-punc">${match}</span>`;
      return `<span class="tok-num">${match}</span>`;
    }
  );
}

// ============================================================
// UI WIRING
// ============================================================
const els = {
  input: document.getElementById("vlessInput"),
  parseBtn: document.getElementById("parseBtn"),
  sampleBtn: document.getElementById("sampleBtn"),
  parseStatus: document.getElementById("parseStatus"),
  linkResults: document.getElementById("linkResults"),
  output: document.getElementById("output"),
  outputCode: document.getElementById("outputCode"),
  copyBtn: document.getElementById("copyBtn"),
  downloadBtn: document.getElementById("downloadBtn"),
  warnings: document.getElementById("warnings"),
};

const optionEls = {
  remoteDns: document.getElementById("optRemoteDns"),
  remoteDnsCustom: document.getElementById("optRemoteDnsCustom"),
  localDns: document.getElementById("optLocalDns"),
  localDnsCustom: document.getElementById("optLocalDnsCustom"),
  blockQuic: document.getElementById("optBlockQuic"),
  blockIpv6: document.getElementById("optBlockIpv6"),
  tunName: document.getElementById("optTunName"),
  tunAddr: document.getElementById("optTunAddr"),
  tunMtu: document.getElementById("optTunMtu"),
  tunStack: document.getElementById("optTunStack"),
  strictRoute: document.getElementById("optStrictRoute"),
  socksEnable: document.getElementById("optSocksEnable"),
  socksPort: document.getElementById("optSocksPort"),
  clashApi: document.getElementById("optClashApi"),
  clashPort: document.getElementById("optClashPort"),
  clashSecret: document.getElementById("optClashSecret"),
  ruleSetMode: document.getElementById("optRuleSetMode"),
  ruleSetPath: document.getElementById("optRuleSetPath"),
  logLevel: document.getElementById("optLogLevel"),
  cacheFile: document.getElementById("optCacheFile"),
};

function readOptions() {
  return {
    remoteDns: optionEls.remoteDns.value,
    remoteDnsCustom: optionEls.remoteDnsCustom.value.trim(),
    localDns: optionEls.localDns.value,
    localDnsCustom: optionEls.localDnsCustom.value.trim(),
    blockQuic: optionEls.blockQuic.checked,
    blockIpv6: optionEls.blockIpv6.checked,
    tunName: optionEls.tunName.value.trim() || "singbox_tun",
    tunAddr: optionEls.tunAddr.value.trim() || "172.18.0.1/30",
    tunMtu: parseInt(optionEls.tunMtu.value, 10) || 9000,
    tunStack: optionEls.tunStack.value,
    strictRoute: optionEls.strictRoute.checked,
    socksEnable: optionEls.socksEnable.checked,
    socksPort: parseInt(optionEls.socksPort.value, 10) || 10808,
    clashApi: optionEls.clashApi.checked,
    clashPort: parseInt(optionEls.clashPort.value, 10) || 10814,
    clashSecret: optionEls.clashSecret.value.trim(),
    ruleSetMode: optionEls.ruleSetMode.value,
    ruleSetPath: optionEls.ruleSetPath.value.trim() || "C:\\sing-box\\srss\\geosite-private.srs",
    logLevel: optionEls.logLevel.value,
    cacheFile: optionEls.cacheFile.checked,
  };
}

// conditional field visibility
optionEls.remoteDns.addEventListener("change", () => {
  optionEls.remoteDnsCustom.hidden = optionEls.remoteDns.value !== "custom";
  regenerate();
});
optionEls.localDns.addEventListener("change", () => {
  optionEls.localDnsCustom.hidden = optionEls.localDns.value !== "custom";
  regenerate();
});
optionEls.ruleSetMode.addEventListener("change", () => {
  optionEls.ruleSetPath.hidden = optionEls.ruleSetMode.value !== "local";
  regenerate();
});
optionEls.socksEnable.addEventListener("change", () => {
  document.getElementById("socksPortRow").style.opacity = optionEls.socksEnable.checked ? "1" : "0.4";
  regenerate();
});
optionEls.clashApi.addEventListener("change", () => {
  const on = optionEls.clashApi.checked;
  document.getElementById("clashPortRow").style.opacity = on ? "1" : "0.4";
  document.getElementById("clashSecretRow").style.opacity = on ? "1" : "0.4";
  regenerate();
});

Object.values(optionEls).forEach(el => {
  if (!el) return;
  const evt = (el.tagName === "SELECT" || el.type === "checkbox") ? "change" : "input";
  el.addEventListener(evt, regenerate);
});

function setNodeState(node, state) {
  const el = document.querySelector(`.path-node[data-node="${node}"]`);
  if (el) el.dataset.state = state;
}
function setWireActive(n, active) {
  const el = document.querySelector(`.path-wire[data-wire="${n}"]`);
  if (el) el.dataset.active = active ? "1" : "0";
}

function updateSignalPath(entries, opts) {
  const okEntries = entries.filter(e => e.ok);
  const hasLink = okEntries.length > 0;
  const hasTls = okEntries.some(e => e.security === "tls" || e.security === "reality");

  setNodeState("link", hasLink ? "active" : "idle");
  setNodeState("tls", hasLink ? (hasTls ? "active" : "warn") : "idle");
  setNodeState("dns", hasLink ? "active" : "idle");
  setNodeState("route", hasLink ? "active" : "idle");
  setNodeState("out", hasLink ? "active" : "idle");

  setWireActive(1, hasLink);
  setWireActive(2, hasLink);
  setWireActive(3, hasLink);
  setWireActive(4, hasLink);
}

function renderLinkResults(entries) {
  els.linkResults.innerHTML = "";
  entries.forEach(e => {
    const card = document.createElement("div");
    if (!e.ok) {
      card.className = "link-card err";
      card.innerHTML = `
        <div class="link-card-main">
          <div class="link-card-name">unparsed link</div>
          <div class="link-card-detail">${escapeHtml(e.error)}</div>
        </div>
        <span class="link-card-badge badge-err">error</span>`;
    } else {
      card.className = "link-card";
      const detail = `${e.host}:${e.port} · ${e.security} · ${e.network}${e.warnings.length ? " · " + e.warnings.length + " warning(s)" : ""}`;
      card.innerHTML = `
        <div class="link-card-main">
          <div class="link-card-name">${escapeHtml(e.name)}</div>
          <div class="link-card-detail">${escapeHtml(detail)}</div>
        </div>
        <span class="link-card-badge ${e.warnings.length ? "badge-err" : "badge-ok"}">${e.warnings.length ? "check" : "ok"}</span>`;
    }
    els.linkResults.appendChild(card);
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function regenerate() {
  const raw = els.input.value;
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  if (lines.length === 0) {
    parsedOutbounds = [];
    updateSignalPath([], {});
    els.linkResults.innerHTML = "";
    return;
  }

  const entries = lines.map((line, i) => {
    if (!/^vless:\/\//i.test(line)) {
      return { ok: false, raw: line, error: "Doesn't start with vless://" };
    }
    try {
      return parseVlessLink(line, i);
    } catch (err) {
      return { ok: false, raw: line, error: err.message || "Failed to parse." };
    }
  });

  parsedOutbounds = entries;
  renderLinkResults(entries);
  updateSignalPath(entries, {});

  const okEntries = entries.filter(e => e.ok);
  const allWarnings = [];
  entries.forEach(e => {
    if (!e.ok) allWarnings.push(`Skipped a link: ${e.error}`);
    else e.warnings.forEach(w => allWarnings.push(`${e.name}: ${w}`));
  });

  if (okEntries.length === 0) {
    els.outputCode.textContent = "// no valid vless:// links yet";
    els.copyBtn.disabled = true;
    els.downloadBtn.disabled = true;
    renderWarnings(allWarnings);
    lastConfig = null;
    return;
  }

  const opts = readOptions();
  const config = buildConfig(entries, opts);
  lastConfig = config;

  const json = JSON.stringify(config, null, 2);
  els.outputCode.innerHTML = highlightJson(json);
  els.copyBtn.disabled = false;
  els.downloadBtn.disabled = false;
  renderWarnings(allWarnings);
}

function renderWarnings(list) {
  if (list.length === 0) {
    els.warnings.hidden = true;
    els.warnings.innerHTML = "";
    return;
  }
  els.warnings.hidden = false;
  els.warnings.innerHTML = `<strong>heads up</strong><ul>${list.map(w => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`;
}

els.parseBtn.addEventListener("click", () => {
  regenerate();
  const okCount = parsedOutbounds.filter(e => e.ok).length;
  const errCount = parsedOutbounds.filter(e => !e.ok).length;
  els.parseStatus.textContent = parsedOutbounds.length
    ? `${okCount} parsed${errCount ? `, ${errCount} failed` : ""}`
    : "";
  els.parseStatus.className = "parse-status " + (errCount ? "err" : (okCount ? "ok" : ""));
});

els.sampleBtn.addEventListener("click", () => {
  els.input.value = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@104.248.151.72:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=2K_uxUIqAyf-Nrw4pFVIwCbXXjx25dLj6FqYohHJ3yk&sid=4268081ad76bb1f0&sni=i.ytimg.com&fp=chrome#Sample-Reality-Server";
  regenerate();
});

els.copyBtn.addEventListener("click", async () => {
  if (!lastConfig) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastConfig, null, 2));
    const old = els.copyBtn.textContent;
    els.copyBtn.textContent = "copied";
    setTimeout(() => { els.copyBtn.textContent = old; }, 1400);
  } catch {
    els.copyBtn.textContent = "copy failed";
  }
});

els.downloadBtn.addEventListener("click", () => {
  if (!lastConfig) return;
  const blob = new Blob([JSON.stringify(lastConfig, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "config.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// initial state
optionEls.remoteDnsCustom.hidden = true;
optionEls.localDnsCustom.hidden = true;
optionEls.ruleSetPath.hidden = true;
