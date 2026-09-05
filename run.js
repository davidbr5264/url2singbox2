// ============================================================
// Config Forge — regression tests
//
// Run with: node test/run.js
//
// Covers the parsing/config-building edge cases that have come up across
// this project's history — each one below was a real bug, a real v2rayN
// parity fix, or a real ambiguity that got resolved a specific way.
// This exists so the next change doesn't have to re-derive them by hand.
//
// No dependencies beyond Node's built-in `assert` — app.js itself stays
// framework-free, and so does this.
// ============================================================

const assert = require("node:assert/strict");
const path = require("node:path");

const {
  parseVlessLink,
  buildConfig,
  parseDnsAddress,
  parseBypassDomains,
  parseBypassApps,
  isValidCidr,
} = require(path.join(__dirname, "..", "app.js"));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok  - ${name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL  - ${name}`);
    console.log(`        ${err.message}`);
  }
}

function baseOpts(overrides) {
  return Object.assign({
    bootstrapDns: "system", directDns: "system",
    remoteDns: "https://cloudflare-dns.com/dns-query",
    tunAddr: "172.18.0.1/30", tunStack: "gvisor", strictRoute: true,
    platform: "windows", icmpRouting: "rule", logLevel: "warn",
    tunName: "singbox_tun", tunMtu: 9000, socksPort: 10808, clashPort: 10814,
    ruleSetMode: "local", ruleSetPath: "C:\\sing-box\\geosite-private.srs",
    bypass: { domain_suffix: [], domain_keyword: [], domain_regex: [] },
    bypassApps: { processNames: [] },
  }, overrides);
}

// ---------------------------------------------------------------
// VLESS link parsing
// ---------------------------------------------------------------

test("parses a basic reality+vision link", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@104.248.151.72:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=2K_uxUIqAyf-Nrw4pFVIwCbXXjx25dLj6FqYohHJ3yk&sid=4268081ad76bb1f0&sni=i.ytimg.com&fp=chrome#Sample";
  const e = parseVlessLink(link, 0);
  assert.equal(e.ok, true);
  assert.equal(e.outbound.server, "104.248.151.72");
  assert.equal(e.outbound.flow, "xtls-rprx-vision");
  assert.equal(e.outbound.tls.reality.public_key, "2K_uxUIqAyf-Nrw4pFVIwCbXXjx25dLj6FqYohHJ3yk");
});

test("Reality always forces tls.insecure=false, even if allowInsecure=1", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=reality&pbk=abc&allowInsecure=1#T";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.tls.insecure, false);
  assert.ok(e.warnings.some(w => w.includes("allowInsecure=1 is ignored")));
});

test("IPv6 bracket host parses correctly", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@[2001:db8::1]:443?security=tls&sni=example.com#IPv6";
  const e = parseVlessLink(link, 0);
  assert.equal(e.ok, true);
  assert.equal(e.outbound.server, "2001:db8::1", "server field must not contain brackets");
  assert.equal(e.isIpv6Host, true);
  assert.equal(e.host, "2001:db8::1");
});

test("IPv4 / domain hosts are unaffected by the IPv6 fix", () => {
  const e1 = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@1.2.3.4:443?security=none#A", 0);
  assert.equal(e1.ok, true);
  assert.equal(e1.outbound.server, "1.2.3.4");
  assert.equal(e1.isIpv6Host, false);

  const e2 = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@my.proxy.example:443?security=none#B", 0);
  assert.equal(e2.ok, true);
  assert.equal(e2.outbound.server, "my.proxy.example");
  assert.equal(e2.isIpv6Host, false);
});

test("ECH inline base64 config wraps into tls.ech", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&sni=example.com&ech=AEX%2BDQBBAAAgACC#Ech";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.tls.ech.enabled, true);
  assert.ok(e.outbound.tls.ech.config[0].includes("BEGIN ECH CONFIGS"));
  assert.ok(e.outbound.tls.ech.config[0].includes("AEX+DQBBAAAgACC"));
});

test("unescaped '+' and '=' padding in a base64 query value survive intact (regression: form-encoding + vs. space)", () => {
  // Many link generators don't bother percent-encoding "+"/"=" since
  // neither needs escaping in a general URI — but URLSearchParams alone
  // treats a literal "+" as a form-encoded space, which would silently
  // corrupt a raw (unescaped) base64 ECH config containing one.
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&sni=example.com&ech=AAj+DQAEAAAAAA==#RawPlus";
  const e = parseVlessLink(link, 0);
  assert.ok(e.outbound.tls.ech.config[0].includes("AAj+DQAEAAAAAA=="), `got: ${e.outbound.tls.ech.config[0]}`);
});

test("ECH with a DNS-reference (://) form is not silently mishandled", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&sni=example.com&ech=https%3A%2F%2Fexample.com%2Fech#Ech2";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.tls.ech, undefined);
  assert.ok(e.warnings.some(w => w.includes("DNS-lookup reference form")));
});

test("headerType=http on raw TCP generates sing-box's http transport", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@1.2.3.4:80?type=tcp&headerType=http&host=cdn.example.com&path=%2Fapi#HttpObfs";
  const e = parseVlessLink(link, 0);
  assert.deepEqual(e.outbound.transport, { type: "http", host: ["cdn.example.com"], path: "/api" });
});

test("headerType=none on raw TCP produces no transport and no warning", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@1.2.3.4:80?type=tcp&headerType=none#Plain";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.transport, undefined);
  assert.equal(e.warnings.length, 0);
});

test("ws transport reads both ed= and eh=, and strips both from path", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&type=ws&host=example.com&sni=example.com&path=%2Fpath%3Fed%3D2560%26eh%3DX-My-Header#WsEd";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.transport.type, "ws");
  assert.equal(e.outbound.transport.path, "/path");
  assert.equal(e.outbound.transport.max_early_data, 2560);
  assert.equal(e.outbound.transport.early_data_header_name, "X-My-Header");
});

test("ws eh= header name is not double-decoded (regression: v2rayN BaseFmt.cs fix)", () => {
  // %2541 in the raw URL decodes ONCE (via URLSearchParams) to a literal
  // "%41" in the path; a second decodeURIComponent pass would corrupt it
  // into "A". The header name must come out as the once-decoded value.
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&type=ws&host=example.com&sni=example.com&path=%2Fws%3Feh%3DX-Header%2541#DoubleDecode";
  const e = parseVlessLink(link, 0);
  assert.equal(e.outbound.transport.early_data_header_name, "X-Header%41");
});

test("grpc transport reads serviceName", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&type=grpc&serviceName=mygrpc&sni=example.com#Grpc";
  const e = parseVlessLink(link, 0);
  assert.deepEqual(e.outbound.transport, { type: "grpc", service_name: "mygrpc" });
});

test("httpupgrade transport reads host/path", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=tls&type=httpupgrade&host=example.com&path=%2Fup&sni=example.com#Hu";
  const e = parseVlessLink(link, 0);
  assert.deepEqual(e.outbound.transport, { type: "httpupgrade", host: "example.com", path: "/up" });
});

test("malformed link is reported, not thrown", () => {
  const e = parseVlessLink("vless://not-a-valid-link", 0);
  assert.equal(e.ok, false);
  assert.ok(e.error.length > 0);
});

test("Reality without pbk warns that the outbound will fail to connect", () => {
  const link = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=reality#NoPbk";
  const e = parseVlessLink(link, 0);
  assert.ok(e.warnings.some(w => w.includes("no pbk")));
});

// ---------------------------------------------------------------
// buildConfig — DNS / route rule shape
// ---------------------------------------------------------------

test("tls_record_fragment is never emitted (hardcoded off)", () => {
  const e = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=none#A", 0);
  const cfg = buildConfig([e], baseOpts());
  assert.ok(!cfg.route.rules.some(r => "tls_record_fragment" in r));
});

test("dns.independent_cache is not emitted (deprecated in sing-box 1.14.0, removed in 1.16.0)", () => {
  const e = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=none#A", 0);
  const cfg = buildConfig([e], baseOpts());
  assert.ok(!("independent_cache" in cfg.dns));
});

test("hosts_dns catch-all rule uses preferred_by, not the older ip_accept_any", () => {
  const e = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=none#A", 0);
  const cfg = buildConfig([e], baseOpts());
  const hostsRule = cfg.dns.rules.find(r => r.server === "hosts_dns");
  assert.ok(hostsRule, "expected a hosts_dns dns rule");
  assert.equal(hostsRule.preferred_by, "hosts_dns");
  assert.ok(!("ip_accept_any" in hostsRule));
});

test("protect-domain DNS rule is added for a domain host, not for an IP host", () => {
  const domainEntry = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@my.proxy.example:443?security=none#A", 0);
  const ipEntry = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@1.2.3.4:443?security=none#B", 1);

  const cfgDomain = buildConfig([domainEntry], baseOpts());
  const protectRuleDomain = cfgDomain.dns.rules.find(r => r.server === "direct_dns" && Array.isArray(r.domain));
  assert.ok(protectRuleDomain, "expected a direct_dns protect-domain rule for a domain host");
  assert.ok(protectRuleDomain.domain.includes("my.proxy.example"));

  const cfgIp = buildConfig([ipEntry], baseOpts());
  const protectRuleIp = cfgIp.dns.rules.find(r => r.server === "direct_dns" && Array.isArray(r.domain));
  assert.equal(protectRuleIp, undefined, "an IP host should not produce a protect-domain rule");
});

test("blockAaaaQuery option adds a query_type:[28] DNS rule only when enabled", () => {
  const e = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=none#A", 0);

  const cfgOff = buildConfig([e], baseOpts());
  assert.ok(!cfgOff.dns.rules.some(r => Array.isArray(r.query_type) && r.query_type.includes(28)));

  const cfgOn = buildConfig([e], baseOpts({ blockAaaaQuery: true }));
  assert.ok(cfgOn.dns.rules.some(r => Array.isArray(r.query_type) && r.query_type.includes(28)));
});

test("TUN self-loop reject rule matches the TUN address as a single prefix", () => {
  const e = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@example.com:443?security=none#A", 0);
  const cfg = buildConfig([e], baseOpts({ tunAddr: "172.18.0.1/30" }));
  const rejectRule = cfg.route.rules.find(r => r.action === "reject" && r.method === "drop");
  assert.deepEqual(rejectRule.ip_cidr, ["172.18.0.1/32"]);
});

test("single link is retagged to the bare 'proxy' outbound; multiple links get a selector", () => {
  const e1 = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@a.example:443?security=none#A", 0);
  const cfgSingle = buildConfig([e1], baseOpts());
  assert.ok(cfgSingle.outbounds.some(o => o.tag === "proxy" && o.type === "vless"));

  const e2 = parseVlessLink("vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@b.example:443?security=none#B", 1);
  const cfgMulti = buildConfig([e1, e2], baseOpts());
  const selector = cfgMulti.outbounds.find(o => o.type === "selector");
  assert.ok(selector, "expected a selector outbound for multiple links");
  assert.equal(selector.outbounds.length, 2);
});

// ---------------------------------------------------------------
// DNS address parsing
// ---------------------------------------------------------------

test("parseDnsAddress: local/localhost", () => {
  assert.deepEqual(parseDnsAddress("local"), { type: "local" });
  assert.deepEqual(parseDnsAddress("localhost"), { type: "local" });
});

test("parseDnsAddress: bare IP defaults to udp", () => {
  assert.deepEqual(parseDnsAddress("1.1.1.1"), { type: "udp", server: "1.1.1.1" });
});

test("parseDnsAddress: https URL with path", () => {
  const r = parseDnsAddress("https://dns.google/dns-query");
  assert.equal(r.type, "https");
  assert.equal(r.server, "dns.google");
  assert.equal(r.path, "/dns-query");
});

test("parseDnsAddress: dhcp scheme", () => {
  assert.deepEqual(parseDnsAddress("dhcp://auto"), { type: "dhcp" });
});

// ---------------------------------------------------------------
// Bypass domain / app parsing
// ---------------------------------------------------------------

test("bypass domains: bare domain, subdomain-only, keyword, regex", () => {
  const r = parseBypassDomains("example.com\n.internal.corp.example\n*.wild.example\nkeyword:analytics\nregex:^ads\\.");
  assert.ok(r.domain_suffix.includes("example.com"));
  assert.ok(r.domain_suffix.includes(".internal.corp.example"));
  assert.ok(r.domain_suffix.includes(".wild.example"));
  assert.ok(r.domain_keyword.includes("analytics"));
  assert.ok(r.domain_regex.includes("^ads\\."));
});

test("bypass keyword is a raw substring, not run through hostname cleanup (regression)", () => {
  // A keyword isn't a hostname — it must not get port/path/query stripping
  // applied to it just because it happens to contain ":digits", "/", or "?".
  const r = parseBypassDomains("keyword:node:1\nkeyword:video?\nkeyword:a/b");
  assert.ok(r.domain_keyword.includes("node:1"), `expected "node:1", got: ${JSON.stringify(r.domain_keyword)}`);
  assert.ok(r.domain_keyword.includes("video?"), `expected "video?", got: ${JSON.stringify(r.domain_keyword)}`);
  assert.ok(r.domain_keyword.includes("a/b"), `expected "a/b", got: ${JSON.stringify(r.domain_keyword)}`);
});

test("bypass domains: invalid regex is skipped with a warning, not thrown", () => {
  const r = parseBypassDomains("regex:(unterminated");
  assert.equal(r.domain_regex.length, 0);
  assert.ok(r.warnings.some(w => w.includes("valid regular expression")));
});

test("bypass apps: Windows warns on missing .exe, Linux warns on 15+ char names", () => {
  const win = parseBypassApps("steam", "windows");
  assert.ok(win.warnings.some(w => w.includes(".exe")));

  const lin = parseBypassApps("a-very-long-process-name", "linux");
  assert.ok(lin.warnings.some(w => w.includes("15 characters")));
});

// ---------------------------------------------------------------
// CIDR validation
// ---------------------------------------------------------------

test("isValidCidr accepts sane IPv4/IPv6 CIDRs and rejects garbage", () => {
  assert.equal(isValidCidr("172.18.0.1/30"), true);
  assert.equal(isValidCidr("2001:db8::1/64"), true);
  assert.equal(isValidCidr("not-a-cidr"), false);
  assert.equal(isValidCidr("172.18.0.1"), false, "missing prefix length");
  assert.equal(isValidCidr("999.1.1.1/30"), false, "octet out of range");
  assert.equal(isValidCidr("172.18.0.1/99"), false, "prefix out of range");
});

// ---------------------------------------------------------------

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
