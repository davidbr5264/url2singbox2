# Config Forge — vless:// → sing-box (Windows &amp; Linux)

A static, client-side tool that turns one or more `vless://` share links into
a `config.json` for the [sing-box](https://sing-box.sagernet.org) core.
Nothing is uploaded anywhere — parsing and config generation run entirely in
the browser tab.

Its DNS and routing generation is ported directly from v2rayN's actual C#
source (`SingboxDnsService.cs`, `SingboxRoutingService.cs`,
`SingboxOutboundService.cs`, `CoreConfigSingboxService.cs` — read from
[github.com/2dust/v2rayN](https://github.com/2dust/v2rayN)), not
reverse-engineered from example exports. An earlier version of this project
did exist as a separate, reverse-engineered generator; it's been removed in
favor of this one, since building against the real source is strictly more
trustworthy.

**UI**: a dark terminal/phosphor theme — near-black background, warm amber
accent, all-monospace (JetBrains Mono) throughout, bracketed `[ ]`-style
status indicators in place of icons. Config generation is a guided
**5-step wizard** (Link → DNS → Security → Extras → Review), not one long
form — a numbered stepper at the top tracks progress, each step shows only
what's relevant to that decision, and the config regenerates live in the
background the whole time so it's ready the instant you reach Review. TUN
interface name, MTU, and log level aren't fields at all — fixed to
`singbox_tun`, `9000`, and `warn`, since essentially nobody needs to change
them.

Two separate pages, one per platform — [`index.html`](index.html) for
Windows, [`linux.html`](linux.html) for Linux — cross-linked to each other.
Each page locks its platform via a hidden, single-option `<select>`; there's
no in-page toggle to get wrong. Both share the same `app.js` and `style.css`.

## What makes this different from a naive sing-box generator

Each verified directly against the real v2rayN source, not guessed:

- **3-tier bootstrap DNS**: a small plain-IP bootstrap resolver (not a hosts
  table) resolves the remote/direct DNS servers' own hostnames by default,
  so any custom DoH provider works — not just a hardcoded few. The static
  hosts table is still used automatically as a faster override, but only
  for providers it actually contains.
- **No forced TLS fingerprint**: if the link doesn't specify `fp=`, no
  `utls` block is added at all — v2rayN never fakes one you didn't ask for.
  An explicit "force fingerprint" option is available as this tool's own
  addition on top, clearly labeled as such.
- **Transport-aware SNI fallback**: derives the TLS SNI from the transport's
  own Host header (ws/httpupgrade) rather than a single flat query-param
  fallback.
- **Real TUN self-loop protection**: the TUN interface's own address is
  rejected-and-dropped, matched per single address rather than by CIDR
  prefix — on Linux, sing-tun registers a derived address in that same
  prefix range with systemd-resolved as a DNS upstream, so a prefix-wide
  match would silently break system DNS.
- **Automatic self-process exclusion**: this client's own traffic is always
  excluded from the tunnel by process name (platform-correct binary name),
  with no manual path to configure — matching v2rayN's own behavior.
- **TLS record fragmentation** (anti-DPI SNI evasion) is exposed as a
  toggle — a real v2rayN TUN option. **ICMP routing policy**, **DNS
  strategy** (`domain_resolver.strategy`), and **forced TLS fingerprint**
  are implemented in `buildConfig()` and correctly wired end-to-end, but
  fixed to v2rayN's own defaults (ordinary routing rules for ICMP, no
  strategy preference, no forced fingerprint) rather than exposed as UI
  fields — they were rarely-touched advanced options, and the fields added
  more clutter than value for most people. `FIXED_ICMP_ROUTING`,
  `FIXED_DNS_STRATEGY`, `FIXED_FORCE_FINGERPRINT` in `app.js` if you want
  them back as fields, or just want to change the fixed value.
- Flow normalization (`xtls-rprx-vision-udp443` → `xtls-rprx-vision`),
  matching v2rayN's own normalization.

Not carried over from v2rayN's C# source: full protocol parity (VMess,
Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard — this tool is still
VLESS-only), FakeIP, raw custom-DNS passthrough, xhttp transport (v2rayN
itself doesn't generate it for sing-box yet either — its own
`FillOutboundTransport` switch has no `xhttp` case, so it silently falls
back to raw TCP; this tool warns instead of silently doing that), the new
Xray-only `encryption=` (post-quantum ML-KEM) VLESS field (sing-box has no
support for it yet, only Xray-core does, so v2rayN itself only wires it up
for its Xray/V2ray output path, not its sing-box one), certificate pinning
(`pcs=`/`vcn=`), and the full region-based geosite/geoip rule-splitting
logic. This tool's own additions on top (bypass domains, bypass
applications, the geosite-private toggle, settings persistence) are kept
since they're independently useful, and clearly distinguished in the UI
from what v2rayN itself does.

## Sync notes (checked against v2rayN @ master)

Re-verified directly against the current `SingboxDnsService.cs`,
`SingboxRoutingService.cs`, `SingboxOutboundService.cs`, and `Global.cs` on
2dust/v2rayN's `master` branch. The core DNS/routing architecture this tool
was originally built from is unchanged (bootstrap → hosts-override →
remote/direct DNS, `default_domain_resolver` pointed at `direct_dns`,
per-address TUN self-loop protection, ICMP routing policy, the predefined
hosts table). A few things had drifted or were missing, now fixed:

- **Reality no longer honors `allowInsecure`.** v2rayN's `FillOutboundTls`
  unconditionally forces `tls.insecure = false` for Reality regardless of
  the link's `allowInsecure` value, since Reality authenticates the server
  through its public key rather than the certificate chain — the flag was
  meaningless there. This tool now does the same and warns if a link
  asked for it anyway.
- **ECH (Encrypted Client Hello) is now supported.** An `ech=` query
  param with an inline base64 config is wrapped into `tls.ech`, matching
  v2rayN's `ParseEchParam()`. The alternate DNS-record-reference form
  (`ech=domain+base64...`) isn't handled — it needs a second DNS lookup
  at request time this tool has no way to model statically — and produces
  a warning instead.
- **`headerType=http` on raw TCP now generates sing-box's `http`
  transport** (reusing the link's `host`/`path`) instead of being dropped
  with a warning, matching v2rayN's own raw-transport handling.
- **WebSocket early data now also reads `eh=`** (a custom early-data
  header name), not just `ed=` (the byte count). v2rayN's own regex
  strips `ed=` back out of the path but, as read from its current source,
  never strips a matched `eh=` back out — left in the literal path sent
  to the server. That reads like an upstream oversight rather than
  intentional, so this tool strips both.
- **A proxy server's own hostname is now protected in DNS routing too.**
  v2rayN's `ProtectDomainList` mechanism adds an explicit high-priority
  DNS rule sending each node's own domain to `direct_dns` — on top of
  `default_domain_resolver` already pointing outbound dialing at
  `direct_dns` — as defense-in-depth against a literal DNS query for that
  same name getting routed through `remote_dns` (and thus through the very
  outbound it's trying to help resolve). Added here for the same reason.
- **New optional "Block AAAA DNS answers" toggle** (off by default, same
  as v2rayN's own `BlockAAAAQuery`), for forcing IPv4-only at the DNS
  layer rather than only rejecting IPv6 once it reaches the route table.
- **Self-process exclusion is now a documented simplification, not a
  literal port.** v2rayN generalized this into a "protected core list"
  keyed by each managed core's absolute binary path (for excluding
  *other* proxy cores it runs from looping through the TUN it drives) —
  it no longer hardcodes `sing-box.exe` by name. That needs a live
  installation to enumerate, which a share-link-only tool has no access
  to, so this tool keeps the simpler always-applicable case: excluding
  sing-box's own process from its own TUN by name.

Confirmed unchanged and still accurate: the `V2RAYN_PREDEFINED_HOSTS`
table (byte-for-byte against `Global.PredefinedHosts`), the DNS preset
address lists, and the flow/vision normalization.

## What it builds

- **TUN inbound** (`strict_route`, `gvisor` stack by default) + optional local
  SOCKS/HTTP mixed inbound (off by default — TUN-only unless you turn it on).
- **DNS over HTTPS** for remote resolution, tunneled through your own proxy
  outbound (`detour: proxy`). Local/direct resolution defaults to **System
  default** — v2rayN's actual default (119.29.29.29, DNSPod) is a
  China-anycast address unreachable for many users outside China, so this
  tool defaults to something that works everywhere instead, with DNSPod
  still available as an option.
- **Fail-closed routing**: `route.final` is your proxy outbound. Private IPs
  go direct via the built-in `ip_is_private` match — no file or download
  needed. The `geosite-private` rule-set (off by default) adds direct
  routing for known local-network *hostnames* on top of that.
- **VLESS parsing**: `security` (none/tls/reality), `flow`
  (xtls-rprx-vision), transports (`tcp`, `ws` incl. early-data, `grpc`,
  `http`, `httpupgrade`), ALPN, Reality `pbk`/`sid`. Multiple links generate
  a `selector` outbound so you can flip between servers.
- **Bypass domains**: a plain list of domains that should skip the proxy —
  applied to both DNS resolution and routing. One per line; a bare domain
  matches itself and its subdomains, a leading `.` matches subdomains only,
  and `keyword:`/`regex:` prefixes give substring/regex matching.
- **Bypass applications**: a list of executables (`steam.exe` on Windows,
  `steam` on Linux — or a full path, only the file name is used) whose
  traffic is sent direct via `process_name` matching, for apps that break
  under a VPN/TUN (games with anti-cheat, LAN-discovery tools, etc).
- **Settings persistence**: every option field auto-saves to your browser's
  `localStorage` and restores on your next visit. Windows and Linux pages
  share the same origin/storage, but the platform-shaped fields (rule-set
  path, bypass applications) are stored as fully separate profiles per
  page — visiting one page never shows, overwrites, or resets the other's
  stashed values. The pasted `vless://` link(s) are deliberately **not**
  persisted, since they carry UUIDs/keys and re-pasting one link is trivial
  compared to re-entering everything else. "Reset to defaults" only resets
  this page's own platform profile, not the other page's.

## Run it locally

No build step — it's plain HTML/CSS/JS.

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## Deploy to Cloudflare Pages

**Option A — dashboard, no git required**
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Upload assets**.
2. Drag in this folder's contents (`index.html`, `linux.html`, `style.css`,
   `app.js`, `_headers`).
3. Deploy. You'll get a `*.pages.dev` URL immediately.

**Option B — git-connected (auto-deploys on push)**
1. Push this folder to a GitHub/GitLab repo.
2. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git** → pick the repo.
3. Build settings: **Framework preset: None**, **Build command: (empty)**,
   **Build output directory: /**.
4. Deploy.

**Option C — Wrangler CLI**
```bash
npm install -g wrangler
wrangler pages deploy . --project-name=config-forge
```

The `_headers` file ships a Content-Security-Policy that blocks all outbound
`connect-src` — a safety net confirming the page can't phone home even by
accident, since it never needs to. **Important if you're editing this
project**: the CSP is also `script-src 'self'` with no `'unsafe-inline'` —
inline `<script>` blocks in the HTML are silently blocked by the browser
once this actually deploys behind `_headers` (this bit us once already: the
wizard's step-navigation logic originally lived in an inline `<script>` and
the Next/Back buttons simply didn't work in production, despite working
fine in any environment that doesn't enforce the CSP). All JavaScript needs
to live in `app.js` or another same-origin `.js` file, never inline.

## Extending

- `app.js` → `V2RAYN_DNS_PRESETS` / `V2RAYN_PREDEFINED_HOSTS` to add resolvers.
- `parseVlessLink()` to add transports (currently unhandled: `kcp`, `quic` as
  a VLESS transport — rare in the wild).
- `buildConfig()` is the single source of truth for the output shape; it's
  intentionally kept framework-free so it's easy to port to a CLI/Node script
  later if you want a non-browser version.
- Windows and Linux are separate pages sharing one `app.js`. Each page locks
  its platform via a hidden, single-option `<select id="optPlatform">` —
  `app.js` itself still supports live switching internally
  (`PLATFORM_DEFAULTS`, `ISOLATED_FIELDS`, `platformProfiles`,
  `switchPlatformProfile()`), left in place in case you want to reintroduce
  an in-page toggle later, but no current page exposes it in the UI. Adding
  a third platform means: a new `PLATFORM_DEFAULTS` entry, a
  `parseBypassApps()` validation branch, and a new HTML page cloned from one
  of the existing two with its defaults swapped. macOS would be the natural
  next one — process-name conventions are closer to Linux's (extension-less)
  than Windows's, and a plausible rule-set path would be
  `/usr/local/etc/sing-box/` or `/opt/homebrew/etc/sing-box/` depending on
  install method.

## Running on Linux

sing-box's TUN mode needs elevated privileges on Linux, same as on Windows:

- **Quick/manual runs**: `sudo sing-box run -c config.json`.
- **systemd service (recommended for anything long-running)**: grant
  capabilities instead of running fully as root —
  `CAP_NET_ADMIN` and `CAP_NET_RAW` for the TUN interface and routing, plus
  `CAP_SYS_PTRACE` if you're using the bypass-applications feature (process
  matching reads `/proc`). The official sing-box systemd service files
  already set these; see
  [sing-box's package-manager install docs](https://sing-box.sagernet.org/installation/package-manager/)
  if you're not using a packaged install.
- The default local rule-set path (`/etc/sing-box/geosite-private.srs`)
  matches where the official `.deb`/`.rpm` packages expect config files to
  live — adjust it if your install uses a different layout.

## Verify before trusting it

```powershell
sing-box.exe check -c config.json
```
