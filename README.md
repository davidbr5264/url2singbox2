# Config Forge — vless:// → sing-box (Windows)

A static, client-side tool that turns one or more `vless://` share links into a
hardened `config.json` for the [sing-box](https://sing-box.sagernet.org) core
on Windows. Nothing is uploaded anywhere — parsing and config generation run
entirely in the browser tab.

## What it builds

- **TUN inbound** (`strict_route`, `gvisor` stack by default) + optional local
  SOCKS/HTTP mixed inbound.
- **DNS over HTTPS** for remote resolution, tunneled through your own proxy
  outbound (`detour: proxy`), with a `hosts`-type bootstrap so the resolver's
  own hostname never leaks over plaintext DNS. Local/direct resolution
  defaults to the OS's own resolver (sing-box's `local` DNS server type) —
  matching what your browser gets with no proxy at all — or a specific
  IP if you set one.
- **Fail-closed routing**: `route.final` is your proxy outbound. Only private
  IPs and the `geosite-private` rule-set go direct — everything else is
  tunneled or dropped, never silently sent out in the clear. `geosite-private`
  defaults to a local file at `C:\sing-box\geosite-private.srs`; switch the
  dropdown to auto-download if you'd rather not manage that file yourself.
- **Leak-path closers** (toggleable): reject UDP/443 (QUIC) so HTTP/3 can't
  route around a TCP-only path, and reject IPv6 since the TUN address here is
  IPv4-only.
- **VLESS parsing**: `security` (none/tls/reality), `flow` (xtls-rprx-vision),
  transports (`tcp`, `ws` incl. early-data, `grpc`, `http`, `httpupgrade`),
  uTLS fingerprint, ALPN, Reality `pbk`/`sid`. Multiple links generate a
  `selector` outbound so you can flip between servers.
- **Bypass domains**: a plain list of domains that should skip the proxy —
  applied to both DNS resolution and routing, evaluated before
  `geosite-private`. One per line; a bare domain matches itself and its
  subdomains, a leading `.` matches subdomains only, and `keyword:`/`regex:`
  prefixes give substring/regex matching.
- **Bypass applications**: a list of Windows executables (`steam.exe`, or a
  full path — only the file name is used) whose traffic is sent direct via
  `process_name` matching, for apps that break under a VPN/TUN (games with
  anti-cheat, LAN-discovery tools, etc). Applied to both DNS and routing,
  independent of the bypass-domain rule.

## Run it locally

No build step — it's plain HTML/CSS/JS.

```bash
cd vless2singbox
python3 -m http.server 8080
# open http://localhost:8080
```

## Deploy to Cloudflare Pages

**Option A — dashboard, no git required**
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Upload assets**.
2. Drag in this folder's contents (`index.html`, `style.css`, `app.js`,
   `_headers`).
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
accident, since it never needs to.

## sing-box version notes

Checked against sing-box stable (1.13.x) and the 1.14 beta docs. The DNS/route
schema this tool generates (typed DNS servers, `domain_resolver`, rule
`action`s, unified TUN `address`) is already the current format — nothing
here is on the legacy path sing-box is removing in 1.14.0. Two things came
out of that check and are now handled automatically:

- **IPv6 "reject" now actually captures the traffic first.** sing-box only
  installs OS routes into the TUN for address families present on the TUN
  interface. With an IPv4-only TUN address, IPv6 traffic was never routed
  into sing-box at all, so a route-rule reject for it never fired — it just
  leaked out the physical adapter unfiltered. Turning "Reject IPv6" on now
  also adds an IPv6 TUN address so that traffic is actually captured, then
  dropped. (v2rayN's July 2026 release added the same IPv4/IPv6 TUN address
  handling for the same reason.)
- **The proxy outbound pins its own DNS resolver.** An outbound resolving
  its own server hostname bypasses `dns.rules` and uses
  `route.default_domain_resolver` (or a per-outbound override) directly —
  confirmed in sing-box's migration docs. If that ever resolved through the
  DoH server tunneled over the proxy itself, a **domain-based** VLESS server
  would deadlock resolving itself through itself. Each outbound now sets its
  own `domain_resolver` to the direct/local resolver explicitly.

## Extending

- `app.js` → `DOH_PROVIDERS` to add resolvers.
- `parseVlessLink()` to add transports (currently unhandled: `kcp`, `quic` as
  a VLESS transport — rare in the wild).
- `buildConfig()` is the single source of truth for the output shape; it's
  intentionally kept framework-free so it's easy to port to a CLI/Node script
  later if you want a non-browser version.
- Currently Windows-only by design (Windows paths, `.exe` process-name hooks
  are not included since this tool builds a fresh config rather than a
  system-wide TUN passthrough list). A macOS/Linux variant would mainly need
  different `cache_file.path` conventions and no drive-letter paths for local
  rule-sets.

## Verify before trusting it

```powershell
sing-box.exe check -c config.json
```

## sing-box compatibility notes

Checked against sing-box's official changelog (current stable: 1.13.x; 1.14
in beta) as of August 2026:

- The generated config uses the current unified `address` field for the TUN
  inbound, not the legacy split `inet4_address`/`inet6_address` fields
  (removed in 1.12.0) — no action needed.
- Adds the official `$schema` field (introduced 1.14.0-beta.2) pointing at
  `https://sing-box.sagernet.org/schema.json`, so editors like VS Code get
  autocomplete/validation when you open `config.json`. This is metadata only
  and has no effect on the running client.
- `dns.independent_cache: true` is kept deliberately even though it's
  deprecated as of 1.14.0-alpha.11. On 1.14+, the DNS cache always keys by
  transport regardless of this flag, but on the current 1.13.x stable branch
  it's still the explicit opt-in for that safer per-resolver cache isolation
  — removing it would silently weaken caching behavior for anyone not yet on
  1.14. It'll need to come out once 1.16.0 removes the field outright.
- sing-box 1.14 (alpha) is adding automatic TUN-level DNS hijacking
  (`dns_mode`/`dns_address`), which could eventually simplify the manual
  hijack-dns route rule here — not yet in a stable release, so no change made.
