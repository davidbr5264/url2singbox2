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
  own hostname never leaks over plaintext DNS. Local/direct resolution stays
  on plain UDP for LAN and split-horizon domains.
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
