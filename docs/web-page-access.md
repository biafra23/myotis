# Web page access — which browser origins may use the JSON-RPC listener

Issue #502. The embedded JSON-RPC server (`:jsonrpc-server`, run by both engines
on `127.0.0.1:<port>` per network) used to answer **every** web page on the
device: the Ktor CORS plugin was installed with `anyHost()`. Any page open in a
browser or in-app WebView could `fetch("http://localhost:8545", …)`, learn that
Myotis runs and which networks (the ports, `eth_chainId`, `web3_clientVersion`),
and read balance, nonce, code, storage and `eth_call` results for any address it
already knew — with no wallet prompt. It could not spend (`eth_sendRawTransaction`
needs bytes the wallet signed), so this was fingerprinting and privacy, not theft.

Now the operator decides, per device, which pages may use the node. The policy
is one for all networks (the user trusts a *site*, not a site-per-chain).

## The three modes

| Mode | Meaning | Default |
|---|---|---|
| **Off** | No web page may use the node. | |
| **Specific sites** | Only the listed origins, matched exactly (scheme + host + port). | **yes, with no sites** |
| **All sites** | Every page — the pre-#502 behaviour. The app shows a warning. | |

The default is *Specific sites with none*: every web page is refused until the
user allows it. Native wallet apps are unaffected in every mode (below). A
browser-extension wallet (MetaMask in Chrome or Firefox) counts as a site: it
sends its extension origin and needs allowing once — the app shows it refused
with an **Allow** button, and the Chrome MetaMask id is labelled by name.

## How the gate tells a web page from a native client

Implemented in `io.myotis.jsonrpc.WebAccess`, run ahead of routing on every
path, so a refused request never reaches `RpcRouter.handle`:

- **`Origin` present → a web page.** Browsers send `Origin` on every fetch/XHR
  POST and on every cross-origin GET; page script cannot set, change or remove
  it (a forbidden request header). Served only if the policy admits that exact
  origin, with `Access-Control-Allow-Origin: <origin>` and `Vary: Origin`; a
  CORS preflight (`OPTIONS`) for an allowed origin is answered here with
  `POST, GET, OPTIONS` / `Content-Type` / a 300 s max-age. Otherwise `403`.
  This also closes the "simple request" hole a CORS grant alone leaves open: a
  cross-origin `text/plain` POST sends no preflight, but it does send `Origin`.
- **No `Origin`, but `Sec-Fetch-Site` other than `none` → a no-cors probe**
  (`<img>`, `<script>`, `fetch(…, {mode:"no-cors"})`). Refused `403` — unless
  `Sec-Fetch-Mode: navigate`: a top-level navigation (a link clicked on some
  page, a bookmark) shows the user the response and leaks nothing to the page
  that linked it, and a navigation that could carry a body (a form POST) sends
  an `Origin` and is judged by that rule instead. Browsers send Fetch Metadata
  to `localhost`/`127.0.0.1` (potentially trustworthy origins). A URL typed
  into the address bar carries `Sec-Fetch-Site: none` and is served
  (`GET /health` → `ok`).
- **Neither → a native client** (MetaMask Mobile, the other Android wallets
  tested, curl, `tools/mm-replay`). Served exactly as before, no CORS headers.
- **`Host` must name the listener** in every mode: `localhost`, `127.0.0.1`,
  `[::1]` (any port) or the bound address — geth's `--http.vhosts`. A
  DNS-rebinding page reaches the node under the attacker's hostname, which is
  what this catches. A request with no `Host` at all (HTTP/1.0) passes. A Host
  refusal is logged but *not* recorded in the recent list: it is not an origin
  "Allow" could admit.

Origins are reduced to one canonical form on both sides (`WebOrigins.normalize`
in the engine, `WebAccessUi.normalize` in `:ui` — keep them in step; both are
pinned by tests): scheme and host lowercased, a scheme's default port dropped, a
trailing slash tolerated, a bare domain means `https://<domain>` (type `http://`
for a local dev server). A path, query, userinfo or wildcard is refused — no
`*.example.org`: on a platform that hosts user content on subdomains it would
admit anyone who can publish there. The opaque origin `null` (file:, data:,
sandboxed frames) never matches a list entry; only *All sites* admits it.
Hosts are ASCII only: a browser serializes an international name in its
`xn--` (punycode) form, so a typed `münchen.example` could never match and is
refused by the add field rather than stored inert — allow it as the `xn--`
form the recent list shows. A malformed `Origin` (no browser sends one) is
refused but never listed, so the list never offers an Allow it could not keep.

## How refusals look, and what a browser shows the user

A refused request gets `403` with a short static text body. The page's own
script never sees the reason: a blocked cross-origin fetch is a plain network
error to JavaScript, the browser withholds the response, and only the developer
console says "blocked by CORS policy". So the *user* learns nothing from the
browser, which is why the apps surface it themselves:

- **Status tab banner** (both modes): "A web page was refused" with the origin,
  **Allow** (adds it to the list and applies at once, so the page's next
  request succeeds — dApps retry/poll, and the preflight cache is short) and
  **Dismiss**. Not shown under *Off*: there a refusal is the setting working.
- **Android notification** (its own channel, "Web page access") with an
  **Allow** action, once per origin per run; the running service polls the
  listeners' recent lists every 5 s. The action lands on the service as a
  start command (`ACTION_ALLOW_WEB_ORIGIN`), which persists the site and
  applies it live.
- **Settings → Web page access**: the mode, the allowed-sites list with Remove
  and an add field, and **Recent web pages** — every origin that tried this
  run, folded across networks, with network, allowed/refused, attempt count
  (preflights count) and last-seen, each with Allow or Remove.

"Allow the *current* request" — holding the refused request open until the
user answers — was considered and not built: a page's fetch would hang for as
long as the user takes, dApp libraries time out on their own schedule (10–30 s
is common), and a preflight cannot be held without holding its grant. Allowing
*future* requests covers the real flow: the page retries, and the next attempt
is served. The hold stays an option if the owner wants it.

A 403 (rather than dropping the connection) means a no-cors probe can still
tell an open port from a closed one — `fetch` *resolves* with an opaque
response instead of rejecting. Ktor exposes no way to abort a connection
without a response, so the choice was made for us; what the page can learn is
"something answers here", never which node or what it holds.

## Where the pieces live

| Layer | What |
|---|---|
| `:jsonrpc-server` commonMain | `WebAccess` (policy holder, decision, bounded recent list — 50 distinct origins, least recently seen dropped), `WebAccessPolicy`, `WebOrigins`; the gate is an `intercept(Plugins)` in `MyotisRpcServer`. The Ktor CORS plugin is gone — one policy object answers preflight, grant and refusal. |
| `:myotis-api` | `WebAccessMode`, `WebAccessPolicy`, `WebOrigin`; `ChainHandle.setWebAccessPolicy` (live, and accepted before `start()` like `setServedBlockWindow`; returns the policy that *applies*, i.e. without any entry the engine could not read as an origin — the daemon refuses to boot on a difference, the apps log it, so a bad entry is never silently dropped) and `ChainHandle.recentWebOrigins()`. |
| engines | `ChainStack` / `RustChainHandle` own one `WebAccess` per network and hand it to `MyotisRpc.server(…)`; the policy never crosses the FFI — the listener is the shared Kotlin server on both engines. |
| `:ui` | `Settings.webAccessMode/webAccessOrigins/supportsWebAccess`, `NodeController.applyWebAccess`, `NodeSnapshot.webOrigins`, `WebAccessScreens.kt` (section + banner — shown only where the host answers `supportsWebAccess()`, never as inert controls), `WebAccessUi` (normalize — pinned to the engine's by `WebAccessParityTest` —, merge, pending refusals). |
| Android | `NodeService` prefs `webAccess.mode` / `webAccess.origins`, pre-start apply, `applyWebAccess`, `recentWebOrigins`, the notification. |
| desktop | `DesktopSettings` keys `webAccess.mode` / `webAccess.origins`, pre-start apply under the served-window lock, `applyWebAccess`, snapshot rows. |
| daemon | `-Dmyotis.rpc.webAccess=off\|all\|<origin>,<origin>…` (`-PwebAccess=…` on `:app:run`); no settings file, so this is its only knob. |
| iOS | Not wired yet (follow-up from #502): `supportsWebAccess()` is false, so no section and no banner show; the listener runs the default policy (specific sites, none — web pages refused). |

The recent list is **in memory only** — it is browsing history — and is never
served over JSON-RPC (any local app could read it).

## What this does not cover

Another native app on the device. `Origin` protects anything only because
browsers enforce it for page script; a native HTTP client can send any `Origin`
or none, and a loopback listener cannot learn which app connected. That needs
client authentication (a per-client token) — a separate design question.
Browsers are adding their own gates for public sites reaching local addresses
(Chrome's Local Network Access); coverage differs by browser and WebView, so
Myotis enforces its own policy regardless. A WebSocket listener, if one is ever
added, must run the same gate on the upgrade request: browsers apply no CORS to
WebSockets.

The headless `rust/myotis-rpcd` is unaffected: it never sent CORS headers, so a
browser page could not read from it; its Host check is the same `--http-vhosts`
rule.
