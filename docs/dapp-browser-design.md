# dApp browser & RPC interception — evaluation and design sketch

Status: **evaluation, nothing built.** Written 2026-10-10 from the tree as of
that day (the Node addon's provider table from #503, the CORS block in
`jsonrpc-server`, the served-window and block-pin rules in the README's
*Wallet API*), the observable behaviour of today's dApp frontend stacks, and
this repo's trust rules. It answers two questions the owner asked: whether the
myotis apps should embed a minimal browser for dApps, and — since most dApps do
not let the user choose their RPC endpoint — whether such a browser could
redirect a dApp's own RPC calls to the engine. Decisions it leaves open are
marked as the owner's call. Nothing here is scheduled.

**Owner's verdict (2026-10-10): postponed.** No dApp browser in the myotis
apps until more details about what one would add arrive; for now the Freedom
browser's integration (§1, §5) is good enough. This document stays as the
record to pick the question up from. The loopback-endpoint finding (§1, §9
phase 0) is independent of the verdict and remains open.

**Short answer.** A general embedded dApp browser does not fit myotis, and the
problem is less the browser than what it drags in: a dApp is only usable once
something can sign for it, and myotis deliberately holds no keys, so "a dApp
browser" is a wallet product with key custody. Redirecting a dApp's own RPC
traffic to the engine is straightforward on desktop and fragile on mobile, but
redirecting is the easy half: the engine cannot serve most of what a dApp asks
(other chains, arbitrary `eth_getLogs`, history, subscriptions, the request
rate), so the real design decision is what happens to the call it cannot
serve — fail it, and dApps break on load; pass it through, and the page becomes
a blend of verified and unverified numbers that look identical to the user.
The recommended path (§9) proves the interception as a desktop browser
extension first, builds the engine-side policy layer that the data from it
calls for, and reserves an embedded WebView for mobile, read-only, over
content-addressed frontends. A general embedded browser with keys inside the
myotis apps is not recommended.

---

## 1. What the tree says today

Facts this document rests on, with where to check them:

- **The engine half of a dApp provider already exists.** Every host runs the
  verified JSON-RPC server on loopback (`jsonrpc-server`, `VERIFIED_METHODS`
  in `RpcRouter.kt`), and [`rust/myotis-node/README.md`](../rust/myotis-node/README.md)
  §*A dApp provider's methods* maps every `window.ethereum` read a page can
  make to an addon call, with the argument checks the routers make (#503).
  Nothing is missing on the read side of a provider.
- **Myotis signs nothing and holds no account keys.** `eth_accounts` is the
  constant `[]`, `eth_sendRawTransaction` relays bytes the wallet signed, and
  [architecture-doc.md](architecture-doc.md) §7 *Submitting Signed Transactions* puts
  construction and signing in the wallet. The only key in the tree is the node
  identity key (`NodeKey`, the `NodeKeyStore` port — "key custody is a genuine
  platform concern", [05-engine-api-bindings.md](reimplementation/05-engine-api-bindings.md)).
- **No host embeds a WebView.** The shared `:ui` is a Compose Multiplatform
  control panel (Status / Query / Logs / Index / Settings). No Android, desktop
  or iOS build file pulls in a WebView, JCEF or Chromium.
- **The browser-with-myotis-inside already exists, outside this repo.** The
  [Freedom browser](https://github.com/solardev-xyz/freedom-browser) embeds the
  Node addon on desktop ([PR #181](https://github.com/solardev-xyz/freedom-browser/pull/181))
  and the Rust staticlib on iOS ([freedom-mobile-ffi](https://github.com/solardev-xyz/freedom-mobile-ffi))
  as an invisible background node for verified `.eth` resolution.
  [04-engine-and-hosts.md](reimplementation/04-engine-and-hosts.md) §8 names
  "point the platform wallet/WebView at it" as a host option — the host's
  WebView, not the engine's.
- **MetaMask on the loopback endpoint is validated end to end**
  ([implementation-status.md](implementation-status.md) §10): the confirm
  screen renders from verified balances, fees and a local gas estimate, and the
  signed transaction is broadcast over devp2p.
- **The loopback endpoint's threat model assumes its client is the wallet.**
  It is unauthenticated, has no TLS and no rate limiting (README §*Wallet API*
  → *Security*), exposes `myotis_pause` / `myotis_wakeup` next to the reads,
  and its CORS block is `anyHost()`
  (`jsonrpc-server/src/commonMain/kotlin/io/myotis/jsonrpc/MyotisRpcServer.kt`,
  `install(CORS)`): the server itself refuses no browser origin. Only
  browser-side private-network rules (Chrome's Private Network Access, which
  Firefox and Safari apply differently, and which vary by version) stand
  between a public web page in an ordinary browser and the port. This is a
  finding on its own, independent of any browser decision (§9, phase 0).
- **No prior discussion.** No issue in this repository mentions a dApp
  browser, WalletConnect, a signer or key custody (searched 2026-10-10).

## 2. How a dApp gets its data

The premise behind the second question is right: most dApps do not let the
user choose the RPC endpoint. A dApp frontend's chain traffic falls into three
buckets, and today myotis touches only the first — through the wallet.

| Bucket | What goes there | Who picks the endpoint | Reaches myotis today? |
|---|---|---|---|
| **A. Provider-routed** (EIP-1193 `window.ethereum`, discovered via EIP-6963) | Always: `eth_requestAccounts`, `eth_accounts`, `eth_chainId`, `eth_sendTransaction`, `personal_sign`, `eth_signTypedData_v4`, `wallet_switchEthereumChain`, `wallet_addEthereumChain`, `wallet_watchAsset`. Plus **every read**, in frontends that wrap the injected provider as their read provider (ethers v5 `Web3Provider` / v6 `BrowserProvider` over `window.ethereum`, older web3.js dApps). | The wallet — i.e. the user, via the wallet's network settings | **Yes**, when the wallet is MetaMask pointed at `127.0.0.1:8545` |
| **B. The dApp's own transport** | In wagmi/viem-era frontends (wagmi `createConfig({ transports })`, RainbowKit, ConnectKit, Web3Modal/AppKit): balances, contract reads, Multicall3 batches, `eth_getLogs` scans, ENS, block polling, gas. The transport is an Alchemy / Infura / QuickNode URL with the dApp's own key, or viem's built-in default public endpoint for the chain when `http()` is given no URL. | The dApp developer, in code | **No** |
| **C. Not JSON-RPC at all** | Subgraphs (The Graph), the dApp's own backend (routing and quote APIs, position and history endpoints), price feeds, token lists, third-party indexers (Etherscan-style APIs, Zapper, Covalent), WebSocket subscriptions to the provider. | The dApp developer | **No**, and cannot be redirected to an Ethereum JSON-RPC server |

Two consequences. First, with MetaMask on myotis the *confirm screen* is
verified but the *numbers the dApp itself shows* usually are not — they come
from bucket B and C. Second, a dApp that puts all reads through the injected
provider (bucket A, the ethers style) already runs every read through the
engine, and is the existing sample of what §7 describes: such dApps work when
their reads stay within the verified surface and stall when they do not.

## 3. Why "a dApp browser" means "a wallet"

Without bucket A's account and signing methods, almost every dApp shows
"connect wallet" and stops: a wallet that answers `eth_requestAccounts` with
`[]` (which is what myotis's `eth_accounts` is) is not a wallet to the page.
So "a minimal browser for dApps" is, concretely:

- key custody (generation, backup, storage in Android Keystore / iOS Secure
  Enclave / a desktop keychain, or a hardware-wallet or WalletConnect path);
- a confirmation screen for transactions and signatures, drawn by native code,
  never by the page, with simulation of what the transaction does (myotis's
  `eth_call` / `eth_estimateGas` with state overrides can feed this well);
- per-origin permissions: which site may see which accounts, which chain it is
  on, revocation;
- chain switching (`wallet_switchEthereumChain` across the networks the
  engine serves);
- EIP-712 typed-data display, blind-signing warnings, approval-amount checks.

That is a wallet product, and it changes the worst case of a compromise. Today
the worst a bug or an attacker can do through myotis is show a wrong number,
censor a transaction, or leak an address–IP pair (the privacy doc's threat
model). With keys in the process, the worst case is loss of funds. This is a
product-scope decision for the owner, not a UI feature.

## 4. Security implications specific to myotis

The generic hazard — attacker-controlled JavaScript in the same process as
signing keys — is the one every mobile wallet with a dApp browser carries, and
the reason those products ship renderer isolation, out-of-process signing and
origin-bound permissions and still have incidents. The points below are the
ones that are *specific* to myotis, because it is a P2P node and not a client
of a hosted RPC.

### 4.1 The loopback endpoint becomes reachable by design

The endpoint's security note (README) is "the wallet is a same-device client".
An embedded browser puts untrusted pages on the trusted side of that line on
purpose: the dApp *is* on the same device. Consequences:

- Page-to-node traffic must go through a **native bridge** with per-origin
  consent and quotas (§6.2), never the raw port. Otherwise any page the browser
  loads can call `myotis_pause` (stop the node), relay arbitrary signed bytes
  through `eth_sendRawTransaction` (the node's broadcast then links *that*
  transaction to the user's IP — the privacy doc's "first spy" setup, for a
  transaction that is not even the user's), and run the reads of §4.2.
- The `anyHost()` CORS block (§1) means an ordinary browser on the same device
  is in nearly the same position already, modulo the browser's own
  private-network rules. Fixing that is independent of this document (§9,
  phase 0) and leaves the extension path intact, since extension-scheme
  origins stay on the allow-list while every other origin, `null` included,
  is refused.

### 4.2 Every read is a network query from the user's IP

A hosted RPC answers a dApp's reads from its own database; nothing about the
user leaves the device but the HTTP request to that one provider. A myotis
read is a snap query to peers that carries `keccak(address)` and storage-key
hashes — [privacy-and-tor.md](privacy-and-tor.md) §1 ranks this the core leak
(**High**): every snap peer learns address ↔ IP, hedged reads widen the
disclosure to up to three peers. A page that can ask the engine for arbitrary
addresses turns the user's node into a **deanonymization oracle the attacker
drives**: it can make the user's IP query any address it likes, at any rate,
and the peers see those queries as the user's interest. The Tor read path
narrows this for account reads only, on the desktop and Android hosts only
(and only in a `-PtorEngine` build); storage reads,
`eth_call`, gas estimation and broadcast have no Tor path today.

### 4.3 The read budget is shared and a dApp is not a cooperative client

Verified reads run on bounded workers: the Node addon gives each operation a
90 s budget including queue wait, one running at a time
([`rust/myotis-node/README.md`](../rust/myotis-node/README.md)), and on the
JVM hosts a read that arrives while the node is waking is held at most 90 s
(`ChainStack.WAKE_WAIT_CAP_MS`, #432); the Node addon's TODO already records
libuv-pool starvation from four concurrent worst-case reads in an Electron
host ([TODO.md](TODO.md)). MetaMask asks for what its screens need. A dApp polls
`eth_blockNumber` every few seconds, fires a Multicall3 `eth_call` per block
per widget, scans logs on load, and retries on its own timeouts. Without
per-origin quotas one page can starve the wallet's own confirm screen.

### 4.4 An HTTPS-served frontend re-imports the trusted server

The project exists to remove the trusted RPC provider from the loop. A dApp
frontend fetched over HTTPS from a CDN is the same class of trust: whoever
controls the DNS name, the CDN or the deploy pipeline controls what the page
asks the node and what it shows. Verified data rendered by an unverified page
is only as good as the page. The coherent version is a **content-addressed
frontend**: an ENS `contenthash` resolved verified by myotis (the engine does
this today — `ensRecordJson` with `method: 'contenthash'`, the daemon's
`resolve-ens-*` commands), then the frontend fetched from IPFS or Swarm by
hash, so its integrity is checked against a root the chain holds. Myotis has
no content-addressed fetch path: the Bee work in this repo is Bee *consuming*
myotis as its RPC, not myotis fetching from Swarm, and an HTTP gateway to IPFS
or Swarm would put the trusted server straight back. The one gateway path in
the tree is the precedent for that, not a counter-example: `:tx-history`
fetches Unchained Index objects by CID through a trusted IPFS HTTP gateway
(`UnchainedIndexStore.kt`, "bounded by TLS to the trusted gateway"), and is
debug-only, Java-engine-only and unverified for exactly that reason. The Freedom browser has
exactly those fetch paths (its Swarm and IPFS nodes) next to its myotis node,
which is one more reason the browser belongs in that kind of host (§9).

### 4.5 Platform cost of the WebView itself

| Host | WebView available | Cost and exposure |
|---|---|---|
| Android (`:android-app`) | System WebView (Chromium, updated by Play, renderer sandboxed) | Cheap to add; `shouldInterceptRequest` sees no POST body (§6.2); minSdk 29 budget unaffected |
| iOS (`:app-ios`, `ios-app/`) | `WKWebView` (out-of-process WebKit, updated with the OS) | Cheap to add; no http(s) interception at all (§6.2); Compose Multiplatform iOS can host it via UIKit interop |
| Desktop (`:app-desktop`) | **None in Compose Multiplatform.** JCEF/KCEF (a Chromium the app ships and patches itself, well over 100 MB on top of the embedded JVM), or JavaFX `WebView` (WebKit, old, no sandbox story) | Heavy; a Chromium patch cycle the project would own; the dmg/deb already embed a JVM |

## 5. Alternatives that keep the boundary where it is

Each of these gets a dApp a verified node without the myotis apps growing a
browser or a signer:

- **The host embeds myotis and owns the browser** — the Freedom model. The
  Node addon's provider table is the engine's half of exactly this; the
  missing half (a `window.ethereum` shim over the addon, with the host's own
  signer) is host work. Contributing that shim upstream gets the result
  without changing what myotis is.
- **A wallet on the loopback endpoint** — what works today. MetaMask pointed
  at the device covers bucket A; the user's keys stay in MetaMask.
- **A browser extension that intercepts bucket B** — the same redirect §6
  describes, in the user's normal browser, with no custody problem and no
  shipped Chromium. Desktop browsers, plus Firefox for Android (general WebExtensions with
  content scripts since Firefox 121, late 2023) and, within Apple's limits,
  iOS Safari's web extensions — so the path also yields a mobile data point
  without a WebView. §9 makes this the first step.
- **WalletConnect or an EIP-6963 extension as the signing boundary** — the
  signer is a separate app or extension; myotis stays the node. WalletConnect's
  relay is a liveness-only trust (it carries encrypted envelopes; it can
  withhold, not forge) but it does see pairing metadata, which the privacy doc
  would have to weigh.

## 6. Intercepting a dApp's own RPC calls (bucket B)

### 6.1 Detection: by body, not by URL

There is no need to know the dApp's provider URL. An Ethereum JSON-RPC request
is a POST whose body is an object or an array of objects with `jsonrpc`,
`method` and `params`, and the method starts with `eth_`, `net_` or `web3_`.
That shape is distinctive enough to classify on the body alone, so an
interceptor can route *every* such request from *any* URL to the engine and
leave everything else untouched. Batches are routed whole (the router handles
them element by element, at most 1000 per batch).

### 6.2 Where the interception can live

| Where | Sees POST bodies? | Covers | Misses |
|---|---|---|---|
| **Electron** (`session.webRequest.onBeforeRequest` with `uploadData`, or `protocol.handle` for the scheme) | Yes | Main frame, iframes, workers, service workers | WebSockets (handle separately) |
| **JCEF** (`CefResourceRequestHandler.getResourceHandler`, `CefRequest.getPostData`) | Yes | Same as Electron | WebSockets |
| **Android WebView** (`WebViewClient.shouldInterceptRequest`) | **No** — `WebResourceRequest` carries no body | Nothing useful at this layer | Everything; fall back to the JS patch below |
| **iOS `WKWebView`** (`WKURLSchemeHandler`) | Custom schemes only; **cannot intercept http(s)** | Nothing at this layer | Everything; fall back to the JS patch below |
| **JavaScript patch** injected at document start, wrapping `fetch` and `XMLHttpRequest` in the page's main world and forwarding matches to a native bridge | Yes (it *is* the caller) | Main-thread requests from viem's `http` transport and friends | Web Workers and Service Workers (separate globals, not patched unless injected there too), WebSockets, `navigator.sendBeacon`, a page that captured `fetch` before the patch, cross-origin iframes the host did not inject into |
| **Browser extension** (content script patching `fetch`/XHR, or MV3 `declarativeNetRequest` URL rules, background worker calling the loopback port) | Content script: yes; DNR: no (URL patterns only) | Desktop browsers; the content-script variant covers what the JS patch covers | Same gaps as the JS patch; DNR rules need a list of provider URL patterns and get no body |

So the network-layer redirect is clean on desktop (Electron, JCEF) and the
mobile WebViews only offer the JavaScript patch, with its gaps. The gaps are
not corner cases: viem can run transports in workers, subscription-based
frontends use WebSockets, and a page's own service worker caches RPC responses.

### 6.3 Chain classification

A dApp's provider URL serves one chain, and most dApps hold several at once
(a portfolio view queries mainnet, Arbitrum, Base, Optimism and Polygon in one
load). The interceptor must know which chain a URL serves before routing, and
route **only** calls for a chain the engine serves (mainnet, Gnosis, Sepolia;
[base-l2-evaluation.md](base-l2-evaluation.md) says why not Base). The
signal that always exists is a one-time `eth_chainId` probe of the original
URL, per origin and URL: **the probe decides.** The URL can only veto: where
a hostname does carry a chain (`eth-mainnet.`, `arb-mainnet.`,
`base-mainnet.` at the large providers) and contradicts the probe, route
nothing for that URL. Many URLs carry no signal at all — viem's built-in
defaults, a dApp's same-origin `/api/rpc` proxy, a QuickNode subdomain — and
those are exactly the dApps this document is about, so the URL can never be
required. The probe is an unverified call to the dApp's own endpoint, but it
decides routing, not a displayed value: a lying endpoint can at worst make
the interceptor route Base calls to the engine's mainnet, and the page then
shows mainnet data under a Base label — a wrong display caused by the
endpoint the dApp already trusts for everything. The hostname veto closes
the easy version of that.

## 7. What breaks when a redirected call reaches the engine

The engine was built for a wallet's traffic. A dApp's is different in kind,
not just in volume. Per class, the engine's behaviour today and the effect on
the page:

| dApp traffic | Engine today | Effect on the page |
|---|---|---|
| Reads on Arbitrum, Base, Optimism, Polygon, … | Not served; cannot be routed at all (§6.3) | Those parts of the page keep using the dApp's provider — nothing gained, nothing lost |
| `eth_getLogs` over arbitrary contracts (position discovery, Transfer history, event-driven UIs) | Served only from the opt-in, per-contract log index, Rust engine only; a range the index has not walked is `-32000`, never a misleading `[]` ([eth-getlogs-design.md](eth-getlogs-design.md)) — and so is a contract that is not on the watch-list at all (`QueryError::UnwatchedAddress` in `host.rs` maps to the plain, retryable error), although no retry will ever index it | The first "your positions" query fails unless the user indexed exactly those contracts, with coverage back to deployment; and because the refusal is the retryable code, a dApp spins on it instead of giving up (§8) |
| Old blocks, old receipts, `earliest`, historical `eth_call` | A served block window (default 32 blocks, `EthHandler.DEFAULT_SERVED_BLOCK_WINDOW`, user-settable); state reads pinned more than 64 blocks behind the head refused with `-32602` — except a pin at or above a head this node itself reported in the last 15 minutes, which `pinServable` (`RpcRouter.kt`) declines with the retryable `-32000`, because recorded MetaMask sessions showed the head swinging back by thousands of blocks; no historical state; `eth_getProof` not served | History views, "transactions" tabs and anything that re-reads a past block fail; and the `eth_blockNumber`-then-pin pattern every dApp uses is exactly the carve-out's traffic, so under a head swing a dApp sees the retryable code on state pins too (§8 A) |
| `eth_subscribe` (WebSocket), `eth_newFilter` / `eth_getFilterChanges` | Not served (`-32601`); no WebSocket listener | viem falls back to polling; frontends that require the socket stall |
| Polling `eth_blockNumber` every few seconds, Multicall3 `eth_call` per block per widget, batched `eth_getBalance` for every token in a list | Each read is a proof fetch from peers, with a round trip per cold storage slot (the prefetch loop batches what it can); the Node addon's 90 s per-operation budget; heartbeat whitespace to survive a wallet's ~30 s read timeout | A hosted RPC answers in tens of milliseconds; the engine answers a cold multicall in hundreds of milliseconds to seconds. dApp timeouts are shorter than a wallet's, and a dApp retries on timeout, which compounds the load (§4.3). [read-stats.md](read-stats.md) measures what a cache would recover |
| The same reads, from the privacy angle | Every address the page asks about is disclosed to peers with the user's IP (§4.2) | The leak rate becomes the dApp's request rate, for addresses the dApp chose |
| Bucket C (subgraphs, backend APIs, price feeds, indexers) | Not JSON-RPC; cannot be redirected | The balance on screen may never have been an RPC call; redirecting bucket B does not touch it |

The honest summary: with perfect interception, the subset of a typical DeFi
frontend that the engine can serve verified is the **current-head state and
call reads on the three served chains**, which is also the subset that
matters most for what the user is about to sign. Everything about the past,
about other chains, and about event scans stays where it was.

## 8. The policy fork: the call the engine cannot serve

This is the design decision, and it is the owner's. With interception in
place, every bucket-B call ends in one of three places:

- **A. Fail closed.** The engine's `-32601` / `-32000` / `-32602` goes back to
  the page as the provider's answer. Honest, and consistent with the trust
  rules — but most dApps fail on load (§7), so the feature reads as "the
  browser where nothing works". It is also not quite fail-closed today: an
  `eth_getLogs` for a contract the user never put on the watch-list answers
  the retryable `-32000`, the code [CLAUDE.md §Trust](../CLAUDE.md) warns a
  client will spin on, for a question no retry will ever answer. Policy A
  needs the phase 2 split (permanent `-32602` for an unwatched contract or an
  unindexed topic, `-32000` only for a range the index is still walking)
  before it is honest for the first query most dApps make. And "honest"
  holds per intercepted call, not per page: §6.3 never intercepts the
  other-chain calls of a multichain page, so under A a page still renders
  engine-verified mainnet or Gnosis values next to unverified Arbitrum or
  Base values, per value indistinguishable — the blend B is faulted for, in
  residual form. No regression against today, where nothing on the page is
  verified, but one more reason the provenance mark and a per-origin
  aggregate (C's, with the never-intercepted other-chain calls in the
  denominator) are wanted under A too; the phase 2 mark is independent of
  the A/C choice.
- **B. Fall through silently.** A call the engine refuses is re-sent to the
  dApp's original URL. Every dApp works; the page is now a blend of verified
  and unverified numbers that look identical, and nothing on screen says
  which is which. This is the posture [CLAUDE.md §Trust](../CLAUDE.md) exists
  to avoid: a well-formed answer from a source the user did not choose, that
  the user cannot distinguish from the verified one. The "applied or refused"
  rule is about parameters, but its reason — the caller cannot detect a
  substitution — applies verbatim.
- **C. Fall through visibly, opt-in.** As B, but only for origins the user
  explicitly allowed, off by default, with the host showing a per-origin
  aggregate ("this page: 41 of 63 calls answered verified; 22 passed through
  to `eth-mainnet.g.alchemy.com`") and the engine marking each response's
  provenance so the host can count. A page's rendering cannot be annotated
  per number — the indicator is per origin, not per value — so this is
  strictly weaker than the wallet's confirm screen, where every number is
  verified or absent.

Recommendation: never B. A is the default. C only if the owner wants the
feature to be usable on today's dApps at all, and then with the provenance
mark and the per-origin consent as hard requirements, not polish. Note that
the *signing path* is unaffected by this choice — bucket A's confirm screen
stays fully verified under A and under C alike — which is why §9 keeps the
value there.

## 9. Recommended path

Ordered so that each step is useful on its own and produces the data the next
one needs. None of it is scheduled.

**Phase 0 — close the loopback endpoint to browser origins, default-deny.**
Independent of everything else and overdue on its own (§1), with one client
that must keep working: the MetaMask extension's background worker reaches
the port with `Origin: chrome-extension://<id>` (on Firefox
`moz-extension://<uuid>`, a per-install UUID no static allowlist can name),
and that is the validated path of §1. So the proposal is an **allow-list**:
serve a request only when it carries no `Origin` header (same-device native
clients, as today) or an extension-scheme origin (`chrome-extension://`,
`moz-extension://`, `safari-web-extension://`); **refuse everything else**,
`http`/`https` web origins and the literal `Origin: null` included. `null`
matters: a sandboxed or `data:` iframe has an opaque origin and its `fetch`
POSTs carry `Origin: null`, so a deny-list that only names web schemes
leaves the port open to exactly the page it meant to shut out. And the
refusal has to be the server rejecting the request (Ktor's CORS plugin
answers a failed origin check with 403), not merely withholding the CORS
response headers: a POST with `Content-Type: text/plain` is CORS-safelisted
and goes out without a preflight, the route reads the body whatever its
content type (`call.receiveText()` in `MyotisRpcServer.kt`), and none of
`myotis_pause`, the `eth_sendRawTransaction` relay or the §4.2 read oracle
needs the response to do its damage. Ktor's static `allowHost` cannot name a
per-install extension UUID, so this is the plugin's origin predicate or a
custom check. That shuts out a web page in any browser and leaves installed
extensions where they are — a weaker line than a pairing token, and that
trade-off is the owner's call; a token (shown in Settings, carried in the
wallet's custom-network URL or a header) is the tighter follow-up if the
owner wants one. Do not rely on the browser's private-network rules — they
differ by browser and version. The phase 1 extension rides the same
extension-origin allowance. A single PR into `main`.

**Phase 1 — a desktop browser extension PoC.** The body-classifying redirect
of §6.1 as a content script plus a background worker talking to the loopback
port (allowed by phase 0), with chain classification per §6.3 and policy A.
Run it against real dApps and *measure*: which methods, which chains, which
block selectors, how many calls per minute, how long each takes, which
timeouts fire, which dApps work under policy A at all. This is the cheapest
way to learn what the engine would have to grow, it needs no custody, no
shipped Chromium and no WebView, and it runs next to the daemon that already
serves the port. The extension is a separate repository or `tools/` entry,
not a host module.

**Phase 2 — the engine-side policy layer.** Whatever phase 1 shows, these are
the engine and host pieces that any interception needs and that are useful to
the existing wallet path too:

- a **provenance mark**, split by who can truthfully set it: the engine
  marks its own responses `verified` or `refused` (and, on the log index,
  `seeded` — the mark [seeded-log-histories.md](seeded-log-histories.md)
  already asks for); the interceptor — extension or host bridge — stamps
  `passed-through` on the responses it fetched itself from the dApp's
  original URL, which the engine never sees and must never fetch
  (devp2p/libp2p only in production; HTTP to a client is debug-only).
  Together they let a host count and show the per-origin aggregate — the
  precondition for policy C, and wanted under A too (§8);
- **per-origin quotas** on the bridge (§4.3) and an explicit per-call
  classification the host can read without parsing error strings;
- the **permanent/retryable split on `eth_getLogs` refusals** (§8 A):
  `-32602` for an unwatched address or an unindexed topic, `-32000` only
  while a range is being walked — the engine's own rule for a parameter it
  cannot apply, applied to the index's scope;
- **wider `eth_getLogs` coverage** by the route already designed: verified
  bundles the walker re-checks ([logindex-verified-bundle-design.md](logindex-verified-bundle-design.md),
  #472), since event scans are the first thing a dApp does;
- the **read-stats** findings turned into a real cache where they justify one,
  since a dApp's polling is exactly the repeat-read pattern that document
  measures.

**Phase 3 — mobile, owner's decision.** Inside the myotis apps, an embedded
WebView is the only place interception can live on Android and iOS; outside
them, Firefox for Android takes the phase 1 extension, which is the cheaper
mobile data point and comes first. If the owner wants a dApp surface
in the mobile apps, the defensible scope is a **read-only verified viewer**:
an ENS name → verified `contenthash` → content-addressed fetch (which first
needs an IPFS or Swarm fetch path the engine does not have, §4.4) → a WebView
whose provider serves only the read methods and refuses account and signing
calls (`4001` / `-32601`), bridged natively, never through the loopback port.
Signing, if ever, through a separate boundary (§5), never with keys in the
myotis process.

**Not recommended:** a general embedded browser with a signer inside the
myotis apps (§3, §4). The Freedom model — a host that owns the browser, the
content-addressed fetch paths and the signer, and embeds myotis as the node —
gets the same outcome with the boundary where this project has kept it.

## 10. Decisions for the owner

Decided 2026-10-10: item 2 is **postponed** — a dApp surface stays with
hosts that embed the engine (the Freedom browser) until more details about
the advantages of an embedded browser arrive. Items 3–5 are moot until item
2 is reopened. Item 1 is unaffected by the verdict and still open.

1. Phase 0's exact policy for browser origins on the loopback endpoint
   (an allow-list of no-`Origin` and extension-scheme origins, everything
   else refused by the server, is the proposal; a pairing token the tighter
   option).
2. Whether a dApp surface belongs in the myotis apps at all, or stays with
   hosts that embed the engine (§5, §9 "Not recommended").
3. If it does: policy A or C for unservable calls (§8). B is not proposed.
4. Whether a content-addressed fetch path (IPFS / Swarm) is in scope for the
   engine, which phase 3 and any trust-consistent frontend loading depend on.
5. Whether signing is ever in scope, and through which boundary (§5).
