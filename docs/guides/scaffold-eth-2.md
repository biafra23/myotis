# Scaffold-ETH 2 dApps on Myotis

How to make a [Scaffold-ETH 2](https://scaffoldeth.io) frontend read its chain
data from a local Myotis node instead of a public RPC or Alchemy. That covers
the dApps built in the [Speedrun Ethereum](https://speedrunethereum.com)
challenges: the challenges are Scaffold-ETH 2 projects that you deploy to a
public network. On your own machine, the numbers your frontend shows for your
contract can then be verified against the beacon chain's sync committee,
like the wallet's confirm screen, rather than taken on a provider's word.

Scope: **mainnet and Sepolia**, the Ethereum networks Myotis serves that
Scaffold-ETH 2 targets. The local `hardhat`/`anvil` chain is not involved (it
is already yours), and L2s (Base, Arbitrum, Optimism) are not served (see
[base-l2-evaluation.md](../ideas/base-l2-evaluation.md)). The background, and why a
dApp's own reads normally bypass the wallet's RPC, is in
[dapp-browser-design.md §2](../ideas/dapp-browser-design.md#2-how-a-dapp-gets-its-data).
This page is the developer's side of that: you own the frontend, so you can
point it at Myotis yourself.

## 1. Setting `rpcOverrides` alone is not enough

`scaffold.config.ts` has an `rpcOverrides` map, and putting
`http://127.0.0.1:8547` there looks like the whole job. It isn't.
`services/web3/wagmiConfig.tsx` puts the override **first in a viem
`fallback()` transport**, ahead of the chain's default public RPC (and, for
mainnet, `mainnet.rpc.buidlguidl.com`):

```ts
if (rpcOverrideUrl) {
  rpcFallbacks = [http(rpcOverrideUrl), ...rpcFallbacks];
}
// …
transport: fallback(rpcFallbacks),
```

viem's `fallback` tries the next transport after **any** error except a
revert, a user rejection, and a few wallet-specific codes (`shouldThrow` in
viem's `clients/transports/fallback.ts`). Myotis returns an error whenever
it cannot answer from verified data:

- `-32000` while it is not synced, for a log range the index has not covered
  yet, or for a contract the index does not watch;
- `-32602` for a selector it cannot apply (`safe`, a block far behind the head);
- `-32601` for a method it does not serve (`eth_subscribe`);
- HTTP `403` when the page's origin is not allowed (§3). The browser hides
  this one from the page: script sees only a network error ("Failed to fetch"),
  and the DevTools console says "blocked by CORS policy".

Each of those becomes a request to a public endpoint, and the page shows the
answer. Nothing on screen tells a verified number from a substituted one.
That is the fall-through policy *dapp-browser-design.md* §8 rules out ("never
B"). It is also the trap the [Trust](../../CLAUDE.md) rule warns about: an answer
the caller cannot tell apart from the one it asked for.

So **replace** the transport for the chains Myotis serves; don't just add to it.

## 2. Point the frontend at Myotis, with no fallback

In `packages/nextjs/services/web3/wagmiConfig.tsx`, return a Myotis-only client
for the chains you run a node for, and leave the rest of the function as it is.
Add `sepolia` to the file's existing `viem/chains` import (it already imports
`hardhat` and `mainnet`):

```ts
import { hardhat, mainnet, sepolia } from "viem/chains";

// Chains whose reads come from the local Myotis node and nowhere else.
// Ports are Myotis's defaults (the apps let you change them per network).
const MYOTIS_RPC: Partial<Record<number, string>> = {
  [sepolia.id]: "http://127.0.0.1:8547",
  // [mainnet.id]: "http://127.0.0.1:8545",  // only if you also run a mainnet node
};

export const wagmiConfig = createConfig({
  chains: enabledChains,
  connectors: wagmiConnectors(),
  ssr: true,
  client({ chain }) {
    const myotisUrl = MYOTIS_RPC[chain.id];
    if (myotisUrl) {
      return createClient({
        chain,
        // A single transport, not fallback(): a refusal must reach the page.
        // A cold eth_call fetches state proofs from peers and can take seconds,
        // so allow more than viem's 10 s default (and consider a longer
        // pollingInterval in scaffold.config.ts, see §5).
        transport: http(myotisUrl, { timeout: 60_000 }),
        pollingInterval: scaffoldConfig.pollingInterval,
      });
    }
    // … the original body, unchanged, for every other chain
  },
});
```

and set the target network in `scaffold.config.ts`:

```ts
targetNetworks: [chains.sepolia],
```

The Myotis JSON-RPC ports: mainnet **8545**, Gnosis 8546, Sepolia **8547**,
Chiado 8548 (README, *Wallet API*).

Scaffold-ETH 2 always adds **mainnet** as well, for ENS names and the ETH
price in the footer. With no mainnet node in `MYOTIS_RPC`, those reads stay on
the public endpoints. That is acceptable for a price label, less so for the ENS
name the `Address` component shows next to an address, which a lying RPC can
spoof. Run a mainnet node alongside (§3) and uncomment that line if the names
matter to you.

## 3. Run the node, and allow the page's origin

The JSON-RPC listener refuses web pages until you allow them
([web-page-access.md](../how-it-works/web-page-access.md)). The Scaffold-ETH 2 dev server's
origin is `http://localhost:3000`. Note the `http://`: a bare domain is read as
`https://`. Origins match exactly: if you open the page as
`http://127.0.0.1:3000`, or Next picks another port because 3000 is busy,
allow that origin instead. A refused page sees only "Failed to fetch". The
refusal itself shows on the app's Status tab, in the daemon's log, and in the
browser's DevTools.

**Desktop daemon:**

```bash
# Sepolia, serving the dev server's origin
./gradlew :app:run -Pnetwork=sepolia -PwebAccess=http://localhost:3000

# or Sepolia and mainnet in one process (mainnet for ENS names and the price)
./gradlew :app:run -Pnetwork=sepolia,mainnet -PwebAccess=http://localhost:3000
```

**Desktop or Android app:** Settings → *Web page access* → *Specific sites*,
add `http://localhost:3000`. Or open the page first: the refusal appears on
the Status tab with an **Allow** button.

**MetaMask (browser extension)** sends its own extension origin and needs
allowing too. It shows up in the same refused list, labelled by name. You need
it only if MetaMask also uses Myotis as its network, which is what makes its
confirm screen verified. The wallet signs and broadcasts your transactions, so
`eth_sendTransaction` never goes through the frontend's transport. Myotis only
relays the signed bytes.

Wait for the node to be ready before you load the page:

```bash
./gradlew :app:run -Pnetwork=sepolia -Pargs=beacon-status   # "state":"SYNCED"
curl -s http://127.0.0.1:8547 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'  # 0xaa36a7
```

(`curl` sends no `Origin`, so the web-page policy doesn't apply to it.)

## 4. Events: index your contract

`useScaffoldEventHistory` calls `eth_getLogs` from the contract's
`deployedOnBlock` to the head, in 500-block batches, one after another. Make
sure `deployedContracts.ts` records `deployedOnBlock`: without it the hook
starts from block 0, which on Sepolia is close to 20,000 sequential requests
before any history appears. `useScaffoldWatchContractEvent` polls through viem, which
uses `eth_newFilter`/`eth_getFilterChanges` and falls back to `eth_getLogs`.
Myotis serves all of these **only from the log index**, which covers just the
contracts you put on its watch-list
([eth-getlogs-design.md](../design-history/eth-getlogs-design.md)). The index exists **only on
the Rust engine**. The default `auto` selection picks it, but where the Rust
engine cannot load (a desktop build without cargo), `auto` runs the Java
engine. That engine answers every log query with `-32000`, and
`build-logindex` answers "not the Rust engine". Start the daemon with
`-Pengine=rust` to make that a startup error instead. Add your deployed
contract back to its deployment block:

```bash
./gradlew :app:run -Pnetwork=sepolia \
  -Pargs="build-logindex <your contract address> --from <deployedOnBlock>"
./gradlew :app:run -Pnetwork=sepolia -Pargs=logindex-status   # blocksRemaining → 0
```

Or use the app's **Index** tab. Choose an *earlier* block when unsure: a later
one hides the first events, an earlier one only walks further.
`build-logindex` is the daemon's only way to add a contract, and it turns on
max speed, so the backfill competes with your page's reads for the snap peers
while it runs. A freshly deployed challenge contract is a few hundred blocks
old, so that is brief. The apps' Index tab keeps the default pacing.

What to expect:

- A contract that is not on the watch-list is refused (`-32000`, "address is
  not on this node's log watch-list") and never answered with `[]`. Without the
  fallback from §1, that error reaches the hook's `error`. This is how you
  notice a missing index entry.
- The index trails the head by up to one tick. So a batch whose `toBlock` is
  the block `eth_blockNumber` just reported can be refused for a moment
  ("retry as the index catches up"). React Query's default retries usually
  cover it.
- The hook's `blockData`, `transactionData` and `receiptData` options fetch the
  block, transaction and receipt of each event by hash. Those reads reach only
  recent blocks: up to 512 below the head for a block, and for a transaction
  or receipt by hash only the recent window the node scans, which can be much
  shorter (README, *Wallet API* and *Block selectors*). For an older
  event Myotis answers `null`, and viem turns that into a not-found error (for
  example `BlockNotFoundError`). The logs themselves still come from the index,
  which can cover far more history. Leave those options off for a contract
  older than a few hundred blocks, or expect the extra data only for recent
  events.

## 5. What else differs from a hosted RPC

- **Recent state only.** State reads and `eth_call` pinned to a block more
  than 64 blocks behind the head are refused with the permanent `-32602`. The
  exception is a block at or above a head this node itself reported in the
  last 15 minutes, which gets the retryable `-32000` (README, *Block
  selectors*). `safe`, `earliest` and block 0 are refused as selectors for
  these reads. This does not affect `eth_getLogs`, whose range the log index
  clamps to the contract's watched start (§4). A Scaffold-ETH 2 frontend reads
  `latest`, so the standard hooks are unaffected. A custom view of past state
  is not.
- **Latency.** A hosted RPC answers in tens of milliseconds. Myotis fetches
  state proofs from peers, so a cold `eth_call` or Multicall3 batch can take
  hundreds of milliseconds to seconds, which is why §2 raises the timeout.
  Scaffold-ETH 2 polls every `pollingInterval` (3 s by default); a longer
  interval in `scaffold.config.ts` means less work for the node and fewer
  addresses disclosed to peers (next point).
- **Privacy.** Every address the page reads is asked of devp2p peers from your
  IP (dapp-browser-design.md §4.2). A provider would see the same addresses,
  plus your API key.
- **A deployed frontend.** All of this is for a frontend you run against your
  own node. A copy deployed on Vercel (`https://….vercel.app`) runs in other
  people's browsers, where no Myotis listens on `127.0.0.1`. Keep the
  `MYOTIS_RPC` switch out of production builds, or gate it behind an
  environment variable. To use the deployed copy against your own node, allow
  its origin as in §3. Recent browsers may also ask before a public site may
  reach `localhost`.

## 6. Check that nothing bypasses the node

Open the browser's developer tools, go to the **Network** tab, and use the
dApp: every JSON-RPC `POST` for your target chain should go to `127.0.0.1`.
Anything else (a public RPC, `g.alchemy.com`, `rpc.buidlguidl.com`) is a read
your page did not take from Myotis. Typical sources are a chain you left out of
`MYOTIS_RPC`, or a component that builds its own client instead of using
`wagmiConfig`.
