# Trust and data sources

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before adding any data source or touching roost, log-index seeds, `:tx-history`, or anything Portal would have solved.

## Trust

- Peer trusted is never an option everything has to be cryptographically verified
- The only trust anchors are sync committee signatures and  the embedded pre-Merge historical hashes accumulator and the Bellatrix-era historical roots accumulator
- **One bounded exception to the two rules above (owner's decision,
  2026-09-25):** a seeded log history of a root-committing protocol is served
  on its publisher's word. The client's on-chain root check keeps forged
  leaves out of its tree; it does not surface a withheld or altered one, so
  the wallet's displayed balance rests on the publisher. Scope and limits: the
  carve-out under *Data sources*.
- **One more, on the owner's request (2026-11-10), Rust engine (its persisted
  store is the snapshot the Java engine also resumes):** only at a
  `STALE_ANCHOR` park and only on the user's request (explicit, or a choice
  the user told the app to remember), a fresh checkpoint that every answering
  checkpoint-sync server names (at least two independent operators). Scope and
  limits: the carve-out under *Data sources*.
- **A parameter that can change the answer must be APPLIED or REFUSED — never
  accepted and silently ignored.** A well-formed result computed against
  something other than what the caller asked for is indistinguishable from a
  correct one, so the caller cannot detect it, retry it, or work around it. This
  is the same rule the log index applies to an out-of-coverage range (an error,
  never a misleading `[]`). It was learned the hard way: `eth_call` accepted the
  state-override parameter and dropped it, which silently broke a wallet's
  account-state reads and cost hours to trace back (#314). When refusing, use a
  PERMANENT error code (`-32602`) — `-32000` is documented as retryable and a
  client will spin on it.

## Data sources
- the only sources for data are devp2p and libp2p calling a local client via http may only be used for debugging purposes it is not an option for production
- **Carve-out for myotis-operated serving infrastructure (owner's decision,
  2026-08-08).** The rule above governs the **wallet**. `roost`, the dedicated
  light-client server (`rust/roost`, docs/design-history/lc-server-design.md), MAY source
  *self-verifying* consensus objects — LC bootstrap, updates, finality and
  optimistic updates — from a local beacon node over loopback REST, and does
  NOT verify them itself. The verification happens in myotis: a bootstrap is
  anchored to the checkpoint root the wallet already pins, and every update is
  checked against sync-committee BLS signatures by the wallet receiving it. A
  relay can withhold, but it cannot forge.
  Two boundaries this carve-out does **not** cross:
  - **"Self-verifying" is load-bearing.** It does not widen into "roost may
    serve anything it read over REST". Any path relaying something a wallet
    cannot check against sync-committee signatures — proxying
    `beacon_blocks_by_range` is the live example — needs its own decision.
  - **Withholding is a liveness attack and this concentrates it.** It is
    *detected*, not silently wrong: both engines' SYNCED gate needs the
    finalized header within 5 epochs of the wall clock
    (`SYNCED_SLOT_SLACK_EPOCHS` in `BeaconSyncState` and `sync.rs`), so a
    stalled relay drops the beacon status to `CATCHING_UP` once its last
    finality is more than 5 epochs old (32 min on mainnet, ~7 min on gnosis)
    and the hosts show "not ready". Reads do NOT start failing with
    `beaconNotSynced` — that token only fires before the first finalized root
    lands after a start — they keep answering against the last anchor until
    peers can no longer prove against it or the header chain passes 8192
    blocks (`headerChainGapTooLarge`). The signal is the beacon status, not a
    read error.
- **Carve-out for seeded log histories of root-committing protocols (owner's
  decision, 2026-09-25).** The log index MAY serve a contract's history from an
  imported seed myotis did not walk, on the word of the protocol maintainers
  who publish and vouch for it, when the protocol's client rebuilds its
  note-commitment tree from the logs and checks the root on-chain. Myotis
  walks and verifies everything above the seed's top, as for any import. This
  is publisher trust for the DISPLAYED BALANCE, with one hard bound: a client
  that inserts leaves only under a root the contract held never holds a
  forged leaf, so no spend is built on a fake tree. It does not make tampering
  visible. RAILGUN's contract keeps every root a tree ever had (`rootHistory`)
  and its stock engine stops quietly at the first bad or missing leaf, so a
  seed that withholds or alters a commitment understates the balance with no
  error; a replaced Shield ciphertext or a withheld nullifier overstates it.
  Detail, the client-side checks that would close most of it, and the
  preconditions: docs/how-it-works/seeded-log-histories.md.
  Two boundaries this carve-out does **not** cross:
  - **The client's root check is load-bearing, and must actually run.** No
    on-chain root, or a client that skips the check, keeps the walk — kohaku's
    Tornado Cash client ships with it off.
  - **The check is the client's, not the index's.** Any other consumer reading
    the span over `eth_getLogs` cannot tell seeded logs from walked ones, so a
    seed is not a production path until the index marks its provenance. Nor
    does this rule let this repo's own tooling GENERATE a seed from a node
    over JSON-RPC — that stays open, and the RAILGUN PoC's seed stays DEBUG /
    DEMO (docs/guides/railgun-poc.md).
- **Carve-out for fresh checkpoints at a stale anchor (owner's request,
  2026-11-10; docs/how-it-works/stale-anchor.md).** The Rust engine reads one
  HTTPS source beside its peers, through its one HTTP client
  (`rust/myotis-net/src/https.rs`: pinned URLs, no redirects, Mozilla roots).
  (Colibri's ZK proofs of the committee chain were in an earlier revision of
  #761 and removed before merging, owner's decision 2026-11-13: they attest the
  walk from Colibri's pinned anchor committee, older than the weak-subjectivity
  bound, so they add no answer to a stale anchor — the doc's last section.)
  - **Checkpointz finalized roots**, ONLY at a `STALE_ANCHOR` park and ONLY
    on the user's request: the explicit "Fetch fresh checkpoint"
    (`refreshAnchorFromCheckpointz`), or that choice remembered by the user and
    then applied by the engine itself at each park, also headless, but never
    unattended under Tor (owner's request, 2026-11-11). Never otherwise
    automatic, and never applied to a store that is not parked. The root is
    accepted only when the vote is UNANIMOUS: every server that answers names
    the same finalized epoch and root, spanning at least 2 operators
    (registrable domains). One differing answer (another root or epoch, an
    `execution_optimistic` or malformed answer) is an alarm: the fetch is
    refused and the outlier named, never outvoted (owner's ruling, #761,
    2026-11-11). It is their word, as the embedded anchor is the release's,
    and the host must say so.

  It does not change the **transport** of the wallet's reads: account, storage
  and call data still come only from devp2p peers. But every one of them is
  verified against the store this source initializes, so for the root of
  trust it does count.
- **TrueBlocks Unchained Index mainnet publishing appears stalled.** The designated
  publisher (`publisher.unchainedindex.eth`) last published a mainnet manifest indexed
  to ~block 23.0M (mid-2025); as of mid-2026 that is ~a year behind the head, and the
  only newer on-chain entry is from an undesignated wallet whose content is not
  retrievable from IPFS. The `:tx-history` scan (debug-only) therefore misses all
  recent history — both its surfaces warn loudly about the gap. PLAN: the user intends
  to run their own index (TrueBlocks scraper) and add its IPFS peer address to Myotis;
  if you find evidence upstream publishing has resumed (a fresh manifest under the
  ENS-designated publisher), flag it to the user.
- **Portal Network is effectively dead.** Its reference clients are abandoned:
  the EF's own Trin client README states "THIS PROJECT IS NO LONGER ACTIVELY
  MAINTAINED" (https://github.com/ethereum/trin), and no one is actively
  continuing the network. (Note: ethereum.org docs may still list Trin/Fluffy as
  active — that is stale and not reliable.) Do NOT treat Portal as available
  infrastructure — anything Portal would have solved (deep historical
  state/blocks, a distributed state network as a SNAP fallback, etc.) must be
  solved another way. If you ever come across credible evidence that Portal has
  been revived or that someone is actively continuing it, FLAG IT TO THE USER
  IMMEDIATELY and prominently — the user wants to know right away because it would
  cover a lot of wallet needs.
