# Trust and data sources

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before adding any data source or touching roost, log-index seeds, `:tx-history`, the Swarm reader (`ant`, the addr1 index, the importer-key setting), or anything Portal would have solved.

## Trust

- Peer trusted is never an option everything has to be cryptographically verified
- The only trust anchors are sync committee signatures, the embedded
  pre-Merge historical hashes accumulator, the Bellatrix-era historical
  roots accumulator and the bundled checkpoint table (below)
- **The bundled checkpoint table (owner's decision D1, 2026-11-20;
  docs/ideas/deep-block-verification.md), Rust engine.** Per network,
  the hash of every 1024th block (entry i = block i*1024) from genesis
  up to a finalized block, committed as an asset whose keccak256 is
  pinned in the source; the loader refuses a table that does not match.
  It is built off-line by hashing every header and linking each by
  parentHash from that finalized block down to the network's genesis
  hash, its top cross-checked against a second, independent client.
  It is the release's word, as the embedded checkpoint is.
  - A block at or below the top is canonical when the headers from it
    up to the next entry (one GetBlockHeaders, at most 1024) hash-link
    to that entry. Above the top, today's window from the attested
    finalized block applies.
  - A walk that closes the gap between the attested finalized block
    and the top must end exactly at the top entry. A mismatch is an
    alarm that refuses every read resting on the table (-32602), never
    outvoted.
  - The table changes only in a PR that names its build (tool, source
    node, top, cross-check), extended at a release (releases.md). A
    running node never writes into it; hashes it linked to an attested
    finalized block may be kept in a local table beside it.
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
- **And one more (owner's decision, 2026-11-19):** the entries of an address's
  history read from the addr1 index on Swarm are candidates; each is shown as
  verified only after it is checked against verified chain data, and the
  list's completeness (and `TRACE` entries) rests on the importer whose key
  the user configured. Scope and limits: the carve-out under *Data sources*.
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
    and the host must say so. It must ALSO be confirmed by at least one
    LONG-KNOWN libp2p peer — pinned by peer ID in the release, or in this
    device's CL peer cache for at least a week — naming the same epoch and root
    in its Status (the eclipse guard; owner's ruling, #761, 2026-11-13). One
    naming another root for that epoch, or long-known peers that answer but
    never at the servers' epoch, refuse with no override. Only when no
    long-known peer answered at all is it refused as UNCONFIRMED and flagged;
    then only the user's explicit "use it anyway", every time, applies it —
    never a remembered choice.

  It does not change the **transport** of the wallet's reads: account, storage
  and call data still come only from devp2p peers. But every one of them is
  verified against the store this source initializes, so for the root of
  trust it does count.
- **Carve-out for Swarm reads of the address index (owner's decision,
  2026-11-19, the tracer bullet of docs/ideas/address-history-plan.md).** The
  Rust engine MAY read the published addr1 address index from Swarm, and
  nothing else from it. The format is eth2swarm's `docs/address-index.md` at
  commit `a1b3923` (https://github.com/biafra23/eth2swarm, branch
  `feature/address-index`); a later revision of the format needs this rule
  read again, it is not covered by it automatically.
  - **The reader is an embedded Swarm light node**: `ant`
    (https://github.com/freedom-hq/ant), linked into the engine, which reaches
    Swarm over libp2p. In production never a separate Swarm process or a local
    Bee/ant HTTP API (that stays the debug-only "local client over HTTP" of the
    rule above, usable for debugging as before), and never a Swarm HTTP gateway
    (one operator's server, which sees every request with the user's IP).
  - **Only where the reader runs.** Any engine or build without it (the Java
    and Go engines; a Rust engine built without `ant`, Android and iOS in the
    first version), the Rust engine without a configured importer key, and
    the Rust engine while Tor routing is on (the embedded node does not route
    through Tor, so its requests would carry the user's IP past the Tor
    setting) refuse the address history with the permanent `-32602`: never an
    empty list, never a reader of their own.
  - **What may be read**, in the spec's terms: `HeadRecord`s (the head feed's
    updates and the origin), `SliceRecord`s (slice descriptors) and
    `BucketRecord`s (buckets, inline or paged), all SOCs of the importer; and
    the content-addressed spill files and bucket pages files they reference.
    That is everything a lookup reads (the cover and the pending merges come
    from the head). Every chunk is checked before use: a content-addressed
    chunk against its address, a SOC against its address
    (`keccak256(identifier ‖ importer)`, so a peer cannot answer one request
    with another validly signed record) and its signature by the importer
    key, and every record by the decoder's canonical checks. Swarm is
    transport only.
  - **What it is trusted for**: an entry is a candidate, and has one of three
    states. *Verified* once Myotis has checked it against verified chain data
    (a header verified through the existing trust anchors, and the body or
    receipts, per role). *Contradicted* when that check fails (the address is
    not where its role says): shown as such, never as unverified and never
    dropped, and the answer says the importer key was contradicted. Else
    *unverified*. A header verified through the bundled checkpoint table
    (D1 of the plan, decided 2026-11-20: the anchor under *Trust*) counts as
    verified through the existing trust anchors. Completeness (an entry left out) and `TRACE` entries
    rest on the importer's word, as the seed carve-out's displayed balance
    rests on its publisher's; the answer says which block range rests on
    which importer key and names every range nobody covered as a gap, never a
    shorter list.
  - **Whose index**: for this first version the importer key is configured at
    runtime by the user (an experimental setting, labelled as trusting that
    importer), not pinned in a release; a pinned key, a key rotation and what
    follows a contradicted entry beyond showing it (stop trusting the key,
    warn, report) are open (D3/D4 of the plan).

  Three boundaries this carve-out does **not** cross:
  - **The address index only.** Block bodies, receipts, state or any other
    data on Swarm needs its own decision, even when the same embedded node
    could fetch it.
  - **The history list only.** The address history may list entries that are
    still unverified, labelled as such. No other read the engine serves (an
    account, a log, a block, a receipt) is answered from Swarm, or steered by
    the index in which blocks it fetches or skips: a log-index backfill or a
    transaction lookup that used it would make its completeness rest on the
    importer, in a method with no field to say so.
  - **Not a decision on the TrueBlocks plan below** (D5 of the plan stays
    open), and no sanction for an IPFS reader.
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
