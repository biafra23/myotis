# Seeded log histories for root-committing protocols

Status: owner ruling 2026-09-25, recorded in CLAUDE.md (*Trust*, *Data
sources*). Not yet a production path — see *Preconditions*. Companion to
[eth-getlogs-design.md](eth-getlogs-design.md) (the index a seed is imported
into), [logindex-verified-bundle-design.md](logindex-verified-bundle-design.md)
(the verified alternative, and why it does not reach mainnet) and
[railgun-poc.md](railgun-poc.md) (the first seed, built and measured).

## The ruling

A log index may serve a contract's history from an imported seed that myotis
did not walk, on the word of the protocol's maintainers who publish and vouch
for it, when the protocol's client rebuilds its note-commitment tree from the
logs and checks the root on-chain. Myotis walks and verifies everything above
the seed's top itself, as for any import (the head bridge and the appender,
eth-getlogs-design.md §Import). In the owner's words: the protocol bundles the
data and vouches for it; myotis just runs the updates.

This is publisher trust, and the rest of this document is about how far it
reaches. The client's root check keeps forged leaves out of its tree. It does
not make tampering visible: with RAILGUN's stock client, a seed that withholds
or alters a commitment leaves the wallet showing a wrong balance with no
error.

## Why not the walk

The verified routes do not reach mainnet history in practice. The walk is a
multi-day download before a wallet can show a balance (railgun-poc.md), and a
verified bundle is as large as the chain's receipts — the bundle design
estimates ~1 TB, unmeasured, for the Tornado and Privacy Pools range from
block 14.17M — because mainnet's `logsBloom` is saturated: with ~2,000+
elements per block setting 3 of 2,048 bits each, a query hits in ~85–95 % of
blocks even for an address that never appears, and each hit can only be
settled by the block's complete receipts (logindex-verified-bundle-design.md,
*What a file can prove* and *Where this pays*).

The logs themselves are small. RAILGUN's full mainnet history is ~426,000
logs framing to a ~243 MB index (railgun-poc.md) — the same class as the
Gnosis Bee index. What costs the terabyte is not the data but the proof that
no log was left out, and that proof is exactly what a seed does not carry.

## What the client's root check proves

A root commits to the exact leaf sequence. A client that inserts leaves only
when the resulting root is one the contract held never holds a forged leaf,
and never builds a spend against a fake tree. The check is an `eth_call`,
which myotis answers from verified state.

It does not prove the client holds every leaf, and with RAILGUN it does not
even report the ones it rejects. RAILGUN's contract records every root a tree
has ever had — `rootHistory[treeNumber][merkleRoot] = true` on each insertion,
never cleared (`contracts/logic/Commitments.sol:224`) — so a tree cut short
still has a valid root. The engine checks each batch as it inserts it
(`merkletree.ts:586-601`), and on a mismatch shrinks the batch, then stops
(`:778-789`); it places leaves only at their stated positions and stops at the
first one missing (`processWriteQueue`, "No commitment group for index"). So a
seed that **withholds, alters, inserts or reorders** a commitment stops the
tree at the last good batch. The engine records the rejection
(`invalidMerklerootDetails`) and does not advance its last-synced block, so it
re-reads the same seed next time — but its post-scan check
(`railgun-engine.ts:642-657`) validates the shortened tree, which passes, the
scan reports complete, and neither `@railgun-community/wallet` nor the
Terminal Wallet reads the recorded rejection. The balance is understated with
no error.

The one loud case is a whole tree gone: only tree 0's empty root is recorded
(`Commitments.sol:99`); `newTree()` records none for later trees
(`:230-241`), so an empty tree n ≥ 1 fails the post-scan check and the scan
reports incomplete.

A contract that keeps only recent roots does better: once the chain has moved
past its buffer, a stalled tree's root is no longer known and the check fails
loudly.

| protocol | on-chain check | old roots | client code, and whether it runs by default |
|---|---|---|---|
| RAILGUN (V2) | `rootHistory(tree, root)` | kept forever | `@railgun-community/engine`: per batch (`merkletree.ts:586`) and after every scan (`railgun-engine.ts:642-657`); **runs**, but a rejected batch truncates the tree silently |
| Tornado Cash | `isKnownRoot(root)` | ring buffer | kohaku `packages/tornado-cash/src/state/thunks/syncThunk.ts:46` → `verifyRootsThunk.ts:35`; **off** — `verify` defaults to `false` (`syncThunk.ts:28`) and `state-manager.ts:214` does not pass it |
| Privacy Pools | `currentRoot()`, then the 64 most recent roots | ring buffer | kohaku `packages/privacy-pools/src/state/thunks/syncThunk.ts:74` → `verifyRootsThunk.ts:35`; **runs** (`verify = true`, `syncThunk.ts:29`) |

Read at engine `6e2614d` (2026-06-18), kohaku `e3735d4` (2026-09-21) and
`Railgun-Privacy/contract` `36bcf5e`.

## What a seed controls

The rows below are for RAILGUN's stock client, the one a seed would serve
first.

| a seed that… | effect | reported? |
|---|---|---|
| withholds, alters, inserts or reorders a commitment | the tree stops at the last good batch: balance **understated** | no |
| sets `from_block` above the real deployment | the index answers `[]` below it without consulting coverage, so the tree misses its start: **understated** (tree 0 silently; a later tree left empty fails loudly) | only for a later tree |
| declares coverage past what it holds | myotis walks only above the declared top, so the gap is never walked: **understated** | no |
| stops early, with an honest top | none while the top is within 500,000 blocks of the finalized block: myotis walks the rest. Further back, it imports and never catches up (`BRIDGE_MAX_GAP`, measured from finalized, `el/reader.rs:622`) | — |
| replaces a Transact note's ciphertext | the note fails to decrypt or to re-hash to its leaf and is dropped (`wallet/abstract-wallet.ts:567-573`): **understated** | no |
| replaces a Shield note's `shieldKey` / `encryptedBundle` (event data, outside the leaf) | a note encrypted to the victim's viewing key — public in their 0zk address — appears as theirs: the Shield branch rebuilds it from the event's preimage and never checks that its `npk` derives from the wallet's own key (`abstract-wallet.ts:632-670`). A phantom, unspendable note: balance **overstated** | no |
| withholds a nullifier (RAILGUN `Nullified`) | a spent note looks unspent: balance **overstated**; the engine makes no on-chain nullifier check | no |
| withholds an `Unshield` | missing from the wallet's history and the POI status grouped from it; balances come from notes and nullifiers and are unaffected | no |

None of these lets a seed move funds or make a spend succeed: a spend proves
membership against a root the contract recognises, the contract rejects a
spent nullifier (`RailgunLogic.sol:500`), and a phantom note cannot be spent.
A spend built on a phantom note or a withheld nullifier fails — usually at gas
estimation, otherwise on-chain at the price of the gas. But a wallet showing a
wrong balance without an error is exactly what the coverage rules exist to
prevent, and with RAILGUN's stock client every row above is silent. Under this
ruling the displayed balance rests on the publisher in both directions.

## Closing the gap on the client

Most of that is detectable from state the client already has or can read
through myotis, and the stock clients do not look:

- **Rejected batches.** Treat a recorded per-batch rejection
  (`invalidMerklerootDetails`) as a failure instead of a stopping point. That
  turns altered, inserted and reordered commitments loud.
- **Events that cannot be placed.** Treat leftover commitments the engine
  could not insert ("No commitment group for index") as a failure. That turns
  any withheld commitment loud when a later one in the same tree follows it.
- **The open tree's tail.** Once synced to the head, compare the rebuilt root
  with `merkleRoot()` (RAILGUN) or `currentRoot()` (Privacy Pools) read at
  `latest`, retrying if a commitment lands in between.
- **A closed tree's tail.** A new tree starts when the next batch would not
  fit (`Commitments.sol:149`), so a closed tree's final length L satisfies
  L + (the next tree's first batch) > 2¹⁶. A client can detect any withheld
  tail longer than that one batch.
- **Nullifiers.** `nullifiers(tree, nullifier)` is public
  (`Commitments.sol:27`), so a client can confirm each note it holds is
  unspent with one `eth_call`.
- **Shield ownership.** Recompute `npk = poseidon(masterPublicKey, random)`
  (`note/shield-note.ts:45-47`) for each decrypted Shield note and drop it on
  a mismatch, as the Transact branches already do with their re-hash.

What would remain is a withheld tail shorter than one batch, and a real note
hidden by a replaced ciphertext, which no client can tell from a note that
was never addressed to it. Requiring these checks would bring the carve-out
close to the roost bar — withholding detected, not silently wrong. They are
not required today; whether to require them is the owner's call.

## Boundaries

- **The root check keeps forged leaves out; the publisher vouches for the
  rest.** The carve-out covers a contract whose client checks its rebuilt
  tree against an on-chain root, and only a client that actually runs the
  check. It does not widen into "any history its maintainers vouch for": a
  contract without an on-chain root, or a client that skips the check, keeps
  the walk (or, on Gnosis, a verified bundle).
- **The check belongs to the client, not to the index.** Any other consumer
  reading the same span over `eth_getLogs` — an explorer, an analytics job, a
  client that does not check roots — gets logs myotis did not verify and has
  no way to tell. That is what the provenance precondition below is for.

## Preconditions before a seeded history is a production path

1. **Provenance.** Seeded spans must be distinguishable from walked ones in
   `logindex-status` and on the hosts' Index tab. Today the engine serves
   them indistinguishably (eth-getlogs-design.md §Import, the
   provenance-marker follow-up). The RAILGUN PoC works around it with a
   per-flavour notice on its Index tab, which a regular host does not have.
2. **Shelf life.** A seed imported through the MLIX path must reach within the
   head bridge's span of the finalized block — at most 500,000 blocks
   (`BRIDGE_MAX_GAP`, `el/reader.rs`), about 69 days on mainnet — or it
   imports and never catches up. A published seed needs a refresh cadence
   inside that, with margin for finality lag. railgun-poc.md documents the
   limit for the PoC's seed (§Shelf life) and how a refresh can move a
   long-running index backwards (§Re-seeding).

## What this ruling does not decide

- **Whether this repo's tooling may generate a seed as a production path.**
  The ruling is about consuming a seed its protocol vouches for. Producing one
  from an operator's node over JSON-RPC is the open generator question in
  logindex-verified-bundle-design.md, which this leaves open. The RAILGUN
  PoC's seed is exactly that kind of fetch, so it stays a DEBUG / DEMO
  artefact (railgun-poc.md).
- **In-app download.** Unchanged: a seed reaches a host bundled at build time
  or imported deliberately by the user, never fetched by the wallet at
  runtime (the second open question in the same doc).
- **Whether to require the client-side checks** in *Closing the gap on the
  client*.
