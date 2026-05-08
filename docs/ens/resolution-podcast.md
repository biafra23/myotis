# ENS Resolution in Myotis — Podcast Script

A two-speaker walkthrough of how `resolve-ens vitalik.eth` works end-to-end
in the Myotis daemon. Speakers are tagged so a TTS pipeline can route
each line to a different voice.

- **ALICE**: host, asks the questions.
- **BOB**: engineer, explains.

---

## Cold open: the problem

[ALICE] Today we're going to walk through ENS resolution in Myotis. The thing
that turns "vitalik dot eth" into the 20-byte address. I want the full story.
Start me from first principles. Why is this hard?

[BOB] Sure. The naive answer is: ENS is a smart contract on Ethereum
mainnet, you call a function, it returns an address. If you have an RPC
endpoint, that's literally one `eth_call` to `resolver.addr(node)` and
you're done. Most wallets do exactly that.

[ALICE] So what's the catch.

[BOB] The catch is that those wallets are trusting somebody. Either an
Infura, an Alchemy, a self-hosted geth, or whatever public RPC you pointed
at. That endpoint is in the trusted computing base. They can lie. They can
return whatever address they want for "vitalik dot eth," and your wallet
sends funds there. There's no cryptographic verification step.

[ALICE] And Myotis doesn't want to trust an RPC.

[BOB] Right, and the project's CLAUDE dot md is explicit about it. Quote:
"Peer trusted is never an option, everything has to be cryptographically
verified. The only trust anchors are sync committee signatures and the
embedded pre-Merge historical hashes accumulator and the Bellatrix-era
historical roots accumulator." So we get state from peers, the peers might
be hostile, and every byte we use has to verify against those anchors or
we throw it away.

[ALICE] OK so we're rebuilding eth-call from scratch, but trustlessly. Walk
me through the layers.

[BOB] There are basically five things stacked on top of each other. Going
bottom-up: discovery, RLPx transport, the eth subprotocol, the snap
subprotocol, and on top of all that we run a local EVM that pulls state
from peers via snap and verifies it with Merkle Patricia proofs. ENS lives
in the EVM layer. It's just a bunch of view calls to specific contracts.

[ALICE] So before we get to ENS, we have to understand the local-EVM
machinery.

[BOB] Yep. The ENS resolver doesn't know it's running on a light client.
From its perspective an SLOAD is an SLOAD — it just so happens that under
the hood, the SLOAD turns into a snap-protocol request to a peer, which
returns the slot value plus a Merkle proof, which we verify against a
known-good state root.

---

## Section 1: ENSIP-1 namehash

[ALICE] Let's start with the data structure. ENS names. How do you go from
the string "vitalik dot eth" to something you can use as a contract key.

[BOB] ENSIP-1 namehash. It's a recursive keccak. You split the name on
dots, into labels, and for each label you keccak-256 the bytes of the
label to get a 32-byte label-hash. Then you fold those from the right.
Start with 32 bytes of zeroes — that's the namehash of the empty string,
which represents the root. Concatenate that with the label-hash of the
right-most label, keccak the 64 bytes, that's your new accumulator. Repeat
moving leftwards. Final accumulator is the namehash.

[ALICE] So for "vitalik dot eth," I'd label-hash "eth," fold it into zero,
then label-hash "vitalik," fold it into the result.

[BOB] Exactly. The implementation is in `myotis-evm/src/main/java/io/myotis/evm/ens/Namehash.java`.
About fifteen lines. The only subtlety is normalisation — ENSIP-15 says
you have to UTS-46 normalise the name before hashing, otherwise
"VITALIK.eth" and "vitalik.eth" hash differently and cause splits in the
namespace. Myotis does a lowercase pass; full UTS-46 is a bigger lift.

[ALICE] And empty labels?

[BOB] Rejected. The DNS encoder downstream — we'll get to that — has to
emit a length-prefixed wire form, and zero-length labels mean different
things in DNS than in ENS. We strip a trailing dot for FQDN tolerance, but
empty middle or leading labels are an error.

[ALICE] OK, so now I have a 32-byte node ID. What do I do with it?

---

## Section 2: the registry, the resolver, and the legacy path

[BOB] Classic ENS — pre-2022 — has two contracts. The Registry, at
zero-x-zero-zero zero-zero zero-zero zero-zero zero-zero zero-zero zero-zero
zero-zero zero-zero zero-zero zero-zero zero-zero zero-zero zero-zero zero-c-2
e-three-c-9-7. That contract maps namehash to "owner address" and "resolver
address." It's a registry — it doesn't know what the address is for the
name, it just knows which contract you're supposed to ask.

[ALICE] So step one: ask the Registry, get the resolver's address.

[BOB] `resolver(bytes32 node) returns (address)`. Step two: call
`addr(bytes32 node)` on that resolver. The resolver returns the actual
20-byte Ethereum address that the name points at. Two on-chain hops.

[ALICE] And the resolver could be any contract, as long as it implements
the right interface.

[BOB] Right. Most names use the public default resolver, but anyone can
deploy their own. That's how things like multi-coin records, content
hashes, and text records all work — they're just methods on the resolver,
not on the registry.

[ALICE] OK two hops. That's still recognisable as the path you'd take in,
say, web3-dot-js. So why is the new code more complicated?

[BOB] Two reasons. ENSIP-10, and ERC-3668. Wildcard resolution and
CCIP-Read. They came in to handle subdomains and off-chain names, and they
fundamentally changed how a wallet has to do a forward lookup.

---

## Section 3: ENSIP-10 wildcard resolution

[ALICE] Subdomains. Why are they hard?

[BOB] Imagine I own "alice dot eth" on the registry, and I want to give
out "anything dot alice dot eth" to all my friends without paying gas to
register each one. Without wildcards, every friend's namehash needs its
own registry entry pointing at a resolver. That's a per-subdomain SSTORE.
Doesn't scale.

[ALICE] So how does ENSIP-10 fix it.

[BOB] It says: when the wallet looks up "bob dot alice dot eth" and
doesn't find a registry entry for it, fall back to walking the parent
chain. Look up "alice dot eth," find its resolver, and ask that resolver
about the child. The resolver gets a single function called
`resolve(bytes name, bytes data)`. The first argument is the DNS wire-format
of the full child name; the second is the inner calldata, like the bytes
you'd have sent for `addr(bytes32)` if you were doing it directly. The
parent resolver decides what to return.

[ALICE] So the parent resolver becomes a kind of mini-server.

[BOB] Exactly. It can implement whatever logic it wants — derive the
address from the label, look it up in its own storage, fetch from a
backend, sign a delegation to a separate signer, anything. The wallet
doesn't care. As far as it's concerned, you call `resolve(name, data)` and
out comes the same answer you would have gotten from `addr(node)` on a
registered resolver.

[ALICE] But it's the wallet's job to figure out which contract to send
that `resolve` call to. That sounds annoying — you'd have to walk the
parent chain yourself. Try the full name, then strip a label, try the
parent, then strip again.

[BOB] Right. Which is where the next contract comes in.

---

## Section 4: the Universal Resolver

[ALICE] OK, the Universal Resolver.

[BOB] Mainnet pin: zero-x c-e-zero-one-f-eight-e-e-e-seven-E-four-seven-nine
C-nine-two-eight F-eight-nine-one-nine-a-b-D-five-three E-five-five-three
a-three-six-C-e-F-six-seven. It's a single contract that does the parent-walk
for you. You call its `resolve(bytes name, bytes data)`, hand it the full DNS
wire-format of "bob dot alice dot eth" and the inner calldata for `addr`,
and it figures out internally — does the registry have a resolver for the
full name? No? Walk to "alice dot eth," check there, yes there's a
resolver, dispatch the call against it. It also handles the legacy path
where the resolver only implements `addr(bytes32)`, by introspecting the
resolver's interface support.

[ALICE] So from the wallet's point of view, ENS resolution collapses back
into one on-chain call.

[BOB] Yep. `universalResolver.resolve(dnsName, addrCalldata)`. That's it.
The Universal Resolver returns a tuple of `(bytes result, address resolver)`,
where `result` is the ABI-encoded inner return — a 32-byte address for
`addr` calls — and `resolver` is the address of whichever resolver
contract actually answered. The wallet decodes `result` as if it had
called `addr` directly.

[ALICE] So the file `myotis-ens/src/main/java/io/myotis/ens/EnsResolver.java`
just calls that one method.

[BOB] Exactly that. The whole forward-resolution `resolveAddress` method
fits in about thirty lines once you strip the comments. Build the DNS
wire-name. Build the inner `addr(bytes32)` calldata. Wrap it in a
`resolve(bytes, bytes)` outer call. Send it as a view call. Decode the
result.

[ALICE] But "view call" is doing a lot of work in that sentence.

[BOB] It is. Because there's the third complication, which is that the
view call can revert with a special revert that means "I can't answer
this on-chain, fetch from this URL and call me back."

---

## Section 5: ERC-3668 CCIP-Read

[ALICE] OK now we're at CCIP-Read. Walk me through the motivation.

[BOB] Take Coinbase IDs. Coinbase wants to give every Coinbase user a
free ENS subdomain — "alice dot c-b dot id" or similar. They have
literally millions of users. Putting one record per user on Ethereum
mainnet at thirty bucks of gas a pop is a non-starter. So they store the
records on their own backend. The on-chain piece is just a tiny adapter
contract.

[ALICE] But then it's not on-chain at all. Why is it ENS?

[BOB] Because there's a verification step. ERC-3668 — the spec known as
CCIP-Read — defines a protocol where the on-chain contract can revert
with a specific selector called `OffchainLookup`, and that revert payload
contains: the sender expected to receive the response, a list of HTTP
URLs to try, the calldata to send to those URLs, a callback function
selector on the sender, and an opaque blob of "extra data" that the
contract wants echoed back.

[ALICE] So the wallet sees the revert, fetches from one of the URLs, and
then calls the contract back with the response.

[BOB] With both: the response and the extra-data blob. The callback is
called `callbackFunction(bytes response, bytes extraData)`. Inside the
callback, the contract verifies the response — and this is the part that
matters — usually by checking a signature in the response against an
authorised signer. So the off-chain server can't just lie. It has to
sign its replies with a key that the on-chain contract recognises. The
contract then returns the address, the wallet decodes it, done.

[ALICE] So it's hybrid. Off-chain bandwidth, on-chain verification.

[BOB] Right. And the wallet's role is just to be a transparent relay.
It sees the revert, fetches the URL, re-enters the contract with the
response. From the contract's point of view, it's like the user did two
calls; from the user's point of view, they did one call and got an
answer.

[ALICE] You said "one of the URLs." What's the routing logic.

[BOB] If the URL template contains the placeholder `{data}` you do a GET
with substitutions; otherwise you POST with a JSON body of `{"sender":
"zero-x...", "data": "zero-x..."}`. The wallet tries the first URL, on
HTTP error or 4xx falls through to the next. Five hundred errors are
treated as transient and retried. The spec is in section six of ERC-3668.

[ALICE] And the recursion.

[BOB] Yeah, the callback can itself revert with another OffchainLookup,
in principle. A naive implementation would loop forever. The plan caps
recursion at one — `CcipReadHandler.MAX_RECURSION_DEPTH = 1` — which is
enough for the corpus we care about and prevents the kind of pathological
behaviour you'd get with a hostile resolver.

---

## Section 6: the executor decorator stack

[ALICE] OK that's all the protocol stuff. Now let me get into the code.
You said earlier there's a stack of executors. Walk me through it.

[BOB] Three layers. Inside-out: `DefaultEvmExecutor`, then
`PrefetchingEvmExecutor`, then `CcipReadEvmExecutor`. They all implement
the same `EvmExecutor` interface — which has just two methods,
`callView` and `estimateGas` — and they decorate one another. The wallet
constructs them like nesting dolls.

[ALICE] So at the bottom, `DefaultEvmExecutor`.

[BOB] That's the one that actually runs Besu's EVM. Hyperledger Besu's
EVM module — `org.hyperledger.besu:evm:24.12.2` — exposes a `WorldUpdater`
interface that any client can implement. We implement it. Our
implementation is `SnapWorldUpdater`, and it's backed by a per-call cache
called `SyncStateView` that talks to a `SnapStateOracle` underneath.

[ALICE] So when the EVM does an SLOAD…

[BOB] It calls into `SnapWorldUpdater.getStorageValue(account, slot)`,
which calls `SyncStateView.storageAt(...)`, which checks its cache, and
on a miss calls `SnapStateOracle.fetchStorage(stateRoot, account, slot)`,
which talks to a real peer over snap, gets the value plus a proof, runs
the proof through `MerklePatriciaProofVerifier` in the core module, and
on success returns the verified value.

[ALICE] And if the proof doesn't verify.

[BOB] We throw `EvmExecutionError.InvalidProof`. The executor surfaces it
as a failed `CompletableFuture` and the call dies.

[ALICE] OK what's the prefetcher for.

---

## Section 7: PrefetchingEvmExecutor and the convergence loop

[BOB] Performance. The naive flow I just described — every SLOAD hits the
network — is correct but slow. A single ENS resolution does dozens of
SLOADs. Each one is one round trip to a peer. On a household connection,
fifty SLOADs at fifty milliseconds each is two and a half seconds of
sequential network time. Unusable for a wallet.

[ALICE] So the prefetcher batches.

[BOB] Yeah. The trick is: most of those SLOADs are predictable. If the
contract reads slot zero, then slot one, then slot two, you can fetch all
three in one snap request. The hard part is figuring out which slots
without actually running the EVM.

[ALICE] Which means you have to run the EVM.

[BOB] Right, which is the bootstrap problem. You can't know which state
you need until you run, but you can't run until you have the state. The
solution is the convergence loop. Run the EVM once with whatever state
you have, observe what state was accessed, fetch all that state in
parallel, then run again. Repeat until two consecutive runs produce the
same result. That's "convergence."

[ALICE] How do you run before you have the state?

[BOB] This is where sentinel-return comes in. There are two flavours of
this. The original design was called trace-based — you wrap Besu's EVM
with an `OperationTracer` that records every storage access into a
`ConvergenceTracker`, and on a miss the EVM blocks waiting for the value.
That ends up being mostly synchronous, because the EVM is sequential and
has to wait for the value to make a control-flow decision.

[ALICE] And sentinel mode.

[BOB] In sentinel mode, on the first iteration, every state read returns
zero immediately — the sentinel value — and we record that the slot was
accessed. The EVM runs to completion against zeros. The result is
probably wrong, because the contract took different branches than it
would have with real values, but we don't care about the result on
iteration zero. We care about the *access set*. After the run, we have a
list of every slot the contract touched. We fetch all of them in parallel
in one or two snap round trips. Iteration one: re-run with real values
in the cache. If the access set is stable, the result of iteration one
is correct and we return it. If iteration one accessed slots that
iteration zero didn't see — maybe a branch took a different path now
that it has real values — we fetch those too and run a third iteration.
Bounded retries; cap is four.

[ALICE] Why does it converge.

[BOB] Because each iteration's access set is a superset, modulo cache
hits, of the previous iteration's. The contract can only touch slots it
can name, and the names come from the calldata plus the slots it's read
so far. Once you've fetched everything reachable, no new accesses
appear and the loop exits.

[ALICE] What if the contract is non-deterministic? Block-timestamp-keyed,
or something.

[BOB] Block context — `BlockContext` in `myotis-evm/src/main/java/io/myotis/evm/BlockContext.java`
— is fixed for the whole resolution. State root, block number, timestamp,
prevrandao, baseFeePerGas, chain ID, gas limit. We pin it once at the top
of the call and pass it down. So the EVM sees the same `block.timestamp`
every iteration. There's no source of nondeterminism inside the EVM
itself.

[ALICE] Where's this coded.

[BOB] The convergence loop is `PrefetchingEvmExecutor.callView`. The
sentinel-return wiring is in `SyncStateView` — there's a flag that
toggles between "block on miss" and "return zero on miss, record access."
First iteration runs in sentinel mode. After the run we walk the access
set and call the oracle once in batched form. Subsequent iterations run
in block-on-miss mode but the cache is hot, so they don't actually block.

[ALICE] So in the happy case it's two iterations. One sentinel, one real.

[BOB] Two iterations, two snap round trips total. Maybe one snap round
trip if all the slots fit in a single GetStorageRanges. ENS resolution
usually converges in two.

---

## Section 8: CcipReadEvmExecutor — the outer decorator

[ALICE] OK and the outermost decorator is for CCIP-Read.

[BOB] Right. `CcipReadEvmExecutor.callView(target, calldata, blockContext)`
is implemented as: call the delegate — which is `PrefetchingEvmExecutor`
— and if it succeeds, return the result. If it fails with an
`EvmExecutionException` whose error is a `Reverted`, look at the revert
payload. If it parses as `OffchainLookupRevert`, we're in CCIP-Read
territory: fetch from the URLs, build the callback calldata, and re-enter
the EVM with the same decorator instance — so a chained CCIP-Read on the
callback also gets handled.

[ALICE] What's `OffchainLookupRevert`.

[BOB] Just a record. Five fields: the sender to call back into, the URL
list, the inner-call data the URLs should answer, the four-byte callback
selector, and the extraData blob. Decoded from the revert payload using
the standard CCIP-Read selector,
`zero-x-five-five-six-f-one-eight-three-zero` followed by the ABI tuple.
The parser is in `myotis-evm/src/main/java/io/myotis/evm/ccipread/OffchainLookupRevert.java`.

[ALICE] And then the gateway fetch.

[BOB] Done by `CcipReadHandler` against a pluggable `CcipGateway`
interface. The interface is intentionally tiny — one method, "send a
GET or POST to a URL, return the body as a string, async." That keeps
`myotis-evm` free of any HTTP-client dependency. The wallet integration
provides the transport. On the daemon side, the new `JavaHttpCcipGateway`
inside `CommandHandler` uses Java's built-in `java.net.http.HttpClient`.
On Android we'll use Ktor, because java-dot-net-dot-http isn't available
below API 33.

[ALICE] Why is the decorator on the outside, not in the middle.

[BOB] Because OffchainLookup can only be observed at the call boundary,
not during execution. The EVM doesn't know it reverted with a special
selector — to it, a revert is a revert. You only see the data after the
call returns. So you have to be the outermost layer that sees the failed
call's revert payload. If you put CcipRead inside Prefetching, the
prefetcher would see "the call reverted" and either bail out or retry,
neither of which is right.

[ALICE] So execution flow on a CCIP-Read name. The wallet calls
universalResolver-dot-resolve. Universal Resolver dispatches to a Coinbase
adapter. Adapter reverts with OffchainLookup. We catch that. We fetch from
Coinbase's URL. We re-enter the EVM with the resolver's callback selector
plus the response plus the extraData. The callback verifies the
signature, returns the address, we decode.

[BOB] That's the whole dance. And the prefetcher still works underneath
the second call — the callback re-enters the same decorator, so
`CcipReadEvmExecutor` recurses, and inside that recursion the
PrefetchingEvmExecutor runs the convergence loop again to fetch whatever
storage the callback's signature-verification logic needs.

[ALICE] And the recursion cap protects you from a hostile contract that
just keeps reverting with new OffchainLookups.

[BOB] Yeah. Depth one. After that we fail with a
`CcipGatewayFailed` error.

---

## Section 9: SnapBackedStateOracle — fetching state with proofs

[ALICE] We've talked about the EVM layer. Now let's go down to where the
state actually comes from.

[BOB] `SnapBackedStateOracle`. It implements the `SnapStateOracle`
interface, which is what the EVM layer talks to. Methods are
`fetchAccount(stateRoot, address)`, `fetchStorage(stateRoot, address,
slot)`, and `fetchBytecode(codeHash)`.

[ALICE] So a single account fetch.

[BOB] We send a `GetAccountRange` snap-protocol message to the peer with
a single-account range — actually, GetAccountRange requires a hash range,
so we set both the start and limit to the keccak of the address, which
covers exactly one slot. The peer responds with `AccountRange`, which
contains the matching account if it exists, plus a Merkle Patricia proof
that anchors the result back to `stateRoot`.

[ALICE] How does the proof work.

[BOB] An MPT proof is a list of RLP-encoded trie nodes, ordered from the
root downward. To verify, you start at the root node — its hash should
equal `stateRoot`. You decode it; depending on whether it's a branch,
extension, or leaf, you walk one nibble of the search key into a child.
The child's hash is in the parent node, so you find the next node in the
proof list whose hash matches that child reference. Continue until either
you reach a leaf containing the value, or you hit a child reference that
points at an empty subtree, in which case the value is "not present" —
also a valid result.

[ALICE] You verify "not present" too.

[BOB] Has to be. Otherwise a malicious peer could just say "no such
account" and get away with it. The proof has to demonstrate that there is
no path from root to leaf for that key, which is just an honest
exploration that hits an empty branch. The verifier in the core module
distinguishes "key found, value is X" from "key absent" from "proof is
malformed."

[ALICE] And the verifier.

[BOB] `core/src/main/java/com/jaeckel/ethp2p/core/trie/MerklePatriciaProofVerifier.java`.
About 150 lines of Java. Hand-rolled, because the Tuweni Merkle Trie
artifact didn't resolve from the ConsenSys Maven repo at the time we
needed it. Pure functional verifier — input is the expected root, the
key, and the proof list; output is the value bytes or null. No external
dependencies beyond Bytes and RLP.

[ALICE] And on a verification failure.

[BOB] We mark that peer's snap as failed, throw
`EvmExecutionError.InvalidProof`, and either fall through to the next
peer or surface to the user. The retry budget is in
`SnapBackedStateOracle` — three peers by default.

[ALICE] What about bytecode.

[BOB] Different message. `GetByteCodes` takes a list of code hashes and
returns the bytecode bytes. Verification is just: keccak of the returned
bytes must equal the requested hash. No Merkle proof needed because the
hash itself is the commitment. We cache verified bytecode in a
`BytecodeCache` so multiple calls into the same contract within a session
don't re-fetch.

[ALICE] And storage slots.

[BOB] `GetStorageRanges` takes an address and a slot-hash range. Same
shape as accounts: returns matching slots plus an MPT proof, this time
against the contract's storage root rather than the global state root.
The verifier doesn't care which root — it's the same MPT primitive. Note:
the proof verifies against the storage root, but the storage root itself
needs to come from the account, which needed its own MPT proof against
the global state root. So a single SLOAD is actually two layered proofs.

[ALICE] Both verified.

[BOB] Both verified. End to end, the only thing we trust is `stateRoot`,
and that comes from a header that was either consensus-verified — sync
committee signature on a beacon block whose body commits to that
execution header — or transitively from a header chain anchored to a
consensus-verified one.

---

## Section 10: BlockContext, and why we use the chain head

[ALICE] You mentioned earlier that for the daemon ENS command, we use the
peer's chain head, not the beacon-finalized header. Why.

[BOB] Practical constraint. Peers prune state. Geth, Besu, Erigon — they
all default to keeping roughly 128 blocks of state for snap-serving
purposes. After that the state for old blocks is no longer reachable.
Beacon finality is twelve and a half minutes — sixty-four slots of twelve
seconds. That's around fifty-eight blocks of execution lag, which is
inside the pruning window most of the time, but not always. And every
beacon-state-root also needs a forward-fetched header chain to map back
to an execution-state-root, which adds latency.

[ALICE] So if you ask for the finalized state, the peer will often say
"sorry, pruned."

[BOB] And then you fall through to another peer, and another. It works
eventually, but it's slow and unreliable. The chain-head root, on the
other hand, is by definition fresh — the peer just told us about it via
the eth Status message — and it's the root they're actively serving snap
requests against.

[ALICE] But the chain head isn't beacon-verified.

[BOB] No. It's whatever the peer claims. So in principle a hostile peer
could feed us a forged head that points at fake state. The mitigation is
that everything underneath still verifies against the head's state root.
A hostile peer would have to forge consistent MPT proofs for every slot
we read, which means producing a state trie whose root matches the head
they sent. That's not impossible — the peer could just spin up a fake
chain and serve coherent state from it — so for "send funds to the
result" use cases, you need the head to be anchored.

[ALICE] So this is fine for ENS resolution but not for, say, signing a
transaction that depends on the result.

[BOB] Right. ENS resolution itself reads a small number of slots in
contracts whose code is well-known and whose state changes infrequently.
If a peer feeds us a fake "vitalik dot eth resolves to attacker dot eth,"
the wallet can do an additional ENSIP-3 verification round — resolve the
returned address back to a name and check it points at "vitalik dot eth"
— but that's a forward-then-reverse loop that's only meaningful if the
forward and reverse use independent state roots. Truly trustless ENS
resolution requires anchoring the head against beacon finality.

[ALICE] And we don't do that yet.

[BOB] We don't do it in the daemon resolve-ens command yet. Phase 0
through 4 of the EVM module is the building blocks; the wallet
integration is where head-anchoring lives. That's the missing layer for
production.

[ALICE] OK so for now the daemon's resolve-ens is "approximately right
when the peer is honest." Useful as a smoke test.

[BOB] Useful as a smoke test, useful as a developer tool, not yet useful
as a wallet primitive. The point of the command is to prove the EVM stack
works against real network state — the resolution has to traverse
Universal Resolver, the registry, a real resolver contract, and possibly
a CCIP-Read gateway, all using state served from a real peer. If that
works, the EVM module is correct. Anchoring is a thin layer on top.

---

## Section 11: the daemon resolve-ens command

[ALICE] Let's put it all together. I run `gradlew :app:run` to start the
daemon. Discovery finds peers, RLPx connects, the eth handshake completes,
some of those peers also negotiate snap. Now I run
`gradlew :app:run -Pargs="resolve-ens vitalik.eth"`. Walk me through
what happens inside CommandHandler.

[BOB] First, dispatch. The IPC server hands the JSON line to
`CommandHandler.handle`, which switches on `cmd` and calls
`handleResolveEns`.

[ALICE] Step one inside that method.

[BOB] Pick a snap-capable peer. We call
`connector.activeSnapHandlers()` — which is the new accessor I added —
and that returns a snapshot of all `EthHandler`s that are READY, have
negotiated snap-slash-one, and aren't flagged as snap-serving-failed. We
take the first one. There's no fancy load-balancing — the
`SnapBackedStateOracle` will rotate to the next on `InvalidProof` or IO
failure, so this is a "first attempt, oracle handles fallback" design.

[ALICE] Step two.

[BOB] Build the BlockContext. We grab `connector.getChainHead()` for the
latest known block number. Then we call `connector.requestBlockHeaders`
with that block number and count one. The peer returns a single
`BlockHeader` record. From it we extract the state root, block number,
timestamp, base fee, prev-randao, gas limit, beneficiary — that becomes
the EVM's `block.coinbase` — and we get the chain ID from
`connector.getNetwork().networkId()`. All seven get plugged into a
`BlockContext` constructor.

[ALICE] Step three.

[BOB] Wrap the EthHandler as a SnapPeer. There's a small adapter,
`EthHandlerSnapPeer` in `app/src/main/java/com/jaeckel/ethp2p/app/snap/EthHandlerSnapPeer.java`,
that translates between the SnapPeer interface — which lives in
myotis-evm and only knows about `getTrieNodes` and `getByteCodes` — and
the EthHandler's request methods. The reason it lives in app and not in
myotis-evm is that myotis-evm doesn't depend on networking. Adapter sits
at the seam.

[ALICE] Step four, build the executor.

[BOB] Construct from inside out. `SnapBackedStateOracle` takes a supplier
that returns a SnapPeer plus a BytecodeCache. `DefaultEvmExecutor` takes
the oracle plus its own bytecode cache plus a single-thread executor for
the EVM run. Then `PrefetchingEvmExecutor` wraps that. Then a
`CcipReadHandler` constructed against the `JavaHttpCcipGateway`. Then
`CcipReadEvmExecutor` wraps the prefetching executor with the handler.
Five lines of constructor calls.

[ALICE] Step five.

[BOB] Construct an `EnsResolver` against that executor. Call
`resolveAddress(name, blockContext)`. The resolver builds the namehash,
the DNS encoding, the inner `addr` calldata, the outer `resolve` calldata,
and calls `executor.callView(universalResolver, calldata, blockContext)`.

[ALICE] And then everything we just discussed kicks in. CcipReadEvmExecutor
sees the call. Forwards to PrefetchingEvmExecutor. PrefetchingEvmExecutor
runs Besu in sentinel mode. Records access set. Fetches everything via
SnapBackedStateOracle. Re-runs in cache mode. Returns the result. If the
result was an OffchainLookup revert, CcipReadEvmExecutor catches it,
fetches from the gateway, re-enters with the callback calldata, recurses
into PrefetchingEvmExecutor again.

[BOB] Right. And eventually `resolveAddress` returns an
`Optional<Address>`. We block on it with a sixty-second timeout — this is
inside a request-handler thread, blocking is fine — and serialise the
result as JSON.

[ALICE] What about the timeout.

[BOB] Sixty seconds is generous because CCIP-Read can involve a fetch to
some random gateway that might be slow. For a pure on-chain name like
"vitalik dot eth," the resolution should be under two seconds end-to-end
on the second snap-fetch convergence iteration.

[ALICE] And shutdown.

[BOB] The single-thread executor we constructed for the EVM run gets
shut down in a `finally` block, so we don't leak threads. The
`JavaHttpCcipGateway` reuses a static HttpClient — its lifetime is the
JVM's, no explicit shutdown.

---

## Section 12: testing and observability

[ALICE] How do we know any of this works.

[BOB] Three tiers. Unit tests in `myotis-evm/src/test/java/io/myotis/evm/`.
They use a `FixtureSnapStateOracle` that holds a hand-built world — a
list of accounts, contracts, bytecode, storage — and serves snap-style
results without actually doing any networking or proof verification.
That's how `EstimateGasTest` runs in CI. Tests for the resolver itself
live in `myotis-ens/src/test/java/io/myotis/ens/`, with mock executors.

[ALICE] Tier two.

[BOB] Integration tests in `myotis-evm/src/integrationTest/java/io/myotis/evm/integration/`.
Env-gated — they only run if `MYOTIS_MAINNET=1` and a few other
environment variables are set, including `MYOTIS_INTEGRATION_PEER_ENODE`,
a recent `MYOTIS_INTEGRATION_STATE_ROOT`, and so on. They connect to a
real mainnet peer, run a real resolution against a real state root, and
compare against a known reference value. There's an ENS-resolution IT,
a gas-estimation IT, a call-view IT.

[ALICE] You said those don't run yet.

[BOB] They have a `connectToMainnetPeer` stub that throws
`UnsupportedOperationException` because the bootstrap code hasn't been
extracted from `Main.main` yet. Once that's done, the integration tests
run end-to-end against mainnet.

[ALICE] Tier three.

[BOB] The daemon command we just built. Operator-driven, not automated.
You run the daemon, run `resolve-ens vitalik dot eth`, eyeball the
result. It's a smoke test for the integration of all the layers in a
real running process. The reason this matters is that the unit tests use
a fixture oracle, the integration tests are gated and not yet wired up,
and there was previously no way to actually exercise the whole stack
against live state. Now there is.

---

## Section 13: reverse resolution and ENSIP-3

[ALICE] We talked about forward resolution. Briefly — what about reverse?
Address to name.

[BOB] Reverse is in the same `EnsResolver` class. It's harder than
forward in one specific way: forward is "I trust the user typed
vitalik dot eth, give me the address they meant." Reverse is "this
address claims to be vitalik dot eth, prove it." A malicious smart
contract could set its own reverse record to claim it's
vitalik dot eth. So you need ENSIP-3 verification.

[ALICE] Walk me through it.

[BOB] Three steps. One: take the address, hex-encode it lower-case
without zero-x prefix, append "dot addr dot reverse," and namehash that
string. That's the reverse-record node ID. Two: ask the registry for the
resolver of that node ID. Three: call `name(bytes32)` on that resolver,
which returns a string — the claimed name. Step four, the
verification: take that claimed name and forward-resolve it. If the
forward resolution returns the same address you started with, the claim
is valid. If it returns a different address, or empty, you reject the
claim and return Optional-empty.

[ALICE] So reverse is more expensive. Two on-chain lookups for the claim,
then a full forward resolution to verify.

[BOB] And the forward resolution itself can hit CCIP-Read. The plan
calls out switching to the Universal Resolver's `reverse()` method as a
future refinement; right now we go through the legacy registry path
because the ENSIP-3 verification round-trip was the harder part to get
right and it works against the old path.

[ALICE] Is reverse exposed in the daemon?

[BOB] Not yet. Same shape as forward — it'd be a `reverse-ens` IPC
command. Five lines of glue.

---

## Section 14: design choices and tradeoffs

[ALICE] Let me ask about a few design choices. Why decorator pattern?
Why not just bake CCIP-Read and prefetching into DefaultEvmExecutor?

[BOB] Composability. Each decorator does one thing. You can use
`DefaultEvmExecutor` alone for tests where you don't want prefetching.
You can use `DefaultEvmExecutor` plus `PrefetchingEvmExecutor` for
internal calls where CCIP-Read isn't needed. You can use the full stack
for ENS resolution. And — this is the bigger reason — each layer's
behaviour is locally checkable. If you bake them together, the test
matrix explodes. With the decorator pattern, the prefetcher's correctness
is independent of CCIP-Read's correctness, and you test them in isolation.

[ALICE] And the price.

[BOB] Two `CompletableFuture` allocations per call, more or less. A bit
more verbose construction. The construction lives in one place — the
wallet integration — so the verbosity is bounded.

[ALICE] Why is the SnapPeer interface in myotis-evm rather than
networking.

[BOB] Because myotis-evm has to be Android-friendly. It's the wallet's
local EVM machinery, and the Android module consumes it directly. The
networking module pulls in Tuweni, Netty, BouncyCastle, libp2p, eventually
discv5 — all the wire-protocol stuff. The Android consumer doesn't want
that on the classpath unless it's running its own peer. So myotis-evm
defines a tiny pluggable interface, and the wallet supplies the transport.
The daemon supplies an EthHandler-backed implementation. A future
Android wallet might supply, I don't know, a remote-light-client-backed
implementation that pulls state from a service running on the phone or
on a server it trusts.

[ALICE] Same shape as the CcipGateway interface.

[BOB] Same idea. myotis-evm doesn't import HttpClient. CcipGateway is one
method. JavaHttpCcipGateway lives in app. A future Android wallet would
ship a Ktor-backed implementation. Decoupling cost: minor; future-proofing
benefit: you can target Kotlin Multiplatform without ripping out the
core.

[ALICE] You mentioned Kotlin. The code is Java now.

[BOB] Java seventeen for most modules, Java twenty-one for myotis-evm and
networking — Besu's EVM jar publishes module metadata that says "JVM-21
floor," and the discv5 library similarly. Long-term direction is a
Kotlin migration to enable Compose Multiplatform consumers. New code can
land in Java where it lowers risk; the public API is the constraint.
That's why none of the public APIs in myotis-evm leak
`CompletableFuture` types that wouldn't translate cleanly to suspending
functions in Kotlin.

[ALICE] Last question. Why hand-roll the MPT verifier? Why not use
Besu's?

[BOB] Two reasons. Besu's MPT verifier is wrapped up in Besu's broader
worldstate machinery — pulling it out cleanly would have meant taking a
much bigger dependency surface. And the verifier is small. A hundred and
fifty lines of pure functional Java that takes a root, a key, and a
proof list, and either returns a value or null. It's testable in
isolation, and it's easier to audit than a transitive dep. There's a
cost — duplication — but the maintenance burden has been low so far.

---

## Closing

[ALICE] OK so to summarise. ENS resolution in Myotis is: namehash the
name, DNS-encode the name, build calldata for `addr` wrapped in a
`resolve` outer call, send it as a view call to the Universal Resolver.
The view call goes through three decorator layers — CcipRead handles
off-chain lookups, Prefetching does the convergence loop to batch state
fetches, and Default actually runs Besu. Default reads state via a
SnapStateOracle that turns each EVM read into a snap-protocol fetch,
verified with a Merkle Patricia proof against a state root pinned in the
BlockContext. The state root comes from the peer's chain-head header for
now, with beacon-anchoring as future work. The whole thing is glued
together by the daemon's resolve-ens IPC command, which runs the stack
once per resolution against a snap-capable peer.

[BOB] That's the picture. The interesting work is in the decorator stack
and the convergence loop. Everything else is plumbing. And the plumbing
is mostly small pluggable interfaces — SnapPeer, CcipGateway,
SnapStateOracle — so the same code can run on the daemon today and on an
Android wallet later, with different transports underneath.

[ALICE] Thanks Bob.

[BOB] Anytime.

---

*End of script.*

## Producing audio

For TTS, this script is laid out so a tiny splitter can route each
`[ALICE]` and `[BOB]` line to a different voice. If you want to render
locally with espeak:

```bash
awk '/^\[ALICE\]/{voice="en+f3";sub(/^\[ALICE\] /,"")} /^\[BOB\]/{voice="en+m3";sub(/^\[BOB\] /,"")} /^\[/{print voice"|"$0}' \
  docs/ens/resolution-podcast.md \
  | while IFS='|' read voice line; do espeak -v "$voice" "$line"; done
```

For ElevenLabs or OpenAI TTS, build per-line API requests with the speaker
tag selecting a voice ID, then concatenate the resulting MP3 / WAV blobs.
