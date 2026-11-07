# Myotis Rust Tour 1.0

A guided reading of every Rust file in the Myotis workspace, for a developer who knows Java and Kotlin and is still building a feel for Rust's memory model. Each stop explains one part of the code through verbatim excerpts, teaches the Rust concepts those excerpts use, and ends with a checkpoint.

- **Pinned to commit `5263a421`.** Every excerpt is cut from that commit with its real line numbers, so `git show 5263a421:rust/<path>` finds it again. Paths of other documents in the text are as they were then (the docs have since been grouped into folders).
- **24 stops, 293 checkpoint questions, about 56 hours of reading.** Read it front to back; [Stop 0](00-map.md) ends with the full route in legs of a few hours, with each workbook exercise placed after the stop it practises.
- **Checkpoints** are static here: decide on your answer, then follow *Answer →* to [the answers](answers.md). The interactive HTML edition grades and tracks them.
- **Other editions**, built from the same sources in [`../source`](../source/): an offline HTML page with graded quizzes and saved progress, and an EPUB. See [the tour's README](../README.md).

## Contents

**Orientation**

- [Stop 0 · Start here: the map](00-map.md)
- [Stop 1 · Rust's memory model for JVM developers](01-primer.md)
- [Stop 2 · The workspace: crates, features and profiles](02-workspace.md)

**Pure foundations**

- [Stop 3 · myotis-bls: BLS through blst](03-bls.md)
- [Stop 4 · myotis-core: bytes, hashes and tries](04-core.md)
- [Stop 5 · myotis-wire: the protocols as pure functions](05-wire.md)
- [Stop 6 · myotis-consensus: the light client as a state machine](06-consensus.md)
- [Stop 7 · myotis-evm: an EVM over verified state](07-evm.md)
- [Stop 8 · myotis-evm, part 2: simulation, tracing and fixtures](08-evm-sim.md)

**myotis-net: all the I/O**

- [Stop 9 · myotis-net, part 1: libp2p, req/resp and discovery](09-net-cl.md)
- [Stop 10 · myotis-net, part 2: the light-client sync loop](10-net-sync.md)
- [Stop 11 · myotis-net, part 3: execution-layer peers](11-el-transport.md)
- [Stop 12 · myotis-net, part 4: the peer pool and the trust chain](12-el-pool.md)
- [Stop 13 · myotis-net, part 5: EVM bridge, log index and transactions](13-el-services.md)
- [Stop 14 · myotis-net, part 6: the verified reader](14-el-reader.md)
- [Stop 15 · myotis-net, part 7: integration tests and probes](15-net-tests.md)

**Boundaries & binaries**

- [Stop 16 · myotis-engine: the boundary](16-engine.md)
- [Stop 17 · Deep dive: how UniFFI connects Kotlin to Rust](17-uniffi.md)
- [Stop 18 · myotis-node: the Node.js addon](18-node.md)
- [Stop 19 · myotis-rpcd: a JSON-RPC daemon in Rust](19-rpcd.md)
- [Stop 20 · roost: the light-client server](20-roost.md)
- [Stop 21 · tor-poc: the same stack over Tor](21-torpoc.md)

**Wrap-up**

- [Stop 22 · Workbook: ten exercises you can run offline](22-workbook.md)
- [Stop 23 · Final checkpoint: one request, end to end](23-final.md)

**Appendices**

- [Checkpoint answers](answers.md)
- [Reading list](reading-list.md)
