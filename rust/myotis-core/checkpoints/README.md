# The bundled checkpoint tables

The hash of every 1024th block per network, a trust anchor: the rule is in
`.claude/agent/data-sources.md` (Trust, "The bundled checkpoint table"), the design in
`docs/ideas/deep-block-verification.md`, the loader in `../src/checkpoints.rs`.

| File | What |
|---|---|
| `mainnet-1024.hashes` | 32 bytes per entry; entry *i* is the hash of block *i*·1024, from block 0 up to the last multiple of 1024 at or below the top |
| `mainnet-1024.hashes.json` | the build's sidecar: entries, last entry, top block and hash, genesis hash, keccak256, source client, cross-check |

The loader does not read the sidecar. It checks the table against `MAINNET_PIN` in
`../src/checkpoints.rs`: the keccak256, the number of entries, entry 0 against the genesis
hash, and the top. A table that does not match is refused.

## The mainnet table

- **Built** 2026-11-20 by eth2swarm's `ethswarm checkpoint-table` (VesperBats/eth2swarm#32)
  from Erigon 3.8.1. The tool hashed every header itself and linked each one by `parentHash`
  down to the genesis hash `0xd4e56740…8fa3`.
- **Top:** block 26,457,537 (`0x229a7a21…85fc`), the source node's finalized block. It was
  cross-checked against Geth 1.17.7: 203 entries and the top block were equal. The owner ruled
  on 2026-11-20 that this suffices for the first table. The running node's gap walk, from its
  beacon-attested finalized block down to the top, checks the top again.
- **Why every entry counts as checked:** the walk linked each header to its parent, from
  the top all the way down to the genesis hash. So every entry sits on one hash chain whose
  two ends are checked: the genesis hash, and the cross-checked top. An entry off that chain
  would have broken the walk. The 203 sampled entries are a check of the tool, not the whole
  check.
- **Size:** 25,838 entries, 826,816 bytes. keccak256 `0xccf5ad88…03d0`.

## Changing a table

A table changes only in a release PR that names its build: the tool, the source node, the
top, and the cross-check. Each release extends it (`.claude/agent/releases.md`, step 6):
replace the file and the sidecar, and move the pin in `../src/checkpoints.rs` in the same
commit. The new table's bytes up to the old last entry must equal the old table's, so a
release only appends. A running node never writes here.
A table is committed, never generated at build time, so release outputs stay byte-identical.
Even so, a PR into `main` that changes one needs a green `reproducible builds` run
(`.claude/agent/reproducibility.md`), because the table is embedded in the engine.
