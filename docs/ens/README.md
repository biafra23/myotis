# ENS docs (`myotis-ens`)

Documents specific to ENS resolution — forward and reverse, ENSIP-10
wildcards, and ERC-3668 CCIP-Read. The resolver runs the ENS contracts
inside the local EVM (see `../evm/`); cross-cutting trust and architecture
notes live in `../architecture-doc.md`.

| Document | Scope |
|----------|-------|
| [phase3-design.md](phase3-design.md) | Phase 3 — forward + reverse ENS resolution against the Universal Resolver via the local EVM. |
| [phase4-design.md](phase4-design.md) | Phase 4 — CCIP-Read (ERC-3668). Off-chain lookup handler that decorates the EVM executor. |
| [resolution-podcast.md](resolution-podcast.md) | Two-speaker walkthrough of how `resolve-ens vitalik.eth` works end-to-end. |
