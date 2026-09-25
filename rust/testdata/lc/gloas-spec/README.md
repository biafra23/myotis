# Gloas light-client spec vectors

Extracted from the `ethereum/consensus-specs` **v1.7.0-beta.2** release assets
(`mainnet.tar.gz`, `minimal.tar.gz`; the old `consensus-spec-tests` repository is
archived). Raw SSZ, snappy-decompressed. The Gloas light-client wire format has
not changed since v1.7.0-alpha.12. Upstream test vectors are CC0.

| File | Source path under `tests/` | Pins |
|---|---|---|
| `mainnet/ssz_static/<Type>/case_{0,1}.ssz` + `roots.txt` | `mainnet/gloas/ssz_static/<Type>/ssz_random/case_{0,1}/` | the fixed Gloas layouts (496 / 25472 / 26424 / 1448 bytes) and each container's `hash_tree_root` |
| `minimal/light_client_sync/bootstrap.ssz` + `trusted_block_root.txt` | `minimal/gloas/light_client/sync/pyspec_tests/light_client_sync/` | a genuine Gloas bootstrap: current sync committee at gindex 2945, execution block hash at 2856 |
| `minimal/gloas_fork/fulu_update.ssz` | the same directory, first step (`update_fork_digest 0xfdb20282`, attested slot 17) | a genuine Fulu header: upgraded to the Gloas shape (`upgrade_lc_header_to_gloas`), its block hash proves at gindex 812 with two zero pad nodes — the shape of a Gloas update's pre-Gloas finalized header |
| `minimal/gloas_fork/fulu_bootstrap.ssz` | `minimal/fulu/light_client/sync/pyspec_tests/gloas_fork/bootstrap.ssz_snappy` (`bootstrap_fork_digest 0xfdb20282`, trusted root `0xb80f3f35…`) | the slot-16 Fulu header the spec's store holds as finalized across the fork — the same 812 upgrade on a NON-GENESIS finalized block. The release has no Gloas-format update carrying one: its transition carries the empty genesis header, then finalizes a Gloas slot |
| `minimal/gloas_fork/update_<attested slot>.ssz` + `expected.txt` | `minimal/fulu/light_client/sync/pyspec_tests/gloas_fork/` (the three steps with `update_fork_digest 0xa23573d9`) | Gloas-format updates across the Fulu→Gloas boundary (`GLOAS_FORK_EPOCH` 3, 8-slot epochs): finality at 735, next committee at 2946 (the first two still carry the empty genesis finalized header) |

The minimal-preset objects have a 32-member sync committee (1584-byte
`SyncCommittee`, 100-byte `SyncAggregate`), so the tests slice them by hand and
feed the headers, branches and roots to the production verification; the
mainnet-preset decoders are exercised by `ssz_static`. Regenerate with the
extraction script kept alongside the PR that introduced this directory.
