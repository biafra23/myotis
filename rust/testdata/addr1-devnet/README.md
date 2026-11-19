# addr1 golden fixture (devnet)

An addr1 index exported by eth2swarm (`addr-import --out`, commit `a1b3923` of
`feature/address-index`) from the bee-factory Anvil chain (chain ID 1337) after
`ethswarm devnet-activity`: an index from block 1920 (unit 30) to 33 units (head updates 0
and 1, the origin), two slices, three spill files, signed by a throwaway key. Read by
`rust/myotis-addr1/tests/devnet_fixture.rs`.

- `addr1.log`: the export log, records `kind (u8) ‖ key (32) ‖ len (u32 BE) ‖ data` in upload
  order: files (1) under their reference, SOCs (2) and heads (3) in wire form under their
  address.
- `expected.txt`: `address block slot roles` per entry, as eth2swarm's `addr-lookup` found
  them through Bee after `addr-upload` (each matched the chain with `--against-chain`);
  `address -` closes each address's list.

Owner `0xad85b9f14bd1be6a53b16f1e18015cc81a679b0f`, chain 1337.
