# addr1 reader conformance vectors

`addr1-reader-vectors.txt` was written by eth2swarm's slice builder (`src/addr/vectors.rs`,
commit `3cfc3e5`, branch `addr/part9-reader-vectors` of `feature/address-index`, eth2swarm
#19), copied unchanged. It holds nine slices at the edges of the encodings, which the devnet
fixture (`../addr1-devnet`) does not reach:

- `spill-pages`: one address with 2000 entries, a spill file of two pages;
- `spill-page-full`: a spill page filled to its last byte, then a second page;
- `spill-limit`: inline entries of exactly 256 bytes (`SPILL_INLINE_MAX`) and of 257, spilled;
- `bucket-4096`: a bucket of exactly 4096 bytes inline;
- `bucket-4097`: one byte more, paged, with a pages file of one page;
- `bucket-pages`: a paged bucket whose pages file has three pages, a spilled record in it;
- `bucket-page-full`: a paged bucket whose first page is filled to its last byte;
- `late-start`: slice (2, 0) of an index from unit 3 (deltas from block 192), roles of
  several bits, one address spilled;
- `mainnet-height`: slice (16, 6) from block 25,165,824, block deltas of three and four bytes.

The payloads are those of the SOCs, unsigned (the devnet fixture covers the signatures), and
each file is listed under its Swarm reference. eth2swarm read everything listed back from these
bytes with its own decoders before writing it; every bucket of a slice is listed, and each
slice names an address it has no record of. The file's header describes the line format.
Read by `rust/myotis-addr1/tests/reader_vectors.rs`, which decodes every address's records
and files with the reader and compares its entries and its record and bucket forms, and
checks that the absent addresses give nothing.
