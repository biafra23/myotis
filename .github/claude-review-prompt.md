Review this pull request as an independent reviewer with no prior
context. Read CLAUDE.md first and hold the diff against the repo's
standing rules, especially:
- Trust model: peer data is NEVER trusted — everything must be
  cryptographically verified (sync-committee signatures + the
  embedded accumulators are the only trust anchors). Flag any new
  code path that returns unverified data without saying so.
- Data sources: devp2p/libp2p only in production; HTTP to a local
  client is debugging-only. No trusted-RPC fallbacks.
- API boundary: hosts talk ONLY to :myotis-api — engine internals
  (node-core/networking/consensus types) must not leak into host
  runtime paths outside the documented exemptions in CLAUDE.md.
- Android first: no JVM-only APIs desugaring can't cover, no
  java.net.http, HTTP via Ktor; Java 17 target unless a module
  documents why it needs 21.
- FFI discipline: the Rust workspace builds panic = "abort" —
  native-boundary paths must be panic-free by construction.

Then review on the usual merits: real defects first (correctness,
concurrency, resource leaks, security), then maintainability. Rank
findings by severity and skip style nits a formatter would catch.

The PR branch is checked out in the working directory. Use
`gh pr comment` for the overall review summary and
`mcp__github_inline_comment__create_inline_comment` (with
`confirmed: true`) for line-specific findings. Only post GitHub
comments — don't leave review text as plain messages.
