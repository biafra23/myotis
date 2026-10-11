# The website — `site/`

`site/index.html` is the page for people who **use** Myotis rather than build it:
what it is, why it matters, and how to install and use the desktop and Android
apps. Developers keep reading the [README](../README.md).

Where it lives:

| Address | Who it is for | Status |
|---|---|---|
| `https://biafra23.github.io/myotis/` | everyone | GitHub Pages, deployed by `.github/workflows/pages.yml` |
| `myotis.eth` | ENS-aware browsers (e.g. the [Freedom browser](https://github.com/solardev-xyz/freedom-browser)) | the same files on Swarm, behind a feed; published by hand with `scripts/publish_site_swarm.mjs` |
| `https://myotis.eth.limo` | ordinary browsers | follows `myotis.eth` automatically |

## Rules for the page

The same directory must work unchanged on GitHub Pages (served under
`/myotis/`), on a Swarm gateway and on eth.limo (both served at the root), so:

- **Relative links only** inside the site (`favicon.svg`, `#android`) — never a
  leading `/`, which would point at a different place on each host.
- **No build step and no third-party requests.** No CDN, no web fonts, no
  analytics, no embedded videos. A privacy tool's homepage should not tell a
  third party who read it, and anything fetched from elsewhere is one more
  thing that breaks on Swarm. Links *to* GitHub (downloads, source) are fine:
  the visitor chooses to follow them.
- **Plain language.** The audience is not technical. Say what a thing does for
  the reader before naming it; keep protocol names out of the main text.
- **Facts follow the apps.** The screen and setting names, ports and chain ids
  quoted on the page are the apps' own (`ui/`), and the download names are the
  release assets' (`Myotis-v<version>-…`). When a release renames a tab, a
  setting or an asset, update the page in the same PR.

The download buttons point at the
[releases list](https://github.com/biafra23/myotis/releases), not at
`/releases/latest`: every release so far is marked *pre-release*, and GitHub's
"latest" skips those (the URL 404s). The page tells the reader which file to
pick instead. Direct download buttons need a release marked as latest **and**
asset names without the version in them.

## Turning on GitHub Pages (once)

A repository admin sets **Settings → Pages → Build and deployment → Source** to
**GitHub Actions**. After that every push to `main` that touches `site/`
redeploys it; *Run workflow* on the *Website (GitHub Pages)* workflow
redeploys by hand.

Preview locally with any static server, e.g. `python3 -m http.server -d site`.

## Swarm and `myotis.eth`

```
site/ ──(your Bee node)──▶ Swarm upload ──▶ feed "myotis-website" ──▶ feed manifest
                                                                          ▲
                              myotis.eth content hash = bzz://<manifest> ─┘  (set once)
```

`scripts/publish_site_swarm.mjs` uploads `site/` from a Bee node you run and
points a Swarm **feed** at it. The feed's manifest address never changes, so
`myotis.eth`'s content hash is set once, in one ENS transaction, and every later
publish only updates the feed. The Freedom browser opens `myotis.eth` directly;
`https://myotis.eth.limo` serves the same page to every other browser (eth.limo
resolves Swarm content hashes as well as IPFS ones).

The upload is the official `swarm-cli` (pinned in the script, fetched by `npx`),
which also asks for the feed key's password, so the password never passes
through the script or a command line. The script adds the checks around it:

- `site/` matches `origin/main`: only merged, reviewed content goes live
  (override with `SWARM_ALLOW_UNMERGED=1`);
- the batch is usable, immutable, and the same one this feed was published
  with before (remembered in `~/.myotis/website-swarm.json`; override with
  `SWARM_NEW_BATCH=1`, see *Keeping it alive*);
- the feed key exists;
- afterwards, your node serves every file of `site/`, the root included;
- where `myotis.eth` points, read through your Myotis node on `127.0.0.1:8545`
  (or `ETH_RPC_URL`, an Ethereum mainnet RPC).

It needs Node 18+ and git.

Publishing is manual on purpose: the feed key decides what `myotis.eth` shows,
and it stays on your machine rather than in CI secrets. GitHub Pages keeps
deploying by itself and stays up as a mirror.

### Once

1. **Create the feed key** and back it up. The password encrypts it on disk.

   ```bash
   npx @ethersphere/swarm-cli@3.6.0 identity create myotis-website
   npx @ethersphere/swarm-cli@3.6.0 identity export myotis-website --out-file myotis-website-feed.json
   ```

   Keep the export and its password offline. Whoever holds this key can change
   what `myotis.eth` shows, for example to a page with fake download links,
   until the ENS record is changed. Losing it means a new feed and a new ENS
   transaction.
2. **Buy an immutable postage batch** for it. `stamp create` prints the price
   in xBZZ and asks before it buys.

   ```bash
   npx @ethersphere/swarm-cli@3.6.0 stamp create --capacity 100MB --ttl 1y --immutable --label myotis-website
   ```

   It must be immutable: a mutable batch that fills up overwrites its oldest
   chunks, the feed's included, and the site disappears without an error. The
   site is under 100 KB, so each publish uses little of it; choose capacity and
   lifetime to taste. Note the batch id it prints.
3. **Publish.**

   ```bash
   SWARM_STAMP=<batch id> node scripts/publish_site_swarm.mjs publish
   ```

   swarm-cli asks for the key's password, uploads and waits for the network
   to take the chunks; the script then waits until your node serves the new
   files and prints the content hash to set: `bzz://<feed manifest>`.
4. **Point `myotis.eth` at it**, once, from the wallet that manages the name:
   in the [ENS app](https://app.ens.domains/myotis.eth), *Records → Edit
   records → Content hash*, enter `bzz://<feed manifest>` and confirm the
   transaction.
5. **Check.** `node scripts/publish_site_swarm.mjs status` reads the record
   back and compares what Swarm serves with `site/`. Then open
   `https://myotis.eth.limo` (eth.limo may cache the old answer for a few
   minutes) and `myotis.eth` in the Freedom browser.

### Every update

After a change to `site/` is merged, from an up-to-date checkout of `main`:

```bash
SWARM_STAMP=<batch id> node scripts/publish_site_swarm.mjs publish
```

No ENS transaction. If the script reports that `myotis.eth` points somewhere
else, the feed key or topic changed (or someone changed the record): the live
site did not change.

### Keeping it alive

Swarm keeps data only while its batch is paid for. Keep **one batch for the life
of the feed**: the feed's earlier updates are stamped with it, so let it neither
expire nor be replaced. The script refuses a different batch than the one it
last published with, unless `SWARM_NEW_BATCH=1`; if you ever do switch, keep the
old batch topped up as well.

- **Before it expires**, top it up (`npx @ethersphere/swarm-cli@3.6.0 stamp
  topup --stamp <id> --amount <plur>`). The script warns when fewer than 30
  days are left.
- **Before it fills**, dilute it to a larger depth (`stamp dilute --stamp <id>
  --depth <n>`; each extra level of depth halves the remaining lifetime, so top up after). The
  script warns at 80 %: an immutable batch refuses uploads once full.
