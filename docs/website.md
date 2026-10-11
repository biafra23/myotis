# The website — `site/`

`site/index.html` is the page for people who **use** Myotis rather than build it:
what it is, why it matters, and how to install and use the desktop and Android
apps. Developers keep reading the [README](../README.md).

Where it lives:

| Address | Who it is for | Status |
|---|---|---|
| `https://biafra23.github.io/myotis/` | everyone | GitHub Pages, deployed by `.github/workflows/pages.yml` |
| `myotis.eth` | ENS-aware browsers (e.g. the [Freedom browser](https://github.com/solardev-xyz/freedom-browser)) | planned: the same files on Swarm |
| `https://myotis.eth.limo` | ordinary browsers | follows `myotis.eth` automatically once its contenthash is set |

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

## Moving to Swarm and `myotis.eth` (later)

A sketch of the steps, for when the page moves. Check each command's `--help`
against the swarm-cli version you run.

1. **Upload** the directory with an index document, from a Bee node with a
   postage batch:

   ```bash
   swarm-cli upload site/ --stamp <batch-id> --index-document index.html
   ```

   This prints a Swarm reference (64 hex characters).
2. **Point the name at it**: in the ENS manager app, set the *content hash* of
   `myotis.eth` to `bzz://<reference>`. The Freedom browser then opens
   `myotis.eth` directly, and `https://myotis.eth.limo` serves the same page —
   eth.limo resolves Swarm content hashes as well as IPFS ones.
3. **Updates without an ENS transaction each time**: upload through a *feed*
   instead (`swarm-cli feed upload site/ --identity <name> --topic-string
   website --stamp <batch-id> --index-document index.html`) and set the content
   hash once to the feed's manifest reference; later uploads under the same
   identity and topic replace what the name shows.
4. **Keep the batch alive.** Swarm keeps data only while its postage batch is
   paid for; top it up (`swarm-cli stamp topup`) before it expires, or the page
   disappears from `myotis.eth` and eth.limo with it.

GitHub Pages can stay as a mirror after the move; nothing on the page depends on
which host served it.
