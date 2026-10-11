#!/usr/bin/env node
// Publish the website (site/) to Swarm, behind the feed that myotis.eth points at.
//
//   node scripts/publish_site_swarm.mjs publish        upload origin/main's site/ and move the feed to it
//   node scripts/publish_site_swarm.mjs status         what myotis.eth serves, and the batches' health
//   node scripts/publish_site_swarm.mjs cli <args…>    run the pinned swarm-cli (identity, stamp, …)
//
// Everything goes through a Swarm FEED: its manifest address never changes, so
// myotis.eth's content hash is set once (one ENS transaction) and every later
// publish only updates the feed. The setup, the postage batch and the ENS step
// are in docs/website.md.
//
// What goes live is a clean `git archive` of origin/main's site/, never the
// working tree: an edit, an unmerged branch or a file git ignores (a Finder
// .DS_Store) cannot reach myotis.eth by accident.
//
// Needs Node 18+ (with npm), git, tar, and a Bee node you control (it pays for
// the upload from an immutable postage batch). The upload itself is done by the
// official swarm-cli, pinned WITH its whole dependency tree by
// scripts/swarm-cli/package-lock.json and installed from it with
// `npm ci --ignore-scripts` on first use: that process is where the feed key's
// password is typed and the key decrypted, so it runs nothing the lockfile did
// not name. swarm-cli asks for the password itself; it never passes through
// this script or a command line.
//
// scripts/site_swarm_feed.json records the feed's manifest and every batch it
// has been published with. Commit it whenever publish changes it: batch ids
// and the manifest are public anyway, and the record lets any checkout refuse a
// wrong key or batch and keep watching every batch the feed lives on.
//
// status exits non-zero when something needs attention (a batch near expiry or
// gone, content that differs), so it can run from cron.
//
// Environment:
//   SWARM_STAMP            postage batch id (64 hex) — required for publish
//   BEE_API_URL            default http://localhost:1633
//   SWARM_FEED_IDENTITY    swarm-cli identity that signs the feed, default myotis-website
//   ETH_RPC_URL            Ethereum mainnet RPC for the ENS check, default your
//                          Myotis node, http://127.0.0.1:8545 (anything else is
//                          reported as unverified)
//   SWARM_GATEWAY_URL      public gateway status also checks, default https://api.gateway.ethswarm.org
//   SWARM_ALLOW_UNMERGED=1 publish the working tree's site/ instead of origin/main's
//   SWARM_NEW_BATCH=1      publish with a batch the feed has not used before

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Part of the feed's identity together with the signing key: changing either
// makes a NEW feed, with a new manifest address, and myotis.eth would need a
// new ENS transaction. Do not change it. The hex is Topic.fromString(FEED_TOPIC),
// i.e. keccak256 of the string.
const FEED_TOPIC = "myotis-website";
const FEED_TOPIC_HEX = "ab98dc5cdad8527c9960bcf7134af15f0983fab5b6b6d3c50b4a78efecfb6e60";
const ENS_NAME = "myotis.eth";
const ENS_NODE = "74ca9bc3d30fab63475ef4463b8b1f9d5bc898da87faa009925c94668b9cff56"; // namehash("myotis.eth")
const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
const SEL_RESOLVER = "0178b8bf"; // resolver(bytes32)
const SEL_CONTENTHASH = "bc1c58d1"; // contenthash(bytes32)
// EIP-1577 content hash of a Swarm manifest: swarm-ns, CIDv1, swarm-manifest, keccak-256, 32 bytes.
const BZZ_PREFIX = "e40101fa011b20";
const PUBLIC_GATEWAY = (process.env.SWARM_GATEWAY_URL || "https://api.gateway.ethswarm.org").replace(/\/+$/, "");
const DEFAULT_ETH_RPC = "http://127.0.0.1:8545";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FEED_FILE = join(ROOT, "scripts", "site_swarm_feed.json");
const CLI_DIR = join(ROOT, "scripts", "swarm-cli");
const CLI_BIN = join(CLI_DIR, "node_modules", ".bin", "swarm-cli");
const CLI_STAMP = join(CLI_DIR, "node_modules", ".installed-lock-sha256");
const BEE = (process.env.BEE_API_URL || "http://localhost:1633").replace(/\/+$/, "");
const ETH_RPC = process.env.ETH_RPC_URL || DEFAULT_ETH_RPC;
// A Myotis node verifies what it answers; an arbitrary RPC is taken on its word.
const ETH_RPC_LABEL = ETH_RPC === DEFAULT_ETH_RPC ? `via ${ETH_RPC}` : `via ${ETH_RPC}, unverified`;
const IDENTITY = process.env.SWARM_FEED_IDENTITY || "myotis-website";

class Fail extends Error {}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const short = (id) => `${id.slice(0, 8)}…`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const git = (...args) => execFileSync("git", ["-C", ROOT, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Fail(`${url} answered HTTP ${res.status}`);
  return res.json();
}

// Installs swarm-cli from the lockfile when node_modules is missing or was
// installed from a different lockfile.
function ensureSwarmCli() {
  const lock = sha256(readFileSync(join(CLI_DIR, "package-lock.json")));
  if (existsSync(CLI_BIN) && existsSync(CLI_STAMP) && readFileSync(CLI_STAMP, "utf8") === lock) return;
  console.error("Installing swarm-cli from scripts/swarm-cli/package-lock.json …");
  try {
    execFileSync("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: CLI_DIR, stdio: ["ignore", "ignore", "inherit"] });
  } catch (e) {
    throw new Fail(`npm ci in ${CLI_DIR} failed (${e.message}); is npm installed?`);
  }
  writeFileSync(CLI_STAMP, lock);
}

function swarmCli(args, { capture = false } = {}) {
  ensureSwarmCli();
  return new Promise((resolveRun, reject) => {
    const child = spawn(CLI_BIN, args, {
      stdio: ["inherit", capture ? "pipe" : "inherit", capture ? "pipe" : "inherit"],
    });
    let out = "";
    if (capture) {
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
    }
    child.on("error", (e) => reject(new Fail(`could not run swarm-cli (${e.message})`)));
    child.on("close", (code) => (code === 0 ? resolveRun(out) : reject(Object.assign(new Fail(`swarm-cli ${args.slice(0, 2).join(" ")} failed`), { out }))));
  });
}

// { feedManifest: hex | null, batches: [hex, …] }, in publish order.
function readFeedRecord() {
  const r = JSON.parse(readFileSync(FEED_FILE, "utf8"));
  return { feedManifest: r.feedManifest || null, batches: (r.batches || []).map((b) => b.toLowerCase()) };
}

function writeFeedRecord(record) {
  writeFileSync(FEED_FILE, JSON.stringify(record, null, 2) + "\n");
}

// The site/ that should be live: a clean export of origin/main's (after a
// fetch), or the working tree's with SWARM_ALLOW_UNMERGED=1. Returns
// { dir, label, cleanup }.
function siteSource() {
  if (process.env.SWARM_ALLOW_UNMERGED === "1") {
    return { dir: join(ROOT, "site"), label: "working tree site/ (SWARM_ALLOW_UNMERGED=1, not checked against main)", cleanup() {} };
  }
  try {
    git("fetch", "--quiet", "origin", "main");
  } catch {
    console.log("Content    ! could not fetch origin/main; using the last fetched copy");
  }
  let rev;
  try {
    rev = git("rev-parse", "--short", "origin/main").trim();
  } catch (e) {
    throw new Fail(`no origin/main in this checkout (${e.stderr || e.message})`);
  }
  const tmp = mkdtempSync(join(tmpdir(), "myotis-site-"));
  const cleanup = () => rmSync(tmp, { recursive: true, force: true });
  try {
    const tar = execFileSync("git", ["-C", ROOT, "archive", "--format=tar", "origin/main", "site"], { maxBuffer: 256 * 1024 * 1024 });
    execFileSync("tar", ["-x", "-C", tmp], { input: tar });
  } catch (e) {
    cleanup();
    throw new Fail(`exporting origin/main's site/ failed: ${e.stderr || e.message}`);
  }
  const dir = join(tmp, "site");
  if (!existsSync(join(dir, "index.html"))) {
    cleanup();
    throw new Fail("origin/main has no site/index.html");
  }
  // Only informative: the export is what goes live, whatever the working tree holds.
  let differs = false;
  try {
    git("diff", "--quiet", "origin/main", "--", "site");
    differs = git("ls-files", "--others", "--", "site").trim() !== "";
  } catch {
    differs = true;
  }
  const note = differs ? " (your working tree's site/ differs; it is not what goes live)" : "";
  return { dir, label: `site/ of origin/main @ ${rev}${note}`, cleanup };
}

// Every file under dir, as paths relative to it.
function siteFiles(dir, base = dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? siteFiles(join(dir, e.name), base) : [relative(base, join(dir, e.name))],
  );
}

// The paths under <server>/bzz/<ref>/ that do not serve the file in dir: the
// root (the index document) and every file by name.
async function differingPaths(server, ref, dir) {
  const checks = [["", "index.html"], ...siteFiles(dir).map((f) => [f, f])];
  const bad = [];
  for (const [path, file] of checks) {
    let served;
    try {
      const res = await fetch(`${server}/bzz/${ref}/${path.split("/").map(encodeURIComponent).join("/")}`);
      served = res.ok ? sha256(Buffer.from(await res.arrayBuffer())) : `HTTP ${res.status}`;
    } catch (e) {
      served = e.message;
    }
    if (served !== sha256(readFileSync(join(dir, file)))) bad.push(path || "/ (index document)");
  }
  return bad;
}

async function checkBee() {
  let health;
  try {
    health = await getJson(`${BEE}/health`);
  } catch (e) {
    throw new Fail(`no Bee node answers at ${BEE} (${e.message}). Start it, or set BEE_API_URL.`);
  }
  console.log(`Bee node   ${BEE} — version ${health.version}, status ${health.status}`);
}

// Checks the batch about to be used (strictly) and every batch the feed has
// been published with (warnings: the feed's earlier updates live on them, and
// a sequence feed is looked up from its first update onwards). Returns whether
// anything needs attention.
async function checkBatches(current, record) {
  let attention = false;
  const ids = [...new Set([...record.batches, ...(current ? [current] : [])])];
  for (const id of ids) {
    const isCurrent = id === current;
    const res = await fetch(`${BEE}/stamps/${id}`);
    const b = res.ok ? await res.json() : null;
    if (!b || !b.exists) {
      const why = res.status === 404 ? "is not one of this node's batches" : !res.ok ? `answered HTTP ${res.status}` : "has expired";
      if (isCurrent) throw new Fail(`postage batch ${id} ${why}`);
      console.log(`Batch      ! ${short(id)} ${why}; it holds earlier feed updates — check it on the node that bought it`);
      attention = true;
      continue;
    }
    const days = Math.floor(Number(b.batchTTL) / 86400);
    const fill = Math.round((100 * b.utilization) / 2 ** (b.depth - b.bucketDepth));
    console.log(`Batch      ${short(id)} — ${b.label ? `"${b.label}", ` : ""}expires in ~${days} days, ${fill}% full${isCurrent ? "" : " (holds feed updates)"}`);
    if (days < 30) {
      console.log(`           ! Top it up soon (swarm-cli stamp topup): when it expires, ${ENS_NAME} stops serving the site.`);
      attention = true;
    }
    if (!isCurrent) continue;
    if (!b.usable) throw new Fail(`postage batch ${id} is not usable yet — a new batch takes a few minutes; try again shortly`);
    if (!b.immutableFlag) {
      // A mutable batch that fills up overwrites its oldest chunks, the feed's
      // included, and the site then disappears from myotis.eth without an error.
      throw new Fail(`postage batch ${id} is mutable; a feed needs an immutable batch (see docs/website.md)`);
    }
    if (fill >= 80) console.log("           ! Nearly full: dilute it (swarm-cli stamp dilute); an immutable batch refuses uploads once full.");
  }
  return attention;
}

async function findIdentity() {
  const hint =
    `If you have not created it yet (and backed it up) as docs/website.md describes:\n` +
    `  node scripts/publish_site_swarm.mjs cli identity create ${IDENTITY}`;
  let out;
  try {
    out = await swarmCli(["identity", "list", "--quiet"], { capture: true });
  } catch (e) {
    // swarm-cli also fails the listing when it has no identities at all.
    throw new Fail(`swarm-cli could not list identities:\n${(e.out || e.message).trim()}\n${hint}`);
  }
  for (const line of out.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] === IDENTITY) return { address: parts[parts.length - 1].replace(/^0x/, "").toLowerCase() };
  }
  throw new Fail(`no swarm-cli identity named "${IDENTITY}". ${hint}`);
}

// The feed manifest for (owner, topic). Bee derives it from those two alone, so
// it is the same address on every publish, and the one swarm-cli creates.
async function feedManifest(owner, stamp) {
  const res = await fetch(`${BEE}/feeds/${owner}/${FEED_TOPIC_HEX}`, {
    method: "POST",
    headers: { "swarm-postage-batch-id": stamp },
  });
  if (!res.ok) throw new Fail(`creating the feed manifest answered HTTP ${res.status}`);
  return (await res.json()).reference;
}

async function ethCall(to, data) {
  let res;
  try {
    res = await fetch(ETH_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
    });
  } catch (e) {
    throw new Fail(`no answer from ${ETH_RPC} (${e.cause?.code || e.message}); start Myotis or set ETH_RPC_URL`);
  }
  const body = await res.json().catch(() => ({}));
  if (body.error) throw new Fail(`${ETH_RPC} answered with an error: ${body.error.message} (is it synced?)`);
  if (typeof body.result !== "string") throw new Fail(`${ETH_RPC} answered HTTP ${res.status} without a result`);
  return body.result.replace(/^0x/, "");
}

// What myotis.eth's content hash points at: null when unset, else
// { bzz: <manifest hex> } or { other: <raw hex> }.
async function ensContent() {
  const reg = await ethCall(ENS_REGISTRY, `0x${SEL_RESOLVER}${ENS_NODE}`);
  if (reg.length < 64) throw new Fail(`no ENS registry at ${ETH_RPC}; it must be an Ethereum mainnet RPC (Myotis serves mainnet on port 8545)`);
  const resolver = "0x" + reg.slice(24, 64);
  if (/^0x0+$/.test(resolver)) return null;
  const ret = await ethCall(resolver, `0x${SEL_CONTENTHASH}${ENS_NODE}`);
  if (ret.length < 128) return null;
  const offset = parseInt(ret.slice(0, 64), 16) * 2;
  const len = parseInt(ret.slice(offset, offset + 64), 16) * 2;
  const hash = ret.slice(offset + 64, offset + 64 + len);
  if (!hash) return null;
  return hash.startsWith(BZZ_PREFIX) && hash.length === BZZ_PREFIX.length + 64
    ? { bzz: hash.slice(BZZ_PREFIX.length) }
    : { other: hash };
}

// Prints where myotis.eth points and, after a publish, what to set if it does
// not point at the feed yet. Returns the content found: undefined when the
// check could not run, null when unset.
async function reportEns(manifest) {
  let content;
  try {
    content = await ensContent();
  } catch (e) {
    console.log(`ENS        not checked: ${e.message}`);
  }
  if (content === null) {
    console.log(`ENS        ${ENS_NAME} has no content hash yet (${ETH_RPC_LABEL}).`);
  } else if (content?.other) {
    console.log(`ENS        ${ENS_NAME} points at something that is not Swarm: 0x${content.other} (${ETH_RPC_LABEL})`);
  } else if (content && manifest && content.bzz === manifest) {
    console.log(`ENS        ${ENS_NAME} already points at this feed (${ETH_RPC_LABEL}). Nothing else to do.`);
    return content;
  } else if (content && manifest) {
    // Not the feed we just updated: someone set another hash. The live site
    // did NOT change.
    console.log(`ENS        ! ${ENS_NAME} points at bzz://${content.bzz} (${ETH_RPC_LABEL}),`);
    console.log(`             NOT at this feed. The site at ${ENS_NAME} did not change.`);
  } else if (content) {
    console.log(`ENS        ${ENS_NAME} → bzz://${content.bzz} (${ETH_RPC_LABEL})`);
  }
  if (manifest) {
    console.log("");
    console.log(`${content === undefined ? "Unless it is already set, set" : "Set"} the content hash of ${ENS_NAME} once, in the ENS app (Records → Content hash), to:`);
    console.log(`  bzz://${manifest}`);
    console.log(`(as raw bytes: 0x${BZZ_PREFIX}${manifest})`);
  }
  return content;
}

async function publish() {
  const stamp = (process.env.SWARM_STAMP || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(stamp)) {
    throw new Fail("set SWARM_STAMP to the id of an immutable postage batch (64 hex characters). docs/website.md says how to buy one.");
  }
  const record = readFeedRecord();
  const site = siteSource();
  try {
    console.log(`Content    ${site.label}`);
    await checkBee();
    await checkBatches(stamp, record);
    if (record.batches.length && !record.batches.includes(stamp)) {
      if (process.env.SWARM_NEW_BATCH !== "1") {
        throw new Fail(
          `the feed has so far been published with ${record.batches.map(short).join(", ")} (scripts/site_swarm_feed.json).\n` +
            "  Keep using that batch (top it up or dilute it, see docs/website.md), or set SWARM_NEW_BATCH=1 to add this one.",
        );
      }
      console.log(`Batch      ! adding ${short(stamp)} (SWARM_NEW_BATCH=1); keep the earlier ones alive too`);
    }
    const { address } = await findIdentity();
    const manifest = await feedManifest(address, stamp);
    if (record.feedManifest && record.feedManifest !== manifest) {
      throw new Fail(
        `identity "${IDENTITY}" (0x${address}) signs the feed bzz://${manifest},\n` +
          `  but myotis.eth's feed is bzz://${record.feedManifest} (scripts/site_swarm_feed.json).\n` +
          "  Wrong SWARM_FEED_IDENTITY, or a different key? Only the original key can update the site.",
      );
    }
    console.log(`Feed       bzz://${manifest} — identity "${IDENTITY}" (0x${address}), topic "${FEED_TOPIC}"`);

    // Recorded before the upload: once swarm-cli has written the feed, this
    // batch holds part of it whether or not the checks below pass.
    const before = JSON.stringify(record);
    if (!record.batches.includes(stamp)) record.batches.push(stamp);
    record.feedManifest = manifest;
    writeFeedRecord(record);
    if (JSON.stringify(record) !== before) {
      console.log("Record     ! scripts/site_swarm_feed.json changed: commit it (a PR) so every checkout knows this feed and batch.");
    }
    console.log("");

    // Not quiet, so swarm-cli can ask for the identity's password itself.
    await swarmCli([
      "feed", "upload", site.dir,
      "--bee-api-url", BEE,
      "--identity", IDENTITY,
      "--topic", FEED_TOPIC_HEX,
      "--stamp", stamp,
      "--index-document", "index.html",
      "--pin",
      "--sync",
      "--yes",
    ]);

    // Right after an update, the node may still resolve the feed to the
    // previous version for a moment.
    let bad = await differingPaths(BEE, manifest, site.dir);
    for (let attempt = 1; bad.length && attempt < 10; attempt++) {
      await sleep(3000);
      bad = await differingPaths(BEE, manifest, site.dir);
    }
    if (bad.length) throw new Fail(`after 30 s ${BEE}/bzz/${manifest}/ still serves other content for: ${bad.join(", ")}`);

    console.log("");
    console.log(`Published  ${BEE}/bzz/${manifest}/ serves every file`);
    console.log(`           ${PUBLIC_GATEWAY}/bzz/${manifest}/ (public gateway; may take a few minutes)`);
    console.log("");
    await reportEns(manifest);
  } finally {
    site.cleanup();
  }
}

async function status() {
  const record = readFeedRecord();
  let attention = false;
  const content = await reportEns(null);
  if (content?.bzz && record.feedManifest && content.bzz !== record.feedManifest) {
    console.log(`           ! not the feed in scripts/site_swarm_feed.json (bzz://${record.feedManifest})`);
    attention = true;
  }
  // What to look at on Swarm: what ENS points at, else the recorded feed.
  const target = content?.bzz || record.feedManifest;
  let beeUp = true;
  try {
    await getJson(`${BEE}/health`);
  } catch {
    console.log(`Swarm      not checked on your node: no Bee node at ${BEE}.`);
    beeUp = false;
  }
  if (beeUp) attention = (await checkBatches(null, record)) || attention;
  if (target) {
    const site = siteSource();
    try {
      console.log(`Content    ${site.label}`);
      for (const [name, server] of beeUp ? [["your node", BEE], ["gateway", PUBLIC_GATEWAY]] : [["gateway", PUBLIC_GATEWAY]]) {
        const bad = await differingPaths(server, target, site.dir);
        console.log(bad.length ? `Swarm      ! ${name} (${server}) differs for: ${bad.join(", ")}` : `Swarm      ${name} (${server}) serves exactly that`);
        attention = attention || bad.length > 0;
      }
    } finally {
      site.cleanup();
    }
  }
  if (attention) process.exitCode = 1;
}

async function cli() {
  await swarmCli(process.argv.slice(3));
}

const command = process.argv[2];
const commands = { publish, status, cli };
if (!commands[command]) {
  console.log("Usage: node scripts/publish_site_swarm.mjs publish|status|cli <swarm-cli args>   (see the comment at the top, and docs/website.md)");
  process.exit(command ? 2 : 0);
}
commands[command]().catch((e) => {
  console.error(`\nError: ${e instanceof Fail ? e.message : e.stack || e}`);
  process.exit(1);
});
