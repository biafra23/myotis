#!/usr/bin/env node
// Publish the website (site/) to Swarm, behind the feed that myotis.eth points at.
//
//   node scripts/publish_site_swarm.mjs publish   upload site/ and move the feed to it
//   node scripts/publish_site_swarm.mjs status    show what myotis.eth serves right now
//
// Everything goes through a Swarm FEED: its manifest address never changes, so
// myotis.eth's content hash is set once (one ENS transaction) and every later
// publish only updates the feed. The setup, the postage batch and the ENS step
// are in docs/website.md.
//
// Needs Node 18+ and a Bee node you control (it pays for the upload from an
// immutable postage batch). The upload itself is done by the official swarm-cli,
// pinned below and fetched by npx on first use; this script adds the checks
// around it: the batch is usable and immutable, the feed key exists, the node
// then serves exactly the local files, and where myotis.eth points.
//
// Environment:
//   SWARM_STAMP           postage batch id (64 hex) — required for publish
//   BEE_API_URL           default http://localhost:1633
//   SWARM_FEED_IDENTITY   swarm-cli identity that signs the feed, default myotis-website
//   SWARM_FEED_PASSWORD   its password; asked for when unset and the identity has one
//   ETH_RPC_URL           Ethereum RPC for the ENS check, default your Myotis node,
//                         http://127.0.0.1:8545

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const SWARM_CLI = "@ethersphere/swarm-cli@3.6.0";
// Part of the feed's identity together with the signing key: changing either
// makes a NEW feed, with a new manifest address, and myotis.eth would need a
// new ENS transaction. Do not change it.
const FEED_TOPIC = "myotis-website";
const ENS_NAME = "myotis.eth";
const ENS_NODE = "74ca9bc3d30fab63475ef4463b8b1f9d5bc898da87faa009925c94668b9cff56"; // namehash("myotis.eth")
const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
const SEL_RESOLVER = "0178b8bf"; // resolver(bytes32)
const SEL_CONTENTHASH = "bc1c58d1"; // contenthash(bytes32)
// EIP-1577 content hash of a Swarm manifest: swarm-ns, CIDv1, swarm-manifest, keccak-256, 32 bytes.
const BZZ_PREFIX = "e40101fa011b20";
const PUBLIC_GATEWAY = "https://api.gateway.ethswarm.org";

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), "..", "site");
const BEE = (process.env.BEE_API_URL || "http://localhost:1633").replace(/\/+$/, "");
const ETH_RPC = process.env.ETH_RPC_URL || "http://127.0.0.1:8545";
const IDENTITY = process.env.SWARM_FEED_IDENTITY || "myotis-website";

class Fail extends Error {}

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Fail(`${url} answered HTTP ${res.status}`);
  return res.json();
}

function swarmCli(args, { capture = false } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn("npx", ["--yes", SWARM_CLI, ...args], {
      stdio: ["inherit", capture ? "pipe" : "inherit", "inherit"],
    });
    let out = "";
    if (capture) child.stdout.on("data", (d) => (out += d));
    child.on("error", (e) => reject(new Fail(`could not run npx (${e.message}); is Node installed?`)));
    child.on("close", (code) =>
      code === 0 ? resolveRun(out) : reject(new Fail(`swarm-cli ${args[0]} ${args[1] ?? ""} exited with ${code}`)),
    );
  });
}

function askHidden(question) {
  if (!process.stdin.isTTY) {
    throw new Fail("the feed identity has a password: set SWARM_FEED_PASSWORD or run this in a terminal");
  }
  return new Promise((done) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let muted = false;
    rl._writeToOutput = (s) => {
      if (!muted || s === "\r\n" || s === "\n") process.stdout.write(s);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write("\n");
      done(answer);
    });
    muted = true;
  });
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

async function checkStamp(stamp) {
  if (!/^[0-9a-f]{64}$/i.test(stamp || "")) {
    throw new Fail("set SWARM_STAMP to the id of an immutable postage batch (64 hex characters). docs/website.md says how to buy one.");
  }
  const res = await fetch(`${BEE}/stamps/${stamp}`);
  if (res.status === 404) throw new Fail(`this Bee node has no postage batch ${stamp}`);
  if (!res.ok) throw new Fail(`${BEE}/stamps/${stamp} answered HTTP ${res.status}`);
  const b = await res.json();
  if (!b.exists) throw new Fail(`postage batch ${stamp} has expired`);
  if (!b.usable) throw new Fail(`postage batch ${stamp} is not usable yet — a new batch takes a few minutes; try again shortly`);
  if (!b.immutableFlag) {
    // A mutable batch that fills up overwrites its oldest chunks, the feed's
    // included, and the site then disappears from myotis.eth without an error.
    throw new Fail(`postage batch ${stamp} is mutable; a feed needs an immutable batch (see docs/website.md)`);
  }
  const days = Math.floor(Number(b.batchTTL) / 86400);
  const slots = 2 ** (b.depth - b.bucketDepth);
  const fill = Math.round((100 * b.utilization) / slots);
  console.log(`Batch      ${stamp.slice(0, 8)}… — ${b.label ? `"${b.label}", ` : ""}expires in ~${days} days, ${fill}% full`);
  if (days < 30) console.log(`           ! Top it up soon (swarm-cli stamp topup): when it expires, ${ENS_NAME} stops serving the site.`);
  if (fill >= 80) console.log("           ! Nearly full: dilute it (swarm-cli stamp dilute); an immutable batch refuses uploads once full.");
}

async function findIdentity() {
  const out = await swarmCli(["identity", "list", "--quiet"], { capture: true });
  for (const line of out.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] === IDENTITY) {
      return { type: parts.slice(1, -1).join(" "), address: parts[parts.length - 1] };
    }
  }
  throw new Fail(
    `no swarm-cli identity named "${IDENTITY}". Create it once (and back it up) as docs/website.md describes:\n` +
      `  npx ${SWARM_CLI} identity create ${IDENTITY}`,
  );
}

async function verifyServed(manifest) {
  const local = sha256(readFileSync(join(SITE, "index.html")));
  // Right after an update, the node may still resolve the feed to the previous
  // version for a moment.
  for (let attempt = 1; attempt <= 10; attempt++) {
    const res = await fetch(`${BEE}/bzz/${manifest}/`);
    if (res.ok && sha256(Buffer.from(await res.arrayBuffer())) === local) {
      const icon = await fetch(`${BEE}/bzz/${manifest}/favicon.svg`);
      if (!icon.ok) throw new Fail(`the feed serves index.html but favicon.svg answered HTTP ${icon.status}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Fail(`after 30 s ${BEE}/bzz/${manifest}/ still does not serve the local site/index.html`);
}

async function ethCall(to, data) {
  const res = await fetch(ETH_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
  });
  const body = await res.json();
  if (body.error) throw new Error(body.error.message);
  return body.result.replace(/^0x/, "");
}

// What myotis.eth's content hash points at: null when unset, else
// { bzz: <manifest hex> } or { other: <raw hex> }.
async function ensContent() {
  const resolver = "0x" + (await ethCall(ENS_REGISTRY, `0x${SEL_RESOLVER}${ENS_NODE}`)).slice(24);
  if (/^0x0+$/.test(resolver)) return null;
  const ret = await ethCall(resolver, `0x${SEL_CONTENTHASH}${ENS_NODE}`);
  if (!ret) return null;
  const offset = parseInt(ret.slice(0, 64), 16) * 2;
  const len = parseInt(ret.slice(offset, offset + 64), 16) * 2;
  const hash = ret.slice(offset + 64, offset + 64 + len);
  if (!hash) return null;
  return hash.startsWith(BZZ_PREFIX) && hash.length === BZZ_PREFIX.length + 64
    ? { bzz: hash.slice(BZZ_PREFIX.length) }
    : { other: hash };
}

async function reportEns(manifest) {
  let content;
  try {
    content = await ensContent();
  } catch (e) {
    console.log(`ENS        not checked: no answer from ${ETH_RPC} (${e.message}). Start Myotis or set ETH_RPC_URL.`);
    return;
  }
  if (!content) {
    console.log(`ENS        ${ENS_NAME} has no content hash yet.`);
  } else if (content.other) {
    console.log(`ENS        ${ENS_NAME} points at something that is not Swarm: 0x${content.other}`);
  } else if (!manifest) {
    console.log(`ENS        ${ENS_NAME} → bzz://${content.bzz}`);
    return content.bzz;
  } else if (content.bzz === manifest) {
    console.log(`ENS        ${ENS_NAME} already points at this feed. Nothing else to do.`);
    return content.bzz;
  } else {
    // Not the feed we just updated: the identity or the topic changed, or
    // someone set another hash. The live site did NOT change.
    console.log(`ENS        ! ${ENS_NAME} points at bzz://${content.bzz},`);
    console.log(`             NOT at this feed. The site at ${ENS_NAME} did not change.`);
  }
  if (manifest) {
    console.log("");
    console.log(`Set the content hash of ${ENS_NAME} once, in the ENS app (Records → Content hash), to:`);
    console.log(`  bzz://${manifest}`);
    console.log(`(as raw bytes: 0x${BZZ_PREFIX}${manifest})`);
  }
}

async function publish() {
  if (!existsSync(join(SITE, "index.html"))) throw new Fail(`${SITE}/index.html not found`);
  const stamp = process.env.SWARM_STAMP;
  await checkBee();
  await checkStamp(stamp);
  const identity = await findIdentity();
  console.log(`Feed       identity "${IDENTITY}" (${identity.address}), topic "${FEED_TOPIC}"`);

  let password = process.env.SWARM_FEED_PASSWORD || "";
  if (!password && identity.type === "V3 Wallet") password = await askHidden(`Password for "${IDENTITY}": `);

  console.log(`Uploading  ${SITE} …`);
  const out = await swarmCli(
    [
      "feed", "upload", SITE,
      "--bee-api-url", BEE,
      "--identity", IDENTITY,
      "--topic-string", FEED_TOPIC,
      "--stamp", stamp,
      "--index-document", "index.html",
      "--pin",
      "--sync",
      "--yes",
      "--quiet",
      ...(password ? ["--password", password] : []),
    ],
    { capture: true },
  );
  const manifest = out.split("\n").map((l) => l.trim()).filter((l) => /^[0-9a-f]{64}$/.test(l)).pop();
  if (!manifest) throw new Fail(`swarm-cli did not print a feed manifest address:\n${out}`);

  await verifyServed(manifest);
  console.log(`Published  ${BEE}/bzz/${manifest}/ serves the local site/`);
  console.log(`           ${PUBLIC_GATEWAY}/bzz/${manifest}/ (public gateway; may take a few minutes)`);
  console.log("");
  await reportEns(manifest);
}

async function status() {
  const target = await reportEns(null);
  if (!target) return;
  let health;
  try {
    health = await getJson(`${BEE}/health`);
  } catch {
    console.log(`Swarm      not checked: no Bee node at ${BEE}.`);
    return;
  }
  const res = await fetch(`${BEE}/bzz/${target}/`);
  if (!res.ok) {
    console.log(`Swarm      ${BEE} (Bee ${health.version}) cannot fetch it: HTTP ${res.status}`);
    return;
  }
  const same = sha256(Buffer.from(await res.arrayBuffer())) === sha256(readFileSync(join(SITE, "index.html")));
  console.log(`Swarm      served; ${same ? "identical to" : "DIFFERENT from"} the local site/index.html`);
}

const command = process.argv[2];
const commands = { publish, status };
if (!commands[command]) {
  console.log("Usage: node scripts/publish_site_swarm.mjs publish|status   (see the comment at the top, and docs/website.md)");
  process.exit(command ? 2 : 0);
}
commands[command]().catch((e) => {
  console.error(`\nError: ${e instanceof Fail ? e.message : e.stack || e}`);
  process.exit(1);
});
