// #455: a worker environment torn down while a Promise completion is still
// queued. On Node 20.x, 22.x and 24.0-24.15 Node frees the completion
// function's context in its finalizer and only then drains the queued items
// through the completion callback, with a null env. The callback must not
// read that context. Run against a BUILT addon, like addon-api.test.mjs:
// node --test teardown.test.mjs, with MYOTIS_NODE_ADDON pointing at the .node
// (or a cargo output); without one the test skips.
//
// What it does: a Worker loads the addon, creates an engine handle (never
// started, so nothing touches the network), queues malformed reads the
// scheduler's workers answer at once, and then keeps its JS thread busy, so
// those completions sit in the queue when the main thread terminates it.
// Repeated, under MALLOC_PERTURB_ so that glibc overwrites freed memory: a
// read of the freed context then crashes or hangs the driver. Limits: the
// perturbation is glibc-only (macOS and Windows reuse freed memory silently),
// and the order that frees the context first is Node's own, so the test can
// only catch the bug on a Node that has it (on the Node 22.23.4 this was
// written with, the unfixed addon passed too). It pins the teardown path; the
// guard in scheduler.rs `complete` is the fix.

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const here = new URL('.', import.meta.url).pathname;
const candidates = process.env.MYOTIS_NODE_ADDON
  ? [process.env.MYOTIS_NODE_ADDON]
  : [
      join(here, 'myotis-node.node'),
      join(here, '..', 'target', 'release', 'libmyotis_node.so'),
      join(here, '..', 'target', 'debug', 'libmyotis_node.so'),
      join(here, '..', 'target', 'release', 'libmyotis_node.dylib'),
      join(here, '..', 'target', 'debug', 'libmyotis_node.dylib'),
    ];
const addonPath = candidates.find((p) => existsSync(p));
const skip = addonPath ? false : `no built addon at ${candidates.join(', ')} (set MYOTIS_NODE_ADDON)`;

// Runs in a child process, so a crash fails this test instead of the runner.
const driver = `
const { Worker } = require('node:worker_threads');
const [addon, base] = process.argv.slice(1);
const body = \`
  const { workerData, parentPort } = require('node:worker_threads');
  const mod = { exports: {} };
  process.dlopen(mod, workerData.addon);
  const m = mod.exports;
  // The scheduler admits 4 reads per handle (PER_HANDLE); several handles put
  // more completions in the queue at once.
  for (let k = 0; k < 8; k++) {
    const h = m.create('mainnet', workerData.dir + '/h' + k);
    if (h < 0) throw new Error('create failed: ' + h);
    for (let i = 0; i < 4; i++) m.requestAccountJson(h, 'not-an-address').catch(() => {});
  }
  parentPort.postMessage('queued');
  const until = Date.now() + 2000;
  while (Date.now() < until) {}
\`;
(async () => {
  for (let round = 0; round < 20; round++) {
    const w = new Worker(body, { eval: true, workerData: { addon, dir: base + '/r' + round } });
    await new Promise((ok, fail) => { w.once('message', ok); w.once('error', fail); });
    await new Promise((r) => setTimeout(r, 20));
    await w.terminate();
  }
  console.log('ok');
})().catch((e) => { console.error(e); process.exit(2); });
`;

test('terminating a worker with completions queued does not touch freed state (#455)', { skip }, () => {
  const base = mkdtempSync(join(tmpdir(), 'myotis-teardown-'));
  try {
    const r = spawnSync(process.execPath, ['-e', driver, resolve(addonPath), base], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, MALLOC_PERTURB_: '165' },
    });
    assert.equal(r.signal, null, `driver killed by ${r.signal}\n${r.stderr}`);
    assert.equal(r.status, 0, `driver exited ${r.status}\n${r.stderr}`);
    assert.match(r.stdout, /ok/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
