#!/usr/bin/env python3
"""Write the full reading route into stops/00-map.html (between the ROUTE markers),
taking each stop's time from its own eyebrow estimate. Run before build.py/epub.py."""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
STOPS = os.path.join(HERE, "stops")
WB_EACH = 15  # minutes per workbook exercise (Stop 22 estimates about 2½ hours for ten)


def minutes(num):
    f = next(x for x in os.listdir(STOPS) if x.startswith(f"{num:02d}-"))
    eb = re.search(r'<div class="eyebrow">(.*?)</div>', open(os.path.join(STOPS, f), encoding="utf-8").read()).group(1)
    m = re.search(r"about ([\d,]+) minutes", eb)
    if m:
        return int(m.group(1).replace(",", ""))
    m = re.search(r"about (\d+)(½)? hours?", eb)
    if not m:
        raise SystemExit(f"{f}: the eyebrow needs a reading time as 'about N minutes' or 'about N hours'")
    return int(m.group(1)) * 60 + (30 if m.group(2) else 0)


def hm(mins):
    h, m = divmod(int(round(mins / 5.0) * 5), 60)
    return f"{h} h {m:02d}" if h else f"{m} min"


S = lambda n, text: ("stop", n, text)          # noqa: E731
W = lambda ex, text: ("wb", ex, text)          # noqa: E731

LEGS = [
    ("The language, then the workspace", [
        S(0, "this map. Skim the file index; no need to read it."),
        S(1, "the primer, including <a href=\"#primer-methods\">methods and <code>self</code></a>. Do its checkpoint carefully: it tells you which concepts to revisit."),
        W([1, 2, 3, 4], "cursor, hex, errors, methods: the primer's ideas in your own hands."),
        S(2, "the manifests: crates, features, profiles, the no_std and wasm canaries."),
        S(3, "the smallest real crate, a warm-up for slices and borrowed <code>Vec</code>s."),
    ]),
    ("Bytes, hashes and wire formats", [
        S(4, "RLP, Keccak, tries and proofs: borrowing slices at speed."),
        W([8], "verify a header chain with slices and iterators, the shape of <code>verify.rs</code>."),
        S(5, "every protocol as a pure function: enums, <code>Result</code> and <code>?</code> everywhere."),
    ]),
    ("The light client and the EVM", [
        S(6, "the light client as a state machine you can test without a network."),
        S(7, "an EVM over verified state: traits, <code>Arc&lt;dyn Trait&gt;</code>, interior mutability."),
        W([10], "traits, generics versus <code>dyn</code>, and a decorator like the test oracle."),
    ]),
    ("Simulation, then the network begins", [
        S(8, "transaction requests, tracers and <code>eth_simulateV1</code>."),
        S(9, "libp2p, request/response and discovery: your first async-heavy stop."),
    ]),
    ("Sync loop and execution-layer peers", [
        S(10, "the sync loop: tasks, channels, <code>select!</code>, cancellation by drop."),
        W([5, 6, 7], "a registry behind a <code>Mutex</code>, a drop guard, a worker that holds only a <code>Weak</code>."),
        S(11, "RLPx, eth and snap sessions: an actor with a split reader and writer."),
    ]),
    ("The pool and the services", [
        S(12, "the peer pool and the trust chain from beacon anchor to Merkle proof."),
        S(13, "the EVM bridge, the log index and transactions."),
    ]),
    ("The verified reader and the tests", [
        S(14, "the biggest file: read its section map first, then the excerpts."),
        W([9], "the hedged race on a paused tokio clock, the shape of <code>hedged_race</code>."),
        S(15, "integration tests, live probes and how <code>#[ignore]</code> keeps them out of CI."),
    ]),
    ("The engine boundary", [
        S(16, "the engine: global state, the catalog, <code>ffi.rs</code> and <code>capi.rs</code>."),
    ]),
    ("UniFFI, end to end", [
        S(17, "what the macros write, who frees which buffer, how the checksums guard it, and how the Android build regenerates the bindings. Long: read it in two or three sittings, at its section breaks."),
    ]),
    ("The binaries", [
        S(18, "the Node addon: a scheduler and admission control around the C ABI."),
        S(19, "rpcd: a JSON-RPC daemon on the engine."),
        S(20, "roost, the light-client server."),
    ]),
    ("Generics over transports, and the whole picture", [
        S(21, "tor-poc: the same stack over Tor, generic over the transport."),
        S(23, "one request traced through every layer, and the final checkpoint."),
    ]),
]

NAMES = {0: "Stop 0", 22: "Workbook"}


def build():
    rows, total, cum, eight = [], 0, 0, None
    wb_ex = {1: "cursor", 2: "hex", 3: "errors", 4: "methods", 5: "registry", 6: "drop guard",
             7: "Weak worker", 8: "header chain", 9: "hedged race", 10: "traits"}
    for i, (title, items) in enumerate(LEGS, 1):
        leg = 0
        lis = []
        for kind, n, text in items:
            if kind == "stop":
                t = minutes(n)
                lis.append(f'<li><a href="#stop-{n:02d}">Stop {n}</a> <span class="t">{hm(t)}</span>: {text}</li>')
            else:
                t = WB_EACH * len(n)
                ex = ", ".join(str(x) for x in n)
                label = "exercise" if len(n) == 1 else "exercises"
                lis.append(f'<li><a href="#stop-22">Workbook {label} {ex}</a> <span class="t">{hm(t)}</span>: {text}</li>')
            leg += t
        total += leg
        if eight is None and total >= 480:
            eight = (i, total - leg)
        rows.append(f'<li><b>Leg {i} · {title}</b> <span class="t">about {hm(leg)}</span><ul>{"".join(lis)}</ul></li>')
    intro = (
        '<div class="prose" id="flight-plan">\n  <h2>The full route</h2>\n'
        f'  <p>The whole tour reads in about {round(total / 60)} hours, front to back. The route below is the same order, '
        f'cut into {len(LEGS)} legs, most of them four to seven hours long, with each workbook exercise placed right after the stop whose '
        'ideas it practises. Times come from each stop\'s own estimate: unhurried reading of the prose and every '
        'excerpt, plus two minutes per checkpoint question. On a long flight, start at Leg 1 and keep going: '
        f'eight hours take you {"through Leg 1 and " if eight[0] == 2 else f"through Legs 1 to {eight[0] - 1} and "}'
        f'about {hm(480 - eight[1])} into Leg {eight[0]}. Take breaks between legs, or between stops, not inside one.</p>\n'
        '  <p>Everything works offline: the exercises run against your local cargo cache, and the reading list points '
        'to your EPUBs and the Rust docs rustup installed.</p>\n</div>\n'
    )
    return intro + '<ol class="route-legs">' + "".join(rows) + "</ol>\n", total


def main():
    path = os.path.join(STOPS, "00-map.html")
    src = open(path, encoding="utf-8").read()
    block, total = build()
    start = src.index('<div class="prose" id="flight-plan">')
    if "<!--ROUTE-END-->" in src:
        end = src.index("<!--ROUTE-END-->")
    else:
        end = src.index("</ol>", start) + len("</ol>\n")
    src = src[:start] + block + "<!--ROUTE-END-->" + src[end:]
    open(path, "w", encoding="utf-8").write(src)
    print(f"route: {len(LEGS)} legs, about {total / 60:.1f} hours")


if __name__ == "__main__":
    main()
