#!/usr/bin/env python3
"""Census for the log-index presets (ui: LogIndexPresets, docs/how-it-works/log-index-presets.md).

AUTHORING TOOL ONLY. It reads public chain data over a JSON-RPC endpoint the
caller names, to produce the CONSTANTS the presets ship — each contract's
creation block, the log count, the share of blocks whose header bloom matches a
watch set, and the size of a matching block's receipts. Nothing it prints is
served to a wallet: the walk verifies every log it stores against its block's
receiptsRoot, and the size figures are estimates the UI labels as such.

The from-blocks are the one output nothing downstream re-checks. The walk only
descends TO a contract's fromBlock and cannot notice that the contract existed
below it, so a from-block above the real deployment silently hides that history
(LogIndexPresets' KDoc). The guards are here, at authoring time: this script
picks the CREATION block by eth_getCode bisection (the safe direction — at worst
it walks a few empty blocks), and every value is cross-checked against a second
reference — the repo's existing pins, the protocol client's own config, or, for
a contract with neither, a second run of this script against an independent
endpoint. A single endpoint's answer is not enough on its own. CLAUDE.md's data-source rule
(devp2p/libp2p only) governs what the wallet serves; it is why no default
endpoint is configured here — the caller names one, per network.

    python3 -I scripts/logindex_preset_census.py --rpc <url> --preset railgun-mainnet
    python3 -I scripts/logindex_preset_census.py --rpc <url> --preset all-mainnet --samples 400

Output: one JSON object per preset on stdout, with `deployments`, `logs`,
`bloomCandidateShare` (per contract and for the union), and
`receiptBytesPerCandidate` (eth/69 wire form, no per-receipt bloom).
"""

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request

# ---- keccak-256 (pure Python; only ever hashes 20-byte addresses here) ----

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = _f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out[:32]


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def bloom_bits(addr_hex: str):
    h = keccak256(bytes.fromhex(addr_hex[2:]))
    return [((h[i] << 8) | h[i + 1]) & 2047 for i in (0, 2, 4)]


def bloom_has(bloom: bytes, bits) -> bool:
    return all(bloom[255 - b // 8] & (1 << (b % 8)) for b in bits)


# ---- the presets' contracts (lower bounds; the census finds the creation block) ----

PRESETS = {
    "railgun-mainnet": ("mainnet", 14_000_000, ["0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"]),
    "railgun-sepolia": ("sepolia", 5_000_000, ["0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea"]),
    "swarm-gnosis": ("gnosis", 31_000_000, [
        "0x45a1502382541Cd610CC9068e88727426b696293",
        "0x47EeF336e7fE5bED98499A4696bce8f28c1B0a8b",
        "0xda2a16EE889E7F04980A8d597b48c8D51B9518F4",
        "0x5069cdfB3D9E56d23B1cAeE83CE6109A7E4fd62d",
    ]),
    "privacy-pools-mainnet": ("mainnet", 22_000_000, [
        "0x6818809EefCe719E480a7526D76bD3e561526b46",
        "0xF241d57C6DebAe225c0F2e6eA1529373C9A9C9fB",
        "0xE859c0BD25f260BaEE534Fb52E307D3B64D24572",
        "0xB419C2867aB3CBC78921660cB95150d95A94CE86",
    ]),
    "privacy-pools-sepolia": ("sepolia", 8_000_000, [
        "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB",
        "0x644d5A2554d36e27509254F32ccfeBe8cd58861f",
        "0x6709277E170DEe3E54101cDb73a450E392ADfF54",
        "0x0b062Fe33c4f1592D8EA63f9a0177FcA44374C0f",
    ]),
    "tornado-mainnet": ("mainnet", 8_000_000, [
        "0xB20c66C4DE72433F3cE747b58B86830c459CA911",
        "0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2",
        "0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc",
        "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936",
        "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
        "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",
        "0x199112eb461ea7eec1d75b33343542e1d069b41c",
        "0x398971a7ae0fed4ae435f353ef00d3d4e4c18fd4",
        "0xf22487b84a618192aa68c0e1da24e9bbd892f774",
        "0x74185a3f30b873c0ce1f4257298d1cda61be2f9f",
        "0xc11197f71c7730c8b5db7c84191e07575f1db896",
        "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
        "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144",
        "0x07687e702b410Fa43f4cB4Af7FA097918ffD2730",
        "0x23773E65ed146A459791799d01336DB287f25334",
        "0x22aaA7720ddd5388A3c0A3333430953C68f1849b",
        "0x03893a7c7463AE47D46bc7f091665f1893656003",
        "0x2717c5e28cf931547B621a5dddb772Ab6A35B701",
        "0xD21be7248e0197Ee08E0c20D4a96DEBdaC3D20Af",
        "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307",
        "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBa9D",
        "0x169AD27A470D064DEDE56a2D3ff727986b15D52B",
        "0x0836222F2B2B24A3F36f98668Ed8F0B38D1a872f",
        "0x178169B423a011fff22B9e3F3abeA13414dDD0F1",
        "0x610B717796ad172B316836AC95a2ffad065CeaB4",
        "0xbB93e510BbCD0B7beb5A853875f9eC60275CF498",
    ]),
    "tornado-sepolia": ("sepolia", 5_000_000, [
        "0x4e69fD587118dFb64957d18654E3894118E9B1BF",
        "0xD6663593E71e4916eCb6f6606e1A6FbfA1634ffA",
        "0x8C4A04d872a6C1BE37964A21ba3a138525dFF50b",
        "0x8cc930096B4Df705A007c4A039BDFA1320Ed2508",
        "0x0E999C5285141ccB6dFaE68A0921F37ABd3e6A87",
        "0x9480Be3964642efcD6CeBdb3570db8dC0f788908",
        "0x83091415b54d764E215153Ff54B36cCd44122e6e",
        "0x7eE90edc51c3739Af3ee277e09ADE3F3d6bad4AF",
        "0x8d10d506d29fc62abb8a290b99f66db27fc43585",
        "0x3d1C943dfb2C8d9905B0Da0AFD18615915fF343A",
        "0x6921fd1a97441dd603a997ED6DDF388658daf754",
    ]),
}


class Rpc:
    def __init__(self, url):
        self.url = url
        self.n = 0

    def call(self, method, params, tries=6):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        for i in range(tries):
            try:
                req = urllib.request.Request(self.url, body, {"content-type": "application/json", "user-agent": "logindex-preset-census/1"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    out = json.load(r)
                self.n += 1
                if "error" in out:
                    raise RuntimeError(out["error"])
                return out["result"]
            except RuntimeError:
                raise
            except urllib.error.HTTPError as e:
                # Some endpoints answer a refused request (a range too wide for
                # the plan) with HTTP 4xx and a JSON-RPC error body.
                if 400 <= e.code < 500 and e.code != 429:
                    raise RuntimeError(e.read().decode(errors="replace")[:200])
                if i == tries - 1:
                    raise
                time.sleep(2 ** i)
            except Exception:  # transport: back off and retry
                if i == tries - 1:
                    raise
                time.sleep(2 ** i)


def creation_block(rpc, addr, lo, hi):
    """Smallest block at which `addr` has code (its creation block)."""
    if rpc.call("eth_getCode", [addr, hex(hi)]) in ("0x", "0x0"):
        return None
    if rpc.call("eth_getCode", [addr, hex(lo)]) not in ("0x", "0x0"):
        raise SystemExit(f"{addr}: has code at the lower bound {lo}; lower it")
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if rpc.call("eth_getCode", [addr, hex(mid)]) in ("0x", "0x0"):
            lo = mid
        else:
            hi = mid
    return hi


def count_logs(rpc, addrs, lo, hi, step, max_step):
    total, a = 0, lo
    while a <= hi:
        b = min(hi, a + step - 1)
        try:
            total += len(rpc.call("eth_getLogs", [{"address": addrs, "fromBlock": hex(a), "toBlock": hex(b)}]))
            a = b + 1
            step = min(step * 2, max_step)
        except RuntimeError:
            if step <= 1:
                raise
            step = max(1, step // 4)
    return total


def _rlp_len(n):  # header length for a payload of n bytes
    return 1 if n < 56 else 1 + (n.bit_length() + 7) // 8


def receipts_wire_bytes(receipts):
    """Approximate eth/69 wire size (no per-receipt bloom) of a block's receipts."""
    total = 0
    for r in receipts:
        logs = 0
        for l in r.get("logs", []):
            data = (len(l["data"]) - 2) // 2
            topics = 33 * len(l["topics"])
            body = 21 + _rlp_len(topics) + topics + _rlp_len(data) + data
            logs += _rlp_len(body) + body
        body = 1 + 1 + 9 + _rlp_len(logs) + logs
        total += _rlp_len(body) + body
    return total + _rlp_len(total)


def census(rpc, name, samples, log_step, max_step, skip_logs=False):
    network, lower, addrs = PRESETS[name]
    head = int(rpc.call("eth_blockNumber", []), 16)
    deployments = {}
    for a in addrs:
        deployments[a] = creation_block(rpc, a, lower, head)
        print(f"  {name}: {a} created at {deployments[a]}", file=sys.stderr)
    live = {a: b for a, b in deployments.items() if b is not None}
    low = min(live.values())
    logs = None if skip_logs else count_logs(rpc, list(live), low, head, log_step, max_step)
    bits = {a: bloom_bits(a) for a in live}
    hits = {a: 0 for a in live}
    union = 0
    in_range = {a: 0 for a in live}
    receipt_bytes, receipt_n = 0, 0
    rnd = random.Random(7)
    for _ in range(samples):
        n = rnd.randint(low, head)
        blk = rpc.call("eth_getBlockByNumber", [hex(n), False])
        bloom = bytes.fromhex(blk["logsBloom"][2:])
        any_hit = False
        for a, b in bits.items():
            if n >= live[a]:
                in_range[a] += 1
                if bloom_has(bloom, b):
                    hits[a] += 1
                    any_hit = True
        if any_hit:
            union += 1
            if receipt_n < max(20, samples // 10):
                receipt_bytes += receipts_wire_bytes(rpc.call("eth_getBlockReceipts", [hex(n)]))
                receipt_n += 1
    return {
        "preset": name,
        "network": network,
        "head": head,
        "deployments": deployments,
        "logs": logs,
        "samples": samples,
        "bloomCandidateShare": {
            "perContract": {a: round(hits[a] / max(1, in_range[a]), 4) for a in live},
            "union": round(union / samples, 4),
        },
        "receiptBytesPerCandidate": receipt_bytes // max(1, receipt_n),
        "rpcCalls": rpc.n,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rpc", required=True, help="JSON-RPC endpoint of the preset's network (archive state for eth_getCode)")
    p.add_argument("--preset", required=True, help="a preset name, or all-<network>")
    p.add_argument("--samples", type=int, default=300, help="blocks sampled for bloom share and receipt size")
    p.add_argument("--log-step", type=int, default=50_000, help="initial eth_getLogs window")
    p.add_argument("--skip-logs", action="store_true", help="sample blooms and receipts only (logs: null)")
    p.add_argument("--max-step", type=int, default=500_000, help="widest eth_getLogs window (the endpoint's limit)")
    a = p.parse_args()
    names = [n for n, v in PRESETS.items() if v[0] == a.preset[4:]] if a.preset.startswith("all-") else [a.preset]
    rpc = Rpc(a.rpc)
    for n in names:
        print(json.dumps(census(rpc, n, a.samples, a.log_step, a.max_step, a.skip_logs)), flush=True)


if __name__ == "__main__":
    main()
