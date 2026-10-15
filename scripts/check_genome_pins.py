#!/usr/bin/env python3
"""Cross-check the pinned Genome (.gno) constants against Gnosis Chain state.

Both engines resolve .gno names with three pins (Java `EnsAddresses.GNOSIS_GENOME_*`,
Rust `myotis_evm::ens::GENOME_*`): the SID registry, the .gno registrar ("Base") and
the root node the tree hashes under. They were taken from Blockscout's ENS service
config and SPACE ID's SDK, not read from chain, so this script asks the chain:

  * Base.baseNode()    must be namehash("gno") under the pinned root
                       (0xb610…, which the unit tests derive from that root — a
                       match therefore also confirms the root);
  * Base.sidRegistry() must be the pinned registry;
  * registry.owner(baseNode) must be the registrar (it owns the .gno node).

It needs only a Gnosis Chain JSON-RPC endpoint — by default a local Myotis node on
Gnosis (`./gradlew :app:run -Pnetwork=gnosis`, verified RPC on port 8546), so the
answers are the beacon-verified state rather than a third party's word:

    scripts/check_genome_pins.py [--rpc http://127.0.0.1:8546]

Exit status 0 = every pin matches, 1 = a mismatch (including a call the contract
rejected — a pinned address without the expected function is a wrong pin), 2 = the
endpoint could not be reached.
"""

import argparse
import json
import sys
import urllib.request

REGISTRY = "0x5dc881dda4e4a8d312be3544ad13118d1a04cb17"
REGISTRAR = "0x942fcaf68a0c264d5447b03a2011b395a899f2d3"
# namehash("gno") under the pinned root c4a8c56f…a63 (EnsResolverTest /
# ens::tests::genome_pins_match_the_java_engine compute it).
GNO_NODE = "b610db9c8c31e1a841d7e46f0184e3ae40589639b590138de0de5df028245ce2"

SEL_BASE_NODE = "ddf7fcb0"      # baseNode()
SEL_SID_REGISTRY = "f9482e1a"   # sidRegistry()
SEL_OWNER = "02571be3"          # owner(bytes32)


def eth_call(rpc, to, data):
    """The call's return as lowercase hex (no 0x), or a string starting with
    'error: ' when the node answered with a JSON-RPC error (e.g. a revert).
    Transport failures raise."""
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": "0x" + data}, "latest"],
    }).encode()
    req = urllib.request.Request(rpc, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        out = json.load(resp)
    if "error" in out:
        return f"error: {out['error']}"
    return out["result"][2:].lower()


def word(ret):
    return ret if ret.startswith("error: ") else ret[:64]


def word_address(ret):
    return ret if ret.startswith("error: ") else "0x" + ret[24:64]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc", default="http://127.0.0.1:8546",
                    help="Gnosis Chain JSON-RPC URL (default: local Myotis on Gnosis)")
    args = ap.parse_args()

    try:
        base_node = word(eth_call(args.rpc, REGISTRAR, SEL_BASE_NODE))
        sid_registry = word_address(eth_call(args.rpc, REGISTRAR, SEL_SID_REGISTRY))
        gno_owner = word_address(eth_call(args.rpc, REGISTRY, SEL_OWNER + GNO_NODE))
    except (OSError, ValueError) as e:  # unreachable endpoint / not JSON: "could not check"
        print(f"RPC failed: {e}", file=sys.stderr)
        return 2

    checks = [
        ("registrar.baseNode() == namehash('gno') under the pinned root", base_node, GNO_NODE),
        ("registrar.sidRegistry() == pinned registry", sid_registry, REGISTRY),
        ("registry.owner(gno node) == pinned registrar", gno_owner, REGISTRAR),
    ]
    ok = True
    for label, got, want in checks:
        good = got == want
        ok &= good
        print(f"{'OK  ' if good else 'FAIL'} {label}\n     got  {got}\n     want {want}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
