#!/usr/bin/env python3
"""Unit tests for the MetaMask replay harness (replay.py).

These exercise the *pure* logic — param normalization, dedup keying, gating
classification — plus integrity of the golden session fixture. No daemon or
network required, so they run in CI (stdlib unittest only; no pip deps).

The full replay (replay.py against a live daemon) remains a manual pre-PR check;
these tests guard the harness's decision logic and the fixture's contract so a
silent change there can't quietly weaken that manual gate.

    python3 -m unittest discover -s tools/mm-replay -p 'test_*.py'
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import replay  # noqa: E402

SESSION = os.path.join(HERE, "sessions", "metamask-send-mainnet.jsonl")


class LatestifyTests(unittest.TestCase):
    def test_rewrites_small_block_hex_and_pending(self):
        self.assertEqual(replay.latestify(["0x1388"]), ["latest"])
        self.assertEqual(replay.latestify(["pending"]), ["latest"])
        self.assertEqual(replay.latestify(["0x1388", "latest"]), ["latest", "latest"])

    def test_preserves_addresses_hashes_objects_and_ambiguous_0x(self):
        addr = "0xb1f8e55c7f64d203c1400b9d8555d050f94adf39"  # 42 chars > 12 -> kept
        digest = "0x" + "ab" * 32                              # 66 chars      -> kept
        obj = {"to": addr, "data": "0xdead"}                   # eth_call arg  -> kept
        self.assertEqual(
            replay.latestify([addr, digest, obj, "0x"]),
            [addr, digest, obj, "0x"],
        )


class KeyTests(unittest.TestCase):
    def test_eth_call_key_is_case_and_input_alias_insensitive(self):
        a = {"method": "eth_call", "params": [{"to": "0xAbC", "data": "0x12"}, "latest"]}
        b = {"method": "eth_call", "params": [{"to": "0xabc", "input": "0x12"}, "0x1388"]}
        self.assertEqual(replay.key(a), replay.key(b))
        self.assertEqual(replay.key(a), ("eth_call", "0xabc", "0x12"))

    def test_non_eth_call_key_ignores_params(self):
        self.assertEqual(
            replay.key({"method": "eth_getBalance", "params": ["0xabc", "latest"]}),
            ("eth_getBalance", "", ""),
        )


class GatingTests(unittest.TestCase):
    def test_skip_and_best_effort_methods_are_non_gating(self):
        for m in ("eth_sendRawTransaction", "eth_getTransactionReceipt", "eth_getTransactionByHash"):
            self.assertFalse(replay.is_gating({"method": m, "params": []}), m)

    def test_balance_checker_sweep_is_non_gating(self):
        req = {"method": "eth_call", "params": [{"to": replay.BALANCE_CHECKER.upper(), "data": "0x"}]}
        self.assertFalse(replay.is_gating(req))

    def test_core_wallet_methods_are_gating(self):
        for m in ("eth_estimateGas", "eth_getBalance", "eth_getCode",
                  "eth_getBlockByNumber", "eth_getTransactionCount", "eth_blockNumber"):
            self.assertTrue(replay.is_gating({"method": m, "params": []}), m)
        self.assertTrue(replay.is_gating({"method": "eth_call", "params": [{"to": "0xsomeContract"}]}))


class GoldenSessionFixtureTests(unittest.TestCase):
    """The captured session is the contract the manual replay checks against."""

    @classmethod
    def setUpClass(cls):
        cls.rows = []
        with open(SESSION) as f:
            for line in f:
                line = line.strip()
                if line:
                    cls.rows.append(json.loads(line))  # asserts JSONL is well-formed

    def test_each_record_has_a_request_with_a_method(self):
        self.assertGreater(len(self.rows), 50)
        for r in self.rows:
            self.assertIn("req", r)
            self.assertIsInstance(r["req"], dict)
            self.assertIn("method", r["req"])

    def test_covers_the_metamask_send_gating_contract(self):
        methods = {r["req"]["method"] for r in self.rows}
        required = {
            "eth_call", "eth_estimateGas", "eth_getBalance", "eth_getCode",
            "eth_getBlockByNumber", "eth_getTransactionCount", "eth_blockNumber",
            "eth_sendRawTransaction",
        }
        missing = required - methods
        self.assertFalse(missing, f"golden session no longer covers MetaMask methods: {missing}")

    def test_exercises_the_non_gating_balance_checker_sweep(self):
        def is_sweep(req):
            p = req.get("params") or [{}]
            return req.get("method") == "eth_call" and isinstance(p[0], dict) \
                and (p[0].get("to") or "").lower() == replay.BALANCE_CHECKER
        self.assertTrue(any(is_sweep(r["req"]) for r in self.rows),
                        "golden session should contain the BalanceChecker sweep (non-gating path)")

    def test_dedup_collapses_metamask_polling(self):
        # MetaMask polls heavily; unique (method,to,calldata) keys must be far fewer.
        keys = {replay.key(r["req"]) for r in self.rows}
        self.assertLess(len(keys), len(self.rows))


if __name__ == "__main__":
    unittest.main()
