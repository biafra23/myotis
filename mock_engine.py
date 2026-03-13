#!/usr/bin/env python3
"""Mock Engine API server that accepts all payloads (including V4/Electra)."""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

JWT_SECRET_PATH = "/home/biafra/.ethereum/geth/jwtsecret"


class EngineHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        method = body.get("method", "")
        params = body.get("params", [])
        req_id = body.get("id", 1)

        sys.stderr.write(f">> {method}\n")

        if method in (
            "engine_newPayloadV1", "engine_newPayloadV2",
            "engine_newPayloadV3", "engine_newPayloadV4",
        ):
            block_hash = params[0].get("blockHash", "0x" + "00" * 32) if params else "0x" + "00" * 32
            result = {"status": "VALID", "latestValidHash": block_hash, "validationError": None}

        elif method in (
            "engine_forkchoiceUpdatedV1", "engine_forkchoiceUpdatedV2",
            "engine_forkchoiceUpdatedV3", "engine_forkchoiceUpdatedV4",
        ):
            head = params[0].get("headBlockHash", "0x" + "00" * 32) if params else "0x" + "00" * 32
            result = {
                "payloadStatus": {"status": "VALID", "latestValidHash": head, "validationError": None},
                "payloadId": None,
            }

        elif method in (
            "engine_getPayloadV1", "engine_getPayloadV2",
            "engine_getPayloadV3", "engine_getPayloadV4",
        ):
            result = None

        elif method.startswith("engine_getBlobs"):
            # Return null for each requested versioned hash (we don't have blob data)
            hashes = params[0] if params else []
            result = [None] * len(hashes)

        elif method == "engine_exchangeCapabilities":
            result = [
                "engine_newPayloadV1", "engine_newPayloadV2",
                "engine_newPayloadV3", "engine_newPayloadV4",
                "engine_forkchoiceUpdatedV1", "engine_forkchoiceUpdatedV2",
                "engine_forkchoiceUpdatedV3", "engine_forkchoiceUpdatedV4",
                "engine_getPayloadV1", "engine_getPayloadV2",
                "engine_getPayloadV3", "engine_getPayloadV4",
                "engine_getBlobsV1",
                "engine_exchangeCapabilities",
            ]

        elif method == "eth_syncing":
            result = False

        elif method == "eth_blockNumber":
            result = "0x0"

        elif method == "eth_chainId":
            result = "0x1"

        elif method == "engine_getClientVersionV1":
            result = [{"code": "MK", "name": "MockEngine", "version": "1.0.0", "commit": "0x00000000"}]

        else:
            result = None

        resp = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp.encode())

    def log_message(self, fmt, *args):
        # Log method name for debugging
        try:
            length = int(self.headers.get("Content-Length", 0))
            # Already consumed, just log the request line
            pass
        except Exception:
            pass
        sys.stderr.write(f"{self.date_time_string()} {args[0]}\n")


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8551), EngineHandler)
    print("Mock Engine API listening on 127.0.0.1:8551")
    server.serve_forever()
