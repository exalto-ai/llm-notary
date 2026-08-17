#!/usr/bin/env python3
"""Loopback-only hosted-share fixture for the daemon persistence E2E."""

import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


API_KEY = "llmn_v1_" + "1" * 32 + "_" + "2" * 64
PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
KEY_ID = "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    shares: dict[str, dict[str, object]] = {}
    last_share_id = ""

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.respond_json({"status": "ready"})
            return
        if self.path == "/debug/upload":
            share = type(self).shares.get(type(self).last_share_id, {})
            uploaded = share.get("uploaded", b"")
            assert isinstance(uploaded, bytes)
            self.respond_json(
                {
                    "size_bytes": len(uploaded),
                    "sha256": hashlib.sha256(uploaded).hexdigest(),
                }
            )
            return
        if self.path == "/api/notary":
            self.respond_json(
                {
                    "format": "notary/registry/v1",
                    "generation": 1,
                    "active_key_id": KEY_ID,
                    "notaries": [
                        {
                            "name": "Alice",
                            "operator": "Exalto",
                            "host": "notary",
                            "port": 7047,
                            "transport": "tcp",
                            "key_id": KEY_ID,
                            "public_key": PUBLIC_KEY,
                            "status": "active",
                            "valid_from_unix_ms": 0,
                            "valid_until_unix_ms": None,
                            "notarize_until_unix_ms": None,
                        }
                    ],
                }
            )
            return
        if self.path.startswith("/api/shares/"):
            if not self.authorized():
                return
            share_id = self.path.removeprefix("/api/shares/")
            if share_id not in type(self).shares:
                self.send_error(404)
                return
            self.respond_json(self.share(share_id, "queued"))
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.authorized():
            return
        if self.path == "/api/shares":
            request = json.loads(self.read_body())
            if request.get("archive_format") != "notary/trace-package/v1":
                self.send_error(400)
                return
            share_id = f"share-e2e-{len(type(self).shares) + 1}"
            type(self).shares[share_id] = {
                "expected_size": int(request["size_bytes"]),
                "expected_sha256": request["sha256"],
                "uploaded": b"",
            }
            type(self).last_share_id = share_id
            self.respond_json(
                {
                    "share": self.share(share_id, "uploading"),
                    "upload": {
                        "method": "PUT",
                        "url": f"http://127.0.0.1:9797/upload/{share_id}",
                        "headers": {
                            "content-length": str(request["size_bytes"]),
                            "content-type": "application/vnd.exalto.notary.trace-package+zip",
                        },
                    },
                },
                status=201,
            )
            return
        if self.path.startswith("/api/shares/") and self.path.endswith("/complete"):
            share_id = self.path.removeprefix("/api/shares/").removesuffix("/complete")
            share = type(self).shares.get(share_id)
            if share is None:
                self.send_error(404)
                return
            uploaded = share["uploaded"]
            assert isinstance(uploaded, bytes)
            if len(uploaded) != share["expected_size"] or hashlib.sha256(
                uploaded
            ).hexdigest() != share["expected_sha256"]:
                self.send_error(409)
                return
            self.respond_json(self.share(share_id, "queued"))
            return
        self.send_error(404)

    def do_PUT(self) -> None:
        if not self.path.startswith("/upload/"):
            self.send_error(404)
            return
        share_id = self.path.removeprefix("/upload/")
        share = type(self).shares.get(share_id)
        if share is None:
            self.send_error(404)
            return
        share["uploaded"] = self.read_body()
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authorized(self) -> bool:
        if self.headers.get("Authorization") == f"Bearer {API_KEY}":
            return True
        self.send_error(401)
        return False

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    @staticmethod
    def share(share_id: str, state: str) -> dict[str, object]:
        return {
            "id": share_id,
            "state": state,
            "visibility": "unlisted",
            "status_url": f"/api/shares/{share_id}",
            "failure_code": None,
            "share_url": f"/library/{share_id}",
            "package_url": f"/api/shares/{share_id}/package",
        }

    def respond_json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        print(f"share fixture: {message % args}", flush=True)


def main() -> None:
    ThreadingHTTPServer(("127.0.0.1", 9797), Handler).serve_forever()


if __name__ == "__main__":
    main()
