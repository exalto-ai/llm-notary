#!/usr/bin/env python3
"""Private-CA TLS provider fixture used only by compose.daemon-e2e.yml."""

import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def read_request_body(handler: BaseHTTPRequestHandler) -> bytes:
    if handler.headers.get("Transfer-Encoding", "").lower() == "chunked":
        body = bytearray()
        while True:
            size_line = handler.rfile.readline()
            if not size_line:
                raise ConnectionError("request ended inside chunked body")
            size = int(size_line.split(b";", 1)[0], 16)
            if size == 0:
                while handler.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                return bytes(body)
            body.extend(handler.rfile.read(size))
            if handler.rfile.read(2) != b"\r\n":
                raise ConnectionError("malformed chunk delimiter")
    length = int(handler.headers.get("Content-Length", "0"))
    return handler.rfile.read(length)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def date_time_string(self, timestamp: float | None = None) -> str:
        del timestamp
        return "Tue, 14 Nov 2023 22:13:20 GMT"

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.respond_json({"service": "offline-openai-fixture"})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        body = read_request_body(self)
        request = json.loads(body)
        if request.get("model") != "fixture-model":
            self.send_error(400)
            return
        self.respond_json(
            {
                "id": "chatcmpl-daemon-e2e",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "fixture-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "offline daemon E2E response",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 5,
                    "total_tokens": 9,
                },
            }
        )

    def respond_json(self, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        print(f"provider fixture: {self.address_string()} {message % args}", flush=True)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        os.environ.get("DAEMON_E2E_PROVIDER_CERT", "/fixtures/server.pem"),
        os.environ.get("DAEMON_E2E_PROVIDER_KEY", "/fixtures/server.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
