"""HTTP service for the sparse-Merkle batch-change verifier.

Endpoints
---------
GET  /                 verification page
GET  /static/*         static assets
GET  /healthz          liveness/readiness JSON
POST /api/verify       verify one batch submission (stateless; never caches
                       prior verdicts). Optional "licenses" add prefix-permit
                       capacity constraints checked only after both roots pass.
POST /api/demo         build a valid two-key shared-prefix demo payload
                       (including a nested/overlapping license set)

Configuration via environment:
  PORT=8080   HOST=0.0.0.0   MAX_BODY_BYTES=1048576
"""

from __future__ import annotations

import json
import os
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from smt import (
    DEFAULT,
    DEPTH,
    ProofError,
    build_tree,
    key_to_path,
    proof_for_changes,
    result_dict,
    sha256,
    verify_batch,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(1024 * 1024)))


def _demo_payload() -> dict:
    # Two keys sharing a long prefix: ...00 and ...01
    key_a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0"
    key_b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde1"
    other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    old_entries = {
        key_a: sha256(b"neutron-device-A@v1"),
        key_b: sha256(b"neutron-device-B@v1"),
        other: sha256(b"unchanged-device-C@v1"),
    }
    new_entries = dict(old_entries)
    new_entries[key_a] = sha256(b"neutron-device-A@v2")
    new_entries[key_b] = sha256(b"neutron-device-B@v2")

    old_root = build_tree(old_entries)
    new_root = build_tree(new_entries)
    siblings = proof_for_changes(old_entries, [key_a, key_b])
    shared = key_to_path(key_a)[1][:255]  # the 255 leading bits both keys share
    return {
        "old_root": old_root.hex(),
        "new_root": new_root.hex(),
        "leaves": [
            {
                "key": key_a,
                "old_leaf": old_entries[key_a].hex(),
                "new_leaf": new_entries[key_a].hex(),
            },
            {
                "key": key_b,
                "old_leaf": old_entries[key_b].hex(),
                "new_leaf": new_entries[key_b].hex(),
            },
        ],
        "shared_siblings": siblings,
        # Nested + overlapping prefix licenses, deliberately listed
        # widest-first: an input-order greedy would mis-allocate, while the
        # verifier returns the lexicographically smallest license-id witness
        # (wide license ends exhausted, the narrow one still has spare quota).
        "licenses": [
            {"id": "NEUTRON-LINE-WIDE", "prefix": "0b0", "quota": 1},
            {"id": "NEUTRON-PAIR-255", "prefix": "0b" + shared, "quota": 1},
            {"id": "NEUTRON-A0-EXACT", "prefix": "0b" + shared + "0", "quota": 2},
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SmtVerifier/1.0"

    def log_message(self, fmt: str, *args) -> None:  # concise structured logs
        import datetime

        msg = fmt % args
        print(
            f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} "
            f"{self.address_string()} {msg}",
            flush=True,
        )

    # -- helpers ----------------------------------------------------------- #
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, rel: str, ctype: str) -> None:
        path = (STATIC_DIR / rel).resolve()
        if not str(path).startswith(str(STATIC_DIR)) or not path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> object:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ProofError("缺少请求体", "bad_request")
        if length > MAX_BODY_BYTES:
            raise ProofError(
                f"请求体超过 {MAX_BODY_BYTES} 字节上限", "body_too_large"
            )
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProofError(f"请求体不是合法 JSON: {exc}", "bad_json")

    # -- routing ----------------------------------------------------------- #
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send_file("index.html", "text/html; charset=utf-8")
        elif path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "depth": DEPTH,
                    "empty_root": DEFAULT[DEPTH].hex(),
                },
            )
        elif path.startswith("/static/"):
            rel = path[len("/static/") :]
            ctype = (
                "application/javascript; charset=utf-8"
                if rel.endswith(".js")
                else "text/css; charset=utf-8"
                if rel.endswith(".css")
                else "application/octet-stream"
            )
            self._send_file(rel, ctype)
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/demo":
            self._send_json(HTTPStatus.OK, {"ok": True, "payload": _demo_payload()})
            return
        if path != "/api/verify":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return

        verification_id = uuid.uuid4().hex
        try:
            payload = self._read_json()
            result = verify_batch(payload)
        except ProofError as exc:
            # Every rejection carries a locatable code; a previous success is
            # never echoed — the response describes only this submission.
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": False,
                    "verification_id": verification_id,
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "level": exc.level,
                    },
                },
            )
            return
        except Exception as exc:  # defensive: never leak a stack trace as success
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "verification_id": verification_id,
                    "error": {"code": "bad_request", "message": str(exc)},
                },
            )
            return

        self._send_json(HTTPStatus.OK, result_dict(result, verification_id))


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"sparse-merkle verifier listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
