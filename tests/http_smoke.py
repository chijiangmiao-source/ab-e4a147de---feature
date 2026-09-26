#!/usr/bin/env python3
"""HTTP smoke acceptance for the running (or locally started) verifier.

Checks against the REAL API:
  1. GET  /healthz                         -> 200 status=ok
  2. GET  /                                -> page HTML
  3. POST /api/demo + POST /api/verify     -> shared-prefix two-key change passes,
                                              BOTH recomputed roots match, and the
                                              demo's overlapping prefix permits get
                                              the stable lex-min allocation
  4. tampered sibling digest               -> ok=false, old_root_mismatch
  5. extra proof node (off path) -> ok=false, extra_proof_node
  6. legacy request without permits -> accepted, no allocation field
  7. insufficient permit capacity  -> ok=false, permit_capacity
  8. key outside every permit      -> ok=false, permit_key_uncovered
  9. duplicate permit id           -> ok=false, permit_duplicate_id

Usage: http_smoke.py [base_url]   (default http://127.0.0.1:${PORT:-8080})
Exits 0 only when every assertion holds.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(HERE, "..", "app")


def wait_ready(base: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=2) as r:
                if r.status == 200 and json.load(r)["status"] == "ok":
                    return
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise SystemExit(f"server did not become ready at {base}: {last}")


def get(base: str, path: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, r.read()


def post(base: str, path: str, body: dict | None) -> dict:
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as exc:
        return json.load(exc)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else f"http://127.0.0.1:{os.environ.get('PORT', '8080')}"
    proc = None
    if "--spawn" in sys.argv:
        port = str(os.environ.get("SMOKE_PORT", "8090"))
        env = dict(os.environ, PORT=port, HOST="127.0.0.1")
        proc = subprocess.Popen(
            [sys.executable, os.path.join(APP_DIR, "server.py")],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        base = f"http://127.0.0.1:{port}"

    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        mark = "PASS" if cond else "FAIL"
        print(f"[{mark}] {name}" + (f" -- {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    try:
        wait_ready(base)

        status, body = get(base, "/healthz")
        health = json.loads(body)
        check("healthz 200 + status ok", status == 200 and health.get("status") == "ok")

        status, page = get(base, "/")
        check("index page served",
              status == 200 and b"SHA-256(00" in page and b"/api/verify" in page)

        demo = post(base, "/api/demo", {})
        check("demo payload generated",
              demo.get("ok") and len(demo["payload"]["leaves"]) == 2
              and demo["payload"]["leaves"][0]["key"] < demo["payload"]["leaves"][1]["key"])
        check("demo payload carries overlapping prefix permits",
              len(demo["payload"].get("permits", [])) == 2)

        payload = demo["payload"]
        first_id = None
        ok = post(base, "/api/verify", payload)
        check("shared-prefix two-key change ACCEPTED",
              ok.get("ok") is True, json.dumps(ok, ensure_ascii=False)[:400])
        if ok.get("ok"):
            check("  dual roots both recomputed equal",
                  ok["recomputed_old_root"] == ok["old_root"]
                  and ok["recomputed_new_root"] == ok["new_root"])
            check("  trace has 256 merge levels",
                  len(ok["merges"]) == 256)
            check("  trace carries old+new left/right per level",
                  all({"old_left", "old_right", "new_left", "new_right",
                       "old_parent", "new_parent"} <= set(m) for m in ok["merges"]))
            check("  default ladder exposed (257 entries)",
                  len(ok["default_ladder"]) == 257)
            alloc = ok.get("permit_allocation") or {}
            usage = {p["permit_id"]: p for p in alloc.get("permits", [])}
            check("  permit allocation present, one row per changed key",
                  [a["key"] for a in alloc.get("assignments", [])]
                  == ok["changed_keys"])
            check("  overlapping permits -> stable lex-min witness",
                  [a["permit_id"] for a in alloc.get("assignments", [])]
                  == ["PERMIT-WIDE", "PERMIT-LEAF-B"])
            check("  wider permit exhausted while narrower still available",
                  usage.get("PERMIT-WIDE", {}).get("used") == 1
                  and usage["PERMIT-WIDE"]["unused"] == 0
                  and usage.get("PERMIT-LEAF-B", {}).get("used") == 1
                  and usage["PERMIT-LEAF-B"]["unused"] == 1)
            first_id = ok["verification_id"]

        # A failed submission must be rejected on its own merits and identified
        # separately — never echoing a prior verdict.
        tampered = json.loads(json.dumps(payload))
        tampered["shared_siblings"][0]["digest"] = "11" * 32
        bad1 = post(base, "/api/verify", tampered)
        check("tampered sibling digest REJECTED (old_root_mismatch)",
              bad1.get("ok") is False and bad1["error"]["code"] == "old_root_mismatch",
              json.dumps(bad1, ensure_ascii=False)[:300])
        check("  rejection carries a locatable level",
              bad1.get("error", {}).get("level") is not None)
        check("  failure id differs from prior success id",
              bad1.get("verification_id") != first_id)

        extra = json.loads(json.dumps(payload))
        extra["shared_siblings"].append(
            {"depth": 256, "prefix": "0b" + "1" * 256, "digest": "22" * 32})
        bad2 = post(base, "/api/verify", extra)
        check("extra proof node REJECTED (extra_proof_node)",
              bad2.get("ok") is False and bad2["error"]["code"] == "extra_proof_node",
              json.dumps(bad2, ensure_ascii=False)[:300])

        # A legacy request without permits must keep the legacy response shape.
        legacy = {k: v for k, v in payload.items() if k != "permits"}
        ok_legacy = post(base, "/api/verify", legacy)
        check("request without permits ACCEPTED, response has no allocation field",
              ok_legacy.get("ok") is True and "permit_allocation" not in ok_legacy,
              json.dumps(ok_legacy, ensure_ascii=False)[:300])

        # Total permit capacity below the changed-key count must be rejected.
        insufficient = json.loads(json.dumps(payload))
        insufficient["permits"] = [
            p for p in insufficient["permits"] if p["permit_id"] == "PERMIT-WIDE"
        ]
        bad3 = post(base, "/api/verify", insufficient)
        check("insufficient permit capacity REJECTED (permit_capacity)",
              bad3.get("ok") is False and bad3["error"]["code"] == "permit_capacity",
              json.dumps(bad3, ensure_ascii=False)[:300])
        check("  capacity rejection id differs from prior success id",
              bad3.get("verification_id") != first_id)

        # A changed key outside every permit prefix must be located/rejected.
        uncovered = json.loads(json.dumps(payload))
        key_a = uncovered["leaves"][0]["key"]
        bits_a = "".join(f"{int(c, 16):04b}" for c in key_a)
        uncovered["permits"] = [
            {"permit_id": "ONLY-A", "prefix": "0b" + bits_a, "max_keys": 5}
        ]
        bad4 = post(base, "/api/verify", uncovered)
        check("key without candidate permit REJECTED (permit_key_uncovered)",
              bad4.get("ok") is False
              and bad4["error"]["code"] == "permit_key_uncovered",
              json.dumps(bad4, ensure_ascii=False)[:300])

        # Duplicate permit ids must be located/rejected.
        dup = json.loads(json.dumps(payload))
        dup["permits"].append(dict(dup["permits"][0]))
        bad5 = post(base, "/api/verify", dup)
        check("duplicate permit id REJECTED (permit_duplicate_id)",
              bad5.get("ok") is False
              and bad5["error"]["code"] == "permit_duplicate_id",
              json.dumps(bad5, ensure_ascii=False)[:300])

    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if failures:
        print(f"\nHTTP SMOKE FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("\nHTTP SMOKE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
