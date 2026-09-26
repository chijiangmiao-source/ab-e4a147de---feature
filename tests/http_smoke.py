#!/usr/bin/env python3
"""HTTP smoke acceptance for the running (or locally started) verifier.

Checks against the REAL API:
  1. GET  /healthz                         -> 200 status=ok
  2. GET  /                                -> page HTML
  3. POST /api/demo + POST /api/verify     -> shared-prefix two-key change passes,
                                              BOTH recomputed roots match
  4. tampered sibling digest               -> ok=false, old_root_mismatch
  5. extra proof node (off path)           -> ok=false, extra_proof_node
  6. prefix licenses (demo set)            -> ok=true, stable lex-min witness,
                                              wide license exhausted / narrow spare
  7. insufficient total license capacity   -> ok=false, license_capacity
  8. duplicate id / bad prefix / bad quota / uncovered key rejections
  9. request without licenses              -> legacy response, no witness field

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

        # ---- prefix licenses -------------------------------------------- #
        check("demo payload carries nested/overlapping licenses",
              isinstance(payload.get("licenses"), list)
              and len(payload["licenses"]) >= 2)

        if ok.get("ok") and "license_witness" in ok:
            w = ok["license_witness"]
            wkeys = [a["key"] for a in w["assignments"]]
            check("license witness present on the accepted demo batch", True)
            check("  witness ordered by ascending key path, one slot per key",
                  wkeys == sorted(wkeys) and sorted(wkeys) == sorted(ok["changed_keys"]))
            check("  per-license used + unused == quota",
                  all(l["used"] + l["unused"] == l["quota"] for l in w["licenses"]))
            quota = {l["id"]: l for l in w["licenses"]}
            wide = quota.get("NEUTRON-LINE-WIDE")
            narrow = quota.get("NEUTRON-A0-EXACT")
            check("  wide license exhausted while narrow still available",
                  wide is not None and wide["unused"] == 0
                  and narrow is not None and narrow["unused"] >= 1)
            again = post(base, "/api/verify", payload)
            check("  witness stable across identical submissions",
                  again.get("license_witness", {}).get("assignments")
                  == w["assignments"])
        else:
            check("license witness present on the accepted demo batch", False,
                  json.dumps(ok, ensure_ascii=False)[:400])

        legacy = json.loads(json.dumps(payload))
        legacy.pop("licenses", None)
        lres = post(base, "/api/verify", legacy)
        check("request without licenses keeps legacy response (no witness field)",
              lres.get("ok") is True and "license_witness" not in lres,
              json.dumps(lres, ensure_ascii=False)[:300])

        tight = json.loads(json.dumps(payload))
        widest = min(tight["licenses"], key=lambda l: len(l["prefix"]))
        tight["licenses"] = [{**widest, "quota": 1}]
        bad3 = post(base, "/api/verify", tight)
        check("insufficient total capacity REJECTED (license_capacity)",
              bad3.get("ok") is False and bad3["error"]["code"] == "license_capacity",
              json.dumps(bad3, ensure_ascii=False)[:300])
        check("  capacity rejection carries a fresh verification_id",
              bad3.get("verification_id") not in (None, first_id))

        dup = json.loads(json.dumps(payload))
        dup["licenses"] = dup["licenses"] + [dict(dup["licenses"][0])]
        bad4 = post(base, "/api/verify", dup)
        check("duplicate license id REJECTED (duplicate_license_id)",
              bad4.get("ok") is False
              and bad4["error"]["code"] == "duplicate_license_id",
              json.dumps(bad4, ensure_ascii=False)[:300])

        badp = json.loads(json.dumps(payload))
        badp["licenses"][0]["prefix"] = "0b012"
        bad5 = post(base, "/api/verify", badp)
        check("illegal license prefix REJECTED (license_prefix_format)",
              bad5.get("ok") is False
              and bad5["error"]["code"] == "license_prefix_format",
              json.dumps(bad5, ensure_ascii=False)[:300])

        badq = json.loads(json.dumps(payload))
        badq["licenses"][0]["quota"] = 0
        bad6 = post(base, "/api/verify", badq)
        check("non-positive quota REJECTED (license_quota)",
              bad6.get("ok") is False and bad6["error"]["code"] == "license_quota",
              json.dumps(bad6, ensure_ascii=False)[:300])

        unc = json.loads(json.dumps(payload))
        unc["licenses"] = [{"id": "ELSEWHERE", "prefix": "0b1", "quota": 5}]
        bad7 = post(base, "/api/verify", unc)
        check("key without candidate license REJECTED (license_uncovered_key)",
              bad7.get("ok") is False
              and bad7["error"]["code"] == "license_uncovered_key",
              json.dumps(bad7, ensure_ascii=False)[:300])

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
