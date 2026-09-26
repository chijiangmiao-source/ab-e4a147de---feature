"""Acceptance-level tests for the sparse Merkle batch verifier.

Covers the demanded rejection classes:
  * shared-prefix two-key change (happy path, dual rebuild)
  * tampered sibling digest
  * extra proof nodes (off-path / redundant / default-valued)
  * missing non-default sibling
  * duplicate path / wrong path order / shared-ancestor conflict
  * independently wrong old vs new root
  * prefix licenses: lexicographically-minimal stable witness (never
    input-order greedy), wide-exhausted/narrow-available acceptance,
    capacity/uncovered-key/duplicate-id/bad-prefix/bad-quota rejections,
    and legacy compatibility when licenses are omitted
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from smt import (  # noqa: E402
    DEFAULT,
    DEPTH,
    ProofError,
    build_tree,
    key_to_path,
    leaf_hash,
    node_hash,
    proof_for_changes,
    result_dict,
    verify_batch,
    sha256,
)

KEY_A = "0123456789abcdef" * 4
# hex ending …e0 / …e1 -> share first 255 bits, differ in last bit
KEY_A0 = KEY_A[:-1] + "0"
KEY_A1 = KEY_A[:-1] + "1"
KEY_B = "fedcba9876543210" * 4
KEY_C = "000000000000000000000000000000000000000000000000000000000000000f"
KEY_D = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"


def v(s):
    return sha256(s)


def make_change(entries_old, changes, changed_keys):
    """Build a full submission payload from old entries and {key: new_digest}."""
    entries_new = dict(entries_old)
    entries_new.update(changes)
    ordered = sorted(changed_keys)
    return {
        "old_root": build_tree(entries_old).hex(),
        "new_root": build_tree(entries_new).hex(),
        "leaves": [
            {
                "key": k,
                "old_leaf": entries_old[k].hex(),
                "new_leaf": entries_new[k].hex(),
            }
            for k in ordered
        ],
        "shared_siblings": proof_for_changes(entries_old, ordered),
    }


class HappyPathTests(unittest.TestCase):
    def test_single_key_change_only_default_siblings(self):
        old = {KEY_A: v(b"cfg@1")}
        payload = make_change(old, {KEY_A: v(b"cfg@2")}, [KEY_A])
        r = verify_batch(payload)
        self.assertEqual(r.recomputed_old_root, payload["old_root"])
        self.assertEqual(r.recomputed_new_root, payload["new_root"])
        self.assertEqual(r.changed_keys, [KEY_A])
        # 256 merge levels, all sibling slots default empty subtrees
        self.assertEqual(len(r.merges), DEPTH)
        self.assertTrue(
            all(m["left_source"] == "default" or m["right_source"] == "default"
                for m in r.merges)
        )

    def test_empty_tree_root_is_default_ladder_top(self):
        self.assertEqual(build_tree({}).hex(), DEFAULT[DEPTH].hex())

    def test_two_shared_prefix_keys(self):
        old = {KEY_A0: v(b"A@1"), KEY_A1: v(b"B@1")}
        payload = make_change(old, {KEY_A0: v(b"A@2"), KEY_A1: v(b"B@2")},
                              [KEY_A0, KEY_A1])
        r = verify_batch(payload)
        self.assertEqual(r.recomputed_old_root, payload["old_root"])
        self.assertEqual(r.recomputed_new_root, payload["new_root"])
        # At level 255 both children are changed leaves (no default/proof side).
        bottom = next(m for m in r.merges if m["level"] == 255)
        self.assertEqual(bottom["changed_sides"], [0, 1])
        self.assertIn(bottom["left_source"], {"leaf", "recompute"})
        self.assertIn(bottom["right_source"], {"leaf", "recompute"})

    def test_two_keys_with_unchanged_neighbor_sibling(self):
        # KEY_B sits in a far subtree; its subtree digest must be supplied.
        old = {KEY_A0: v(b"A@1"), KEY_A1: v(b"B@1"), KEY_B: v(b"C@1")}
        payload = make_change(old, {KEY_A0: v(b"A@2"), KEY_A1: v(b"B@2")},
                              [KEY_A0, KEY_A1])
        self.assertTrue(payload["shared_siblings"], "应包含非默认兄弟证明")
        r = verify_batch(payload)
        self.assertEqual(r.recomputed_old_root, payload["old_root"])
        self.assertEqual(r.recomputed_new_root, payload["new_root"])
        pinned = [m for m in r.merges
                  if m["left_source"] == "shared-proof"
                  or m["right_source"] == "shared-proof"]
        self.assertTrue(pinned)

    def test_four_keys_change_two(self):
        old = {KEY_A0: v(b"A@1"), KEY_A1: v(b"B@1"), KEY_C: v(b"C@1"),
               KEY_D: v(b"D@1")}
        payload = make_change(old, {KEY_C: v(b"C@2"), KEY_D: v(b"D@2")},
                              [KEY_C, KEY_D])
        r = verify_batch(payload)
        self.assertEqual(r.recomputed_old_root, payload["old_root"])
        self.assertEqual(r.recomputed_new_root, payload["new_root"])

    def test_leaf_and_node_prefixes(self):
        # Explicitly verify the 0x00 / 0x01 domain separation.
        d = v(b"x")
        self.assertEqual(leaf_hash(d), sha256(b"\x00" + d))
        self.assertEqual(node_hash(d, d), sha256(b"\x01" + d + d))


class RejectionTests(unittest.TestCase):
    def setUp(self):
        self.old = {KEY_A0: v(b"A@1"), KEY_A1: v(b"B@1"), KEY_B: v(b"C@1")}
        self.payload = make_change(
            self.old, {KEY_A0: v(b"A@2"), KEY_A1: v(b"B@2")}, [KEY_A0, KEY_A1]
        )

    def assertReject(self, payload, code, level=None):
        with self.assertRaises(ProofError) as cm:
            verify_batch(payload)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        if level is not None:
            self.assertEqual(cm.exception.level, level)
        return cm.exception

    def test_duplicate_path(self):
        p = {**self.payload,
             "leaves": self.payload["leaves"] + [dict(self.payload["leaves"][0])]}
        self.assertReject(p, "duplicate_path")

    def test_path_order_wrong(self):
        # Single-key change with reversed submission is impossible for 1 leaf;
        # craft two out-of-order leaves manually.
        old = {KEY_A0: v(b"A@1"), KEY_B: v(b"B@1")}
        good = make_change(old, {KEY_A0: v(b"A@2"), KEY_B: v(b"B@2")},
                           [KEY_A0, KEY_B])
        bad = {**good, "leaves": list(reversed(good["leaves"]))}
        self.assertReject(bad, "path_order")

    def test_tampered_sibling_digest(self):
        p = self._with_sibling(0, digest=b"\x11" * 32)
        self.assertReject(p, "old_root_mismatch")

    def test_tampered_sibling_only_breaks_new_impossible(self):
        # Pinned siblings participate in BOTH roots; a tampered sibling that
        # still matched old root cannot exist. Instead, correct old root but a
        # wrong declared new root alone must be caught independently.
        p = dict(self.payload)
        p["new_root"] = "00" * 32
        self.assertReject(p, "new_root_mismatch")

    def test_wrong_old_root_independently(self):
        p = dict(self.payload)
        p["old_root"] = "00" * 32
        self.assertReject(p, "old_root_mismatch")

    def test_extra_proof_node_off_path(self):
        extra = {"depth": 256, "prefix": "0b" + "1" * 256, "digest": (b"\x22" * 32).hex()}
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [extra]}
        self.assertReject(p, "extra_proof_node")

    def test_extra_proof_node_default_digest(self):
        # A sibling slot that legitimately needs a proof but the submitted
        # digest equals the default ladder value -> redundant, must reject.
        sib = dict(self.payload["shared_siblings"][0])
        level = sib["depth"]
        sib["digest"] = DEFAULT[DEPTH - level].hex()
        p = self._with_sibling(0, raw=sib)
        self.assertReject(p, "extra_proof_node", level=level)

    def test_extra_proof_node_redundant_descendant(self):
        # Add a proof node strictly inside an existing sibling subtree.
        existing = self.payload["shared_siblings"][0]
        depth = existing["depth"]
        base = existing["prefix"].removeprefix("0b")
        nested = {
            "depth": depth + 1,
            "prefix": "0b" + base + "0",
            "digest": (b"\x33" * 32).hex(),
        }
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [nested]}
        self.assertReject(p, "extra_proof_node")

    def test_shared_ancestor_conflict(self):
        # Pin the subtree that actually contains changed leaf KEY_A1.
        # Their shared parent at level 255 has prefix = KEY_A1's first 255 bits.
        from smt import key_to_path
        bits = key_to_path(KEY_A1)[1]
        conflict = {
            "depth": 255,
            "prefix": "0b" + bits[:255],
            "digest": (b"\x44" * 32).hex(),
        }
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [conflict]}
        self.assertReject(p, "shared_ancestor_conflict", level=255)

    def test_missing_nondefault_sibling(self):
        # Drop the proof for KEY_B's subtree while the declared old root still
        # reflects it -> mismatch with a locatable level.
        p = {**self.payload, "shared_siblings": []}
        err = self.assertReject(p, "old_root_mismatch")
        self.assertIsNotNone(err.level)
        self.assertIn("兄弟", err.message)

    def test_duplicate_proof_node(self):
        dup = dict(self.payload["shared_siblings"][0])
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [dup]}
        self.assertReject(p, "duplicate_proof_node")

    def test_bad_depth_range(self):
        bad = {"depth": 0, "prefix": "0b", "digest": (b"\x55" * 32).hex()}
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [bad]}
        self.assertReject(p, "proof_format")

    def test_prefix_length_mismatch(self):
        bad = {"depth": 256, "prefix": "0b010", "digest": (b"\x55" * 32).hex()}
        p = {**self.payload,
             "shared_siblings": self.payload["shared_siblings"] + [bad]}
        self.assertReject(p, "proof_format")

    def test_bad_digest(self):
        p = dict(self.payload)
        p["old_root"] = "not-hex"
        self.assertReject(p, "digest_format")

    def test_bad_key(self):
        p = {**self.payload,
             "leaves": [{**self.payload["leaves"][0], "key": "zz"}]}
        self.assertReject(p, "key_format")

    def test_wrong_old_leaf_value(self):
        # Old root stays the same but the supplied old leaf digest is wrong.
        leaves = [dict(x) for x in self.payload["leaves"]]
        leaves[0]["old_leaf"] = (b"\x66" * 32).hex()
        p = {**self.payload, "leaves": leaves}
        self.assertReject(p, "old_root_mismatch")

    def test_root_cannot_pass_by_only_checking_one(self):
        # Both roots wrong in different ways must fail regardless of order.
        p = dict(self.payload)
        p["old_root"] = "11" * 32
        p["new_root"] = "22" * 32
        self.assertReject(p, "old_root_mismatch")

    def _with_sibling(self, index, digest=None, raw=None):
        sibs = [dict(s) for s in self.payload["shared_siblings"]]
        if raw is not None:
            sibs[index] = raw
        else:
            sibs[index]["digest"] = digest.hex()
        return {**self.payload, "shared_siblings": sibs}


P255 = key_to_path(KEY_A0)[1][:255]  # the 255 leading bits KEY_A0/KEY_A1 share


def lic(lid, prefix, quota):
    return {"id": lid, "prefix": prefix, "quota": quota}


class LicenseTests(unittest.TestCase):
    """Prefix-permit capacity constraints, evaluated only after both roots
    verify. Keys under test: KEY_A0 < KEY_A1 (share the 255-bit P255)."""

    def setUp(self):
        self.old = {KEY_A0: v(b"A@1"), KEY_A1: v(b"B@1")}
        self.payload = make_change(
            self.old, {KEY_A0: v(b"A@2"), KEY_A1: v(b"B@2")}, [KEY_A0, KEY_A1]
        )

    def with_licenses(self, licenses):
        return {**self.payload, "licenses": licenses}

    def assertReject(self, payload, code):
        with self.assertRaises(ProofError) as cm:
            verify_batch(payload)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception

    def witness(self, payload):
        r = verify_batch(payload)
        self.assertIsNotNone(r.license_witness)
        return r.license_witness

    # -- acceptance -------------------------------------------------------- #
    def test_overlapping_licenses_stable_assignment(self):
        licenses = [
            lic("WIDE", "0b0", 1),
            lic("PAIR", "0b" + P255, 1),
            lic("EXACT-A0", "0b" + P255 + "0", 2),
        ]
        w = self.witness(self.with_licenses(licenses))
        # KEY_A0 takes the smallest id that keeps the rest feasible; KEY_A1
        # then takes PAIR (smaller than WIDE).
        self.assertEqual(
            [(a["key"], a["license_id"]) for a in w["assignments"]],
            [(KEY_A0, "EXACT-A0"), (KEY_A1, "PAIR")],
        )
        self.assertEqual(w["assignments"][0]["matched_prefix"], "0b" + P255 + "0")
        self.assertEqual(w["assignments"][1]["matched_prefix"], "0b" + P255)
        quota = {l["id"]: l for l in w["licenses"]}
        self.assertEqual((quota["WIDE"]["used"], quota["WIDE"]["unused"]), (0, 1))
        self.assertEqual((quota["PAIR"]["used"], quota["PAIR"]["unused"]), (1, 0))
        self.assertEqual(
            (quota["EXACT-A0"]["used"], quota["EXACT-A0"]["unused"]), (1, 1)
        )
        # Stable: re-submitting the identical batch yields the same witness.
        w2 = self.witness(self.with_licenses(licenses))
        self.assertEqual(w, w2)

    def test_input_order_greedy_would_fail_but_assignment_exists(self):
        # Listed widest-first: per-key input-order greedy seats KEY_A0 on WIDE
        # and then has nothing for KEY_A1. The verifier must NOT do that.
        licenses = [lic("WIDE", "0b0", 1), lic("EXACT-A0", "0b" + P255 + "0", 1)]
        w = self.witness(self.with_licenses(licenses))
        self.assertEqual(
            [a["license_id"] for a in w["assignments"]], ["EXACT-A0", "WIDE"]
        )

    def test_lexicographically_smallest_witness_chosen(self):
        # Both licenses cover both keys; id "AAA" must saturate first.
        licenses = [lic("BBB", "0b0", 2), lic("AAA", "0b" + P255, 2)]
        w = self.witness(self.with_licenses(licenses))
        self.assertEqual(
            [a["license_id"] for a in w["assignments"]], ["AAA", "AAA"]
        )
        # Same shape, but "AAA" has only one slot -> KEY_A1 falls back to BBB.
        licenses = [lic("BBB", "0b" + P255, 2), lic("AAA", "0b0", 1)]
        w = self.witness(self.with_licenses(licenses))
        self.assertEqual(
            [a["license_id"] for a in w["assignments"]], ["AAA", "BBB"]
        )

    def test_wide_exhausted_narrow_available_still_passes(self):
        # The demo scenario: the wide license ends exhausted while the narrow
        # one keeps spare quota — the batch is accepted.
        licenses = [
            lic("NEUTRON-LINE-WIDE", "0b0", 1),
            lic("NEUTRON-PAIR-255", "0b" + P255, 1),
            lic("NEUTRON-A0-EXACT", "0b" + P255 + "0", 2),
        ]
        w = self.witness(self.with_licenses(licenses))
        self.assertEqual(
            [a["license_id"] for a in w["assignments"]],
            ["NEUTRON-A0-EXACT", "NEUTRON-LINE-WIDE"],
        )
        quota = {l["id"]: l for l in w["licenses"]}
        self.assertEqual(quota["NEUTRON-LINE-WIDE"]["unused"], 0)   # wide exhausted
        self.assertEqual(quota["NEUTRON-A0-EXACT"]["unused"], 1)    # narrow spare
        self.assertEqual(quota["NEUTRON-PAIR-255"]["used"], 0)

    def test_empty_prefix_license_matches_everything(self):
        licenses = [lic("ROOT", "0b", 2)]
        w = self.witness(self.with_licenses(licenses))
        self.assertEqual([a["license_id"] for a in w["assignments"]], ["ROOT", "ROOT"])
        self.assertEqual(w["licenses"][0]["used"], 2)

    def test_witness_present_in_result_dict(self):
        r = verify_batch(self.with_licenses([lic("ROOT", "0b", 2)]))
        d = result_dict(r, "vid")
        self.assertIn("license_witness", d)
        self.assertEqual(len(d["license_witness"]["assignments"]), 2)

    # -- rejection ---------------------------------------------------------- #
    def test_total_capacity_insufficient_rejected(self):
        err = self.assertReject(self.with_licenses([lic("WIDE", "0b0", 1)]),
                                "license_capacity")
        self.assertIn("1/2", err.message)  # at most 1 of 2 keys can be seated

    def test_both_slots_on_one_key_leave_other_uncovered(self):
        # Two slots for two keys, but both licenses only cover KEY_A0.
        licenses = [
            lic("A0-ONE", "0b" + P255 + "0", 1),
            lic("A0-TWO", "0b" + P255 + "0", 1),
        ]
        self.assertReject(self.with_licenses(licenses), "license_uncovered_key")

    def test_uncovered_key_located(self):
        err = self.assertReject(
            self.with_licenses([lic("ONLY-A0", "0b" + P255 + "0", 5)]),
            "license_uncovered_key",
        )
        self.assertIn(KEY_A1, err.message)

    def test_duplicate_license_id_rejected(self):
        licenses = [lic("DUP", "0b0", 1), lic("DUP", "0b1", 2)]
        err = self.assertReject(self.with_licenses(licenses), "duplicate_license_id")
        self.assertIn("licenses[0]", err.message)
        self.assertIn("licenses[1]", err.message)

    def test_bad_prefix_rejected(self):
        for bad in ("0b012", "0b" + "0" * 257, "0x10", 5, ["0"]):
            self.assertReject(
                self.with_licenses([lic("L", bad, 1)]), "license_prefix_format"
            )

    def test_non_positive_quota_rejected(self):
        for bad in (0, -1, "1", 1.5, True, None):
            self.assertReject(
                self.with_licenses([lic("L", "0b0", bad)]), "license_quota"
            )

    def test_license_structure_rejected(self):
        self.assertReject(self.with_licenses("not-a-list"), "license_format")
        self.assertReject(self.with_licenses([["id"]]), "license_format")
        self.assertReject(
            self.with_licenses([{"id": "L", "prefix": "0b0"}]), "license_format"
        )
        self.assertReject(
            self.with_licenses([lic("  ", "0b0", 1)]), "license_id_format"
        )

    def test_roots_verified_before_licenses(self):
        # A broken root must surface even when the licenses are also invalid:
        # the dual-root recomputation always runs first.
        p = self.with_licenses([lic("DUP", "0b0", 1), lic("DUP", "0b1", 1)])
        p["old_root"] = "00" * 32
        self.assertReject(p, "old_root_mismatch")

    # -- compatibility ------------------------------------------------------ #
    def test_omitted_licenses_keep_legacy_behaviour(self):
        for variant in ({}, {"licenses": None}, {"licenses": []}):
            payload = {**self.payload, **variant}
            r = verify_batch(payload)
            self.assertIsNone(r.license_witness)
            d = result_dict(r, "vid")
            self.assertNotIn("license_witness", d)
            self.assertEqual(d["changed_keys"], [KEY_A0, KEY_A1])


class TraceStructureTests(unittest.TestCase):
    def test_merge_levels_cover_root_to_leaf(self):
        old = {KEY_A0: v(b"A@1"), KEY_B: v(b"B@1")}
        payload = make_change(old, {KEY_B: v(b"B@2")}, [KEY_B])
        r = verify_batch(payload)
        levels = sorted(m["level"] for m in r.merges)
        self.assertEqual(levels, list(range(DEPTH)))
        root_row = next(m for m in r.merges if m["level"] == 0)
        self.assertEqual(root_row["old_parent"], payload["old_root"])
        self.assertEqual(root_row["new_parent"], payload["new_root"])
        self.assertEqual(root_row["parent_prefix"], "0b")

    def test_every_chain_uses_node_encoding(self):
        payload = make_change({KEY_C: v(b"1")}, {KEY_C: v(b"2")}, [KEY_C])
        r = verify_batch(payload)
        for m in r.merges:
            expect_old = node_hash(bytes.fromhex(m["old_left"]),
                                   bytes.fromhex(m["old_right"])).hex()
            expect_new = node_hash(bytes.fromhex(m["new_left"]),
                                   bytes.fromhex(m["new_right"])).hex()
            self.assertEqual(m["old_parent"], expect_old)
            self.assertEqual(m["new_parent"], expect_new)


if __name__ == "__main__":
    unittest.main(verbosity=2)
