"""Sparse Merkle tree (256-bit keys) batch-change verification.

Conventions
-----------
* Leaf node digest:  ``SHA-256(0x00 || leaf_digest)``
* Internal node:      ``SHA-256(0x01 || left_digest || right_digest)``
* Empty subtree of height ``h`` uses the default-hash ladder:
  ``DEFAULT[0] = SHA-256(b"")`` and ``DEFAULT[h] = H(01||DEFAULT[h-1]||DEFAULT[h-1])``.

Levels run from 256 at the leaf slots (prefix = the full 256-bit key path)
down to 0 at the root (prefix = ""). A node at level ``l`` therefore carries
a prefix of exactly ``l`` bits and subtree height ``256 - l``.

A batch proof claims: "the old root was produced by these old leaf values and
the new root by replacing those values at the *same* key paths; every other
touched subtree is unchanged (its root digest is supplied as a shared sibling
proof) or empty (the default digest)". The verifier rebuilds BOTH trees
bottom-up from one structural skeleton and compares both recomputed roots.
The submitted roots are never used to derive anything.
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field

DEPTH = 256
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# DEFAULT[h] = digest of the empty subtree of height h (h = 0..256).
DEFAULT: list[bytes] = [sha256(b"")]
for _ in range(DEPTH):
    h = DEFAULT[-1]
    DEFAULT.append(sha256(NODE_PREFIX + h + h))


def default_at_level(level: int) -> bytes:
    """Empty-subtree digest for a node at ``level`` (leaf level 256 .. root 0)."""
    return DEFAULT[DEPTH - level]


def leaf_hash(value: bytes) -> bytes:
    """Node digest of a populated leaf: SHA-256(00 || leaf_digest)."""
    return sha256(LEAF_PREFIX + value)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


_HEX = set("0123456789abcdef")
_BITS = set("01")


class ProofError(Exception):
    """Rejection carrying a human message, machine code and optional level."""

    def __init__(self, message: str, code: str = "rejected", level: int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.level = level


def _clean_hex(value: object) -> str:
    if not isinstance(value, str):
        raise ProofError("摘要必须是 64 位十六进制字符串", "digest_format")
    s = value.strip().removeprefix("0x").lower()
    if len(s) != 64 or any(c not in _HEX for c in s):
        raise ProofError(f"不是 64 位十六进制摘要: {value!r}", "digest_format")
    return s


def parse_digest(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise ProofError(f"{what} 必须是 64 位十六进制字符串", "digest_format")
    s = value.strip().removeprefix("0x").lower()
    if len(s) != 64 or any(c not in _HEX for c in s):
        raise ProofError(f"{what} 不是 64 位十六进制摘要: {value!r}", "digest_format")
    return bytes.fromhex(s)


def key_to_path(key_hex: object) -> tuple[str, str]:
    """Validate a 256-bit key; return (64 hex chars, 256 MSB-first bits)."""
    if not isinstance(key_hex, str):
        raise ProofError("键路径必须是 64 位十六进制字符串", "key_format")
    h = key_hex.strip().removeprefix("0x").lower()
    if len(h) != 64 or any(c not in _HEX for c in h):
        raise ProofError(f"键路径 {key_hex!r} 不是 64 位十六进制", "key_format")
    return h, "".join(f"{int(c, 16):04b}" for c in h)


def prefix_bits(raw: object, want_len: int, what: str) -> str:
    if not isinstance(raw, str):
        raise ProofError(f"{what} 必须是二进制字符串", "proof_format")
    bits = raw.strip().removeprefix("0b")
    if len(bits) != want_len or any(c not in _BITS for c in bits):
        raise ProofError(
            f"{what} 必须是恰好 {want_len} 个 0/1，实际为 {raw!r}", "proof_format"
        )
    return bits


@dataclass(frozen=True)
class Update:
    key: str          # 64 hex chars
    path: str         # 256 bits, MSB-first
    old_value: bytes  # 32-byte old leaf digest
    new_value: bytes  # 32-byte new leaf digest


@dataclass(frozen=True)
class Sibling:
    level: int            # node level 1..256
    prefix: str           # exactly `level` bits
    digest: bytes
    raw_prefix: str


@dataclass
class MergeRow:
    level: int
    parent_prefix: str
    changed_sides: list[int]
    old_left: str
    old_right: str
    new_left: str
    new_right: str
    old_parent: str
    new_parent: str
    left_source: str   # leaf | recompute | shared-proof | default
    right_source: str


@dataclass
class VerifyResult:
    old_root: str
    new_root: str
    recomputed_old_root: str
    recomputed_new_root: str
    leaves: list[dict]
    shared_nodes: list[dict]
    merges: list[MergeRow]
    defaults_used: list[dict]
    changed_keys: list[str]
    permit_allocation: dict | None = None


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _parse_updates(raw: object) -> list[Update]:
    if not isinstance(raw, list) or not raw:
        raise ProofError("leaves 必须是非空数组", "proof_format")
    if len(raw) > 1024:
        raise ProofError("一次批量改动的叶数量超过上限 1024", "too_many_leaves")

    updates: list[Update] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProofError(f"leaves[{i}] 必须是对象", "proof_format")
        key, path = key_to_path(item.get("key"))
        if path in seen:
            raise ProofError(f"同一路径重复: {key} 在批量中出现多次", "duplicate_path")
        seen.add(path)
        old_value = parse_digest(item.get("old_leaf"), f"leaves[{i}].old_leaf")
        new_value = parse_digest(item.get("new_leaf"), f"leaves[{i}].new_leaf")
        updates.append(Update(key, path, old_value, new_value))

    # Strict submission order: ascending 256-bit key path.
    keys = [u.key for u in updates]
    if keys != sorted(keys):
        bad = next(i for i in range(1, len(keys)) if keys[i] < keys[i - 1])
        raise ProofError(
            f"路径次序错误: leaves[{bad}]={keys[bad]} 排在 leaves[{bad - 1}]="
            f"{keys[bad - 1]} 之前，必须按 256 位键路径升序提交",
            "path_order",
        )
    return updates


def _parse_siblings(raw: object) -> list[Sibling]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProofError("shared_siblings 必须是数组", "proof_format")
    out: list[Sibling] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProofError(f"shared_siblings[{i}] 必须是对象", "proof_format")
        if not {"depth", "prefix", "digest"} <= set(item):
            raise ProofError(
                f"shared_siblings[{i}] 必须包含 depth、prefix、digest 字段",
                "proof_format",
            )
        depth = item["depth"]
        if isinstance(depth, bool) or not isinstance(depth, int):
            raise ProofError(f"shared_siblings[{i}].depth 必须是整数", "proof_format")
        if not 1 <= depth <= DEPTH:
            raise ProofError(
                f"shared_siblings[{i}].depth={depth} 超出节点层级范围 1..256",
                "proof_format",
            )
        raw_prefix = item["prefix"]
        bits = prefix_bits(raw_prefix, depth, f"shared_siblings[{i}].prefix")
        digest = parse_digest(item["digest"], f"shared_siblings[{i}].digest")
        out.append(Sibling(depth, bits, digest, str(raw_prefix)))
    return out


# --------------------------------------------------------------------------- #
# Prefix permits (optional capacity authorization for the changed keys)
# --------------------------------------------------------------------------- #

MAX_PERMITS = 512


@dataclass(frozen=True)
class Permit:
    permit_id: str
    prefix: str   # 0..256 bits; "" matches every key
    max_keys: int
    index: int    # submission position, for error messages


def _parse_permits(raw: object) -> list[Permit] | None:
    """Parse the optional permit list.

    Returns ``None`` when the feature is not used (field absent, JSON null or
    an empty array), so legacy requests keep their legacy behaviour and a
    response shape identical to the pre-permit service.
    """
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ProofError("permits 必须是数组", "permit_format")
    if not raw:
        return None
    if len(raw) > MAX_PERMITS:
        raise ProofError(f"许可数量超过上限 {MAX_PERMITS}", "too_many_permits")

    permits: list[Permit] = []
    seen: dict[str, int] = {}
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProofError(f"permits[{i}] 必须是对象", "permit_format")
        if not {"permit_id", "prefix", "max_keys"} <= set(item):
            raise ProofError(
                f"permits[{i}] 必须包含 permit_id、prefix、max_keys 字段",
                "permit_format",
            )
        pid = item["permit_id"]
        if not isinstance(pid, str) or not pid.strip():
            raise ProofError(
                f"permits[{i}].permit_id 必须是非空字符串", "permit_format"
            )
        pid = pid.strip()
        if len(pid) > 128:
            raise ProofError(
                f"许可标识 {pid[:32]!r}… 超过 128 字符上限", "permit_format"
            )
        if pid in seen:
            raise ProofError(
                f"许可标识重复: {pid!r} 同时出现在 permits[{seen[pid]}] 与 "
                f"permits[{i}]，许可标识必须唯一",
                "permit_duplicate_id",
            )
        seen[pid] = i

        raw_prefix = item["prefix"]
        if not isinstance(raw_prefix, str):
            raise ProofError(
                f"许可 {pid!r} 的 prefix 必须是 0/1 字符串", "permit_prefix_format"
            )
        bits = raw_prefix.strip().removeprefix("0b")
        if len(bits) > DEPTH or any(c not in _BITS for c in bits):
            raise ProofError(
                f"许可 {pid!r} 的前缀 {raw_prefix!r} 非法: 须为 0..256 个 0/1 "
                "字符（可带 0b 前缀，空前缀表示覆盖全部键）",
                "permit_prefix_format",
            )

        cap = item["max_keys"]
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
            raise ProofError(
                f"许可 {pid!r} 的 max_keys 必须是正整数，实际为 {cap!r}",
                "permit_quota",
            )
        permits.append(Permit(pid, bits, cap, i))
    return permits


def allocate_permits(paths: list[str], keys: list[str],
                     permits: list[Permit]) -> dict:
    """Assign every changed key to one prefix-matching permit.

    Each permit may absorb at most ``max_keys`` keys. Nested/overlapping
    permits are NOT distributed greedily by input order: among all feasible
    assignments the function returns the unique witness whose permit-id
    sequence (keys taken in ascending 256-bit path order) is lexicographically
    smallest. Raises ProofError when a key has no candidate permit or when no
    assignment can give every key one permit slot.
    """
    n = len(paths)  # paths/keys are already in ascending path order
    m = len(permits)

    # Candidate permits per key, pre-sorted by permit id.
    candidates: list[list[int]] = []
    for key, path in zip(keys, paths):
        cand = [j for j, p in enumerate(permits) if path.startswith(p.prefix)]
        if not cand:
            raise ProofError(
                f"变更键 {key} 不在任何许可前缀范围内：没有候选许可可承接该键",
                "permit_key_uncovered",
            )
        cand.sort(key=lambda j: permits[j].permit_id)
        candidates.append(cand)

    # Permit key-sets are laminar (prefix-nested), so the keys under any
    # permit prefix form one contiguous interval of the sorted key list, and
    # the distinct prefixes form a tree. For such a tree the max-flow/min-cut
    # (Hall) feasibility condition of any residual instance is
    #     sum over tree roots r of min(0, h(r)) >= need - total_capacity
    # where f(t) = keys_under(t) - capacity_under(t) and
    # h(t) = min(f(t), sum of h over children of t).
    node_prefix: list[str] = []
    prefix_to_node: dict[str, int] = {}
    node_of: list[int] = []
    for p in permits:
        nid = prefix_to_node.get(p.prefix)
        if nid is None:
            nid = len(node_prefix)
            prefix_to_node[p.prefix] = nid
            node_prefix.append(p.prefix)
        node_of.append(nid)
    nn = len(node_prefix)

    parent = [-1] * nn
    for nid, pfx in enumerate(node_prefix):
        for length in range(len(pfx) - 1, -1, -1):
            up = prefix_to_node.get(pfx[:length])
            if up is not None:
                parent[nid] = up
                break
    children: list[list[int]] = [[] for _ in range(nn)]
    roots: list[int] = []
    for nid, par in enumerate(parent):
        if par >= 0:
            children[par].append(nid)
        else:
            roots.append(nid)
    deepest_first = sorted(range(nn), key=lambda t: -len(node_prefix[t]))

    lo_of = [bisect.bisect_left(paths, pfx) for pfx in node_prefix]
    hi_of = [bisect.bisect_left(paths, pfx + "2") for pfx in node_prefix]

    def residual_deficit(start: int, remaining: list[int]) -> tuple[int, list[int], list[int]]:
        """(deficit, keys_under, cap_under) for keys[start:].

        deficit = sum of min(0, h(root)) - (need - total); feasible iff >= 0.
        """
        need = n - start
        total = sum(remaining)
        keys_under = [0] * nn
        for t in range(nn):
            cnt = hi_of[t] - max(lo_of[t], start)
            keys_under[t] = cnt if cnt > 0 else 0
        cap_under = [0] * nn
        for j in range(m):
            cap_under[node_of[j]] += remaining[j]
        for t in deepest_first:
            if parent[t] >= 0:
                cap_under[parent[t]] += cap_under[t]
        h = [0] * nn
        for t in deepest_first:
            down = sum(h[c] for c in children[t])
            f = keys_under[t] - cap_under[t]
            h[t] = f if f < down else down
        deficit = sum(min(0, h[r]) for r in roots) - (need - total)
        return deficit, keys_under, cap_under

    def residual_feasible(start: int, remaining: list[int]) -> bool:
        """Can keys[start:] still be placed with the remaining capacities?"""
        if n - start > sum(remaining):
            return False
        deficit, _, _ = residual_deficit(start, remaining)
        return deficit >= 0

    remaining = [p.max_keys for p in permits]

    if not residual_feasible(0, remaining):
        total = sum(remaining)
        if n > total:
            raise ProofError(
                f"许可总额度不足: {n} 个变更键各需占用一次许可额度，"
                f"全部许可总额度仅 {total}",
                "permit_capacity",
            )
        # Locate the bottleneck: reconstruct the witness antichain of prefix
        # cones whose outside holds more keys than the outside capacity.
        _, keys_under, cap_under = residual_deficit(0, remaining)
        h = [0] * nn
        for t in deepest_first:
            down = sum(h[c] for c in children[t])
            f = keys_under[t] - cap_under[t]
            h[t] = f if f < down else down

        witness: list[int] = []

        def collect(t: int) -> None:
            down = sum(h[c] for c in children[t])
            if keys_under[t] - cap_under[t] <= down:
                witness.append(t)
            else:
                for c in children[t]:
                    collect(c)

        for r in roots:
            if h[r] < 0:
                collect(r)
        outside_keys = n - sum(keys_under[t] for t in witness)
        outside_cap = total - sum(cap_under[t] for t in witness)
        shown = "、".join(f"0b{node_prefix[t]}" for t in witness[:3])
        if len(witness) > 3:
            shown += f" 等 {len(witness)} 个"
        raise ProofError(
            f"许可容量不足: 落在许可前缀 {shown} 覆盖范围之外的变更键有 "
            f"{outside_keys} 个，而范围之外的许可总额度仅 {outside_cap}"
            f"（缺口 {outside_keys - outside_cap}）",
            "permit_capacity",
        )

    # Lexicographically smallest witness: for each key in ascending path
    # order take the smallest permit id that still admits a feasible
    # completion. The upfront check guarantees one candidate always survives.
    assigned = [-1] * n
    for i in range(n):
        for j in candidates[i]:
            if remaining[j] <= 0:
                continue
            remaining[j] -= 1
            if residual_feasible(i + 1, remaining):
                assigned[i] = j
                break
            remaining[j] += 1
        else:  # pragma: no cover - unreachable after the feasibility check
            raise ProofError(
                f"许可容量不足: 无法为全部 {n} 个变更键各分配一次许可额度",
                "permit_capacity",
            )

    used = [p.max_keys - remaining[j] for j, p in enumerate(permits)]
    return {
        "assignments": [
            {
                "key": keys[i],
                "permit_id": permits[a].permit_id,
                "permit_prefix": "0b" + permits[a].prefix,
            }
            for i, a in enumerate(assigned)
        ],
        "permits": [
            {
                "permit_id": p.permit_id,
                "prefix": "0b" + p.prefix,
                "max_keys": p.max_keys,
                "used": used[j],
                "unused": p.max_keys - used[j],
            }
            for j, p in sorted(enumerate(permits), key=lambda t: t[1].permit_id)
        ],
    }


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify_batch(payload: object) -> VerifyResult:
    """Rebuild both trees and check both roots. Raises ProofError on rejection."""
    if not isinstance(payload, dict):
        raise ProofError("请求体必须是 JSON 对象", "bad_request")

    declared_old = parse_digest(payload.get("old_root"), "old_root")
    declared_new = parse_digest(payload.get("new_root"), "new_root")
    updates = _parse_updates(payload.get("leaves"))
    siblings = _parse_siblings(payload.get("shared_siblings"))

    paths = {u.path for u in updates}

    def contains_changed(prefix: str) -> bool:
        """Whether the subtree rooted at `prefix` contains a changed leaf."""
        return any(p.startswith(prefix) for p in paths)

    # Index proof nodes by node slot (level, prefix), rejecting duplicates.
    proof: dict[tuple[int, str], Sibling] = {}
    for s in siblings:
        key = (s.level, s.prefix)
        if key in proof:
            raise ProofError(
                f"多余证明节点: depth={s.level} prefix={s.raw_prefix} 重复提交",
                "duplicate_proof_node",
                s.level,
            )
        proof[key] = s

    # A proof node carrying the default empty-subtree digest is redundant:
    # default subtrees are implicit, so submitting one is an extra proof node.
    for s in siblings:
        if s.digest == default_at_level(s.level):
            raise ProofError(
                f"多余证明节点: depth={s.level} prefix={s.raw_prefix} 的摘要等于该层"
                "默认空子树，默认子树无需在 shared_siblings 中提供",
                "extra_proof_node",
                s.level,
            )

    # A proof node whose subtree contains a changed leaf conflicts with the
    # bottom-up recomputation: that digest must change, it cannot be pinned.
    for s in siblings:
        if contains_changed(s.prefix):
            raise ProofError(
                f"共享祖先处冲突: depth={s.level} prefix={s.raw_prefix} 的子树内含"
                f"变更叶 {next(p for p in paths if p.startswith(s.prefix))[:16]}…，"
                "该节点必须自底向上重算，不得作为固定兄弟证明",
                "shared_ancestor_conflict",
                s.level,
            )

    # Redundant ancestor/descendant proof pairs: the upper node covers the
    # lower one, so the lower is an extra proof node.
    ordered = sorted(siblings, key=lambda s: (s.level, s.prefix))
    for i, hi in enumerate(ordered):
        for lo in ordered[i + 1 :]:
            if lo.prefix.startswith(hi.prefix):
                raise ProofError(
                    f"多余证明节点: depth={lo.level} prefix={lo.raw_prefix} 已被"
                    f" depth={hi.level} prefix={hi.raw_prefix} 的证明覆盖",
                    "extra_proof_node",
                    lo.level,
                )

    # Parent merges actually required: one per (level, parent prefix) that a
    # changed path passes through.
    required: set[tuple[int, str]] = set()
    for u in updates:
        for lvl in range(DEPTH - 1, -1, -1):
            required.add((lvl, u.path[:lvl]))

    # Proof nodes not on any required merge path are superfluous.
    for s in siblings:
        used = (s.level - 1, s.prefix[: s.level - 1]) in required
        if not used:
            raise ProofError(
                f"多余证明节点: depth={s.level} prefix={s.raw_prefix} 不位于任何"
                "变更叶的合并路径上",
                "extra_proof_node",
                s.level,
            )

    # ---- Bottom-up dual rebuild ------------------------------------------ #
    old: dict[tuple[int, str], bytes] = {}
    new: dict[tuple[int, str], bytes] = {}
    src: dict[tuple[int, str], str] = {}
    for u in updates:
        old[(DEPTH, u.path)] = leaf_hash(u.old_value)
        new[(DEPTH, u.path)] = leaf_hash(u.new_value)
        src[(DEPTH, u.path)] = "leaf"

    merges: list[MergeRow] = []
    defaults_used: list[dict] = []
    default_slots: list[tuple[int, str]] = []

    for lvl in range(DEPTH - 1, -1, -1):
        for pfx in sorted(p for (l, p) in required if l == lvl):
            lslot = (lvl + 1, pfx + "0")
            rslot = (lvl + 1, pfx + "1")

            def resolve(slot: tuple[int, str]) -> tuple[bytes, bytes, str]:
                if slot in old:
                    return old[slot], new[slot], "recompute" if src[slot] != "leaf" else "leaf"
                node = proof.get(slot)
                if node is not None:
                    # Unchanged subtree: same digest participates in BOTH roots.
                    return node.digest, node.digest, "shared-proof"
                default_slots.append(slot)
                d = default_at_level(slot[0])
                defaults_used.append(
                    {"level": slot[0], "prefix": "0b" + slot[1], "digest": d.hex()}
                )
                return d, d, "default"

            old_l, new_l, src_l = resolve(lslot)
            old_r, new_r, src_r = resolve(rslot)
            old_p = node_hash(old_l, old_r)
            new_p = node_hash(new_l, new_r)
            pkey = (lvl, pfx)
            old[pkey], new[pkey], src[pkey] = old_p, new_p, "recompute"

            sides = sorted({int(u.path[lvl]) for u in updates if u.path[:lvl] == pfx})
            merges.append(
                MergeRow(
                    level=lvl,
                    parent_prefix="0b" + pfx,
                    changed_sides=sides,
                    old_left=old_l.hex(),
                    old_right=old_r.hex(),
                    new_left=new_l.hex(),
                    new_right=new_r.hex(),
                    old_parent=old_p.hex(),
                    new_parent=new_p.hex(),
                    left_source=src_l,
                    right_source=src_r,
                )
            )

    got_old = old[(0, "")]
    got_new = new[(0, "")]

    if got_old != declared_old or got_new != declared_new:
        # Cryptographically, a tampered sibling digest, a wrong leaf value and
        # an omitted non-default sibling (silently default-substituted) all
        # surface as a root mismatch. Locate the deepest slot where the proof
        # asked us to assume the empty subtree, and the deepest pinned sibling,
        # so the reviewer knows where to look. Either way the batch is rejected.
        deepest_default = max((s[0] for s in default_slots), default=None)

        def mismatch(which: str, got: bytes, declared: bytes, code: str) -> ProofError:
            detail = (
                f"；最可能的定位位置是 level={deepest_default} 处按默认空子树代入的"
                "兄弟槽：若该子树非空则属于「缺少非默认兄弟节点」，否则请检查附近"
                " shared_siblings 摘要是否被篡改或叶摘要是否有误"
                if deepest_default is not None
                else ""
            )
            return ProofError(
                f"{which}复算不一致: 重建根 {got.hex()} ≠ 提交根 {declared.hex()}{detail}",
                code,
                deepest_default,
            )

        if got_old != declared_old:
            raise mismatch("旧根", got_old, declared_old, "old_root_mismatch")
        raise mismatch("新根", got_new, declared_new, "new_root_mismatch")

    # ---- Prefix permits (only after BOTH roots verified) ------------------ #
    # The dual rebuild above is untouched; permit authorization is layered on
    # top of a cryptographically valid batch. Any permit problem rejects the
    # batch on its own — no partial/earlier allocation is ever returned.
    permits = _parse_permits(payload.get("permits"))
    permit_allocation = None
    if permits is not None:
        permit_allocation = allocate_permits(
            [u.path for u in updates], [u.key for u in updates], permits
        )

    return VerifyResult(
        old_root=declared_old.hex(),
        new_root=declared_new.hex(),
        recomputed_old_root=got_old.hex(),
        recomputed_new_root=got_new.hex(),
        leaves=[
            {
                "key": u.key,
                "old_leaf_digest": u.old_value.hex(),
                "new_leaf_digest": u.new_value.hex(),
                "old_leaf_hash": leaf_hash(u.old_value).hex(),
                "new_leaf_hash": leaf_hash(u.new_value).hex(),
            }
            for u in updates
        ],
        shared_nodes=[
            {
                "depth": s.level,
                "prefix": "0b" + s.prefix,
                "digest": s.digest.hex(),
                "is_default_empty": s.digest == default_at_level(s.level),
            }
            for s in sorted(siblings, key=lambda s: (s.level, s.prefix))
        ],
        merges=[vars(m) for m in merges],
        defaults_used=defaults_used,
        changed_keys=[u.key for u in updates],
        permit_allocation=permit_allocation,
    )


def result_dict(r: VerifyResult, verification_id: str) -> dict:
    d = {
        "ok": True,
        "verification_id": verification_id,
        "old_root": r.old_root,
        "new_root": r.new_root,
        "recomputed_old_root": r.recomputed_old_root,
        "recomputed_new_root": r.recomputed_new_root,
        "changed_keys": r.changed_keys,
        "leaves": r.leaves,
        "shared_siblings": r.shared_nodes,
        "merges": r.merges,
        "defaults_used": r.defaults_used,
        "default_ladder": [
            {"height": h, "level": DEPTH - h, "digest": DEFAULT[h].hex()}
            for h in range(DEPTH, -1, -1)
        ],
    }
    # Only present when the submission actually carried permits: legacy
    # requests keep the legacy response shape, field for field.
    if r.permit_allocation is not None:
        d["permit_allocation"] = r.permit_allocation
    return d


# --------------------------------------------------------------------------- #
# Reference tree builder (used by tests and the demo-payload endpoint)
# --------------------------------------------------------------------------- #


def build_tree(entries: dict[str, bytes]) -> bytes:
    """Build a sparse tree from {key_path(256 bits or hex): leaf_digest}."""
    nodes: dict[tuple[int, str], bytes] = {}
    for key, value in entries.items():
        path = key if len(key) == DEPTH and set(key) <= _BITS else key_to_path(key)[1]
        nodes[(DEPTH, path)] = leaf_hash(value)
    if not nodes:
        return default_at_level(0)
    for lvl in range(DEPTH - 1, -1, -1):
        prefixes = {p[:lvl] for (l, p) in nodes if l == lvl + 1}
        for pfx in prefixes:
            left = nodes.get((lvl + 1, pfx + "0"), default_at_level(lvl + 1))
            right = nodes.get((lvl + 1, pfx + "1"), default_at_level(lvl + 1))
            nodes[(lvl, pfx)] = node_hash(left, right)
    return nodes[(0, "")]


def proof_for_changes(
    entries: dict[str, bytes], changed_paths: list[str]
) -> list[dict]:
    """Compact shared-sibling proof for changing `changed_paths` in `entries`.

    Emits every non-default sibling subtree along the changed merge paths.
    """
    norm: dict[str, bytes] = {}
    for key, value in entries.items():
        path = key if len(key) == DEPTH and set(key) <= _BITS else key_to_path(key)[1]
        norm[path] = value
    changed = set()
    for key in changed_paths:
        changed.add(key if len(key) == DEPTH and set(key) <= _BITS else key_to_path(key)[1])

    nodes: dict[tuple[int, str], bytes] = {}
    for path, value in norm.items():
        nodes[(DEPTH, path)] = leaf_hash(value)
    for lvl in range(DEPTH - 1, -1, -1):
        prefixes = {p[:lvl] for (l, p) in nodes if l == lvl + 1}
        for pfx in prefixes:
            left = nodes.get((lvl + 1, pfx + "0"), default_at_level(lvl + 1))
            right = nodes.get((lvl + 1, pfx + "1"), default_at_level(lvl + 1))
            nodes[(lvl, pfx)] = node_hash(left, right)

    out: dict[tuple[int, str], bytes] = {}
    for path in changed:
        for lvl in range(DEPTH - 1, -1, -1):
            side = int(path[lvl])
            sib_prefix = path[:lvl] + str(1 - side)
            key = (lvl + 1, sib_prefix)
            if any(p.startswith(sib_prefix) for p in changed):
                continue  # recomputed from another changed leaf
            digest = nodes.get(key, default_at_level(lvl + 1))
            if digest != default_at_level(lvl + 1):
                out[key] = digest
    return [
        {"depth": lvl, "prefix": "0b" + pfx, "digest": digest.hex()}
        for (lvl, pfx), digest in sorted(out.items())
    ]
