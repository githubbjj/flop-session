#!/usr/bin/env python3
"""Agent-side verification for FLOP compute-channel sessions (Yellow Paper v0.5.0).

R12.1b makes one thing the agent's job and nobody else's:

    the agent MUST verify and counter-sign a receipt over the cumulative root
    before accepting output

Counter-signing without verifying is paying for work you never checked. This module is
that check, written from the Yellow Paper (§6.5, §12.1, App. F.3) so it can run before
the network exists.

Scope: transcript leaves, the Merkle accumulator, the checked aggregate, and the receipt
preimage. Not the chain, not settlement, not TOPLOC/TEE attestation.

STATUS — read this before trusting a result. There is no reference implementation and no
published test vectors for FLOP, so nothing here is checked against an authority the way
a port normally would be. What is verified is internal consistency: the byte layouts
reproduce the sizes the spec states (236/172/140/116, VerifiedTurn 268). Three places
where the spec does not determine an answer are marked AMBIGUOUS and surfaced as explicit
choices rather than guessed silently. See FINDINGS.md.

Apache-2.0.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Iterable, Literal, Sequence

try:
    import sr25519  # py-sr25519-bindings
except ImportError:  # keep the hashing path usable without the binding
    sr25519 = None

# ── constants from the spec ──────────────────────────────────────────────────

H256_LEN = 32
SIG_LEN = 64
CHANNEL_MAX_SETTLEMENT_TURNS = 1024        # §12.1h
MAX_ACTIVE_RESERVATIONS_BASE = 4           # §12.2, Appendix A

LEAF_SIZES = {"V3": 236, "V2": 172, "V1": 140, "V0": 116}   # App. F.3
VERIFIED_TURN_FIXED_BYTES = 268                             # App. F.3

LeafVersion = Literal["V3", "V2", "V1", "V0"]
OddNodePolicy = Literal["duplicate", "promote"]


class TranscriptError(ValueError):
    """A transcript failed a check. Never raised as a warning — the agent must not sign."""


def blake2_256(data: bytes) -> bytes:
    """BlakeTwo256 — the runtime hash (§6.5). Merkle leaves and nodes both use it."""
    return hashlib.blake2b(data, digest_size=32).digest()


def _h256(name: str, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != H256_LEN:
        raise TranscriptError(f"{name} must be exactly {H256_LEN} bytes")
    return bytes(value)


def _uint(name: str, value: int, width: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TranscriptError(f"{name} must be a non-negative integer")
    try:
        return value.to_bytes(width, "little")
    except OverflowError as e:
        raise TranscriptError(f"{name} does not fit in u{width * 8}") from e


# ── transcript turn ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VerifiedTurn:
    """App. F.3 VerifiedTurn. `merkle_path` items are (sibling_hash, sibling_is_left)."""

    turn_index: int
    h_in: bytes
    h_out: bytes
    g_n: int
    decode_policy_hash: bytes
    h_ids: bytes
    toploc_commitment_hash: bytes
    miner_recv_ms: int
    miner_done_ms: int
    latency_ms: int
    enclave_sig: bytes
    merkle_path: Sequence[tuple[bytes, bool]] = field(default_factory=tuple)

    def leaf_preimage(self, channel_id: bytes, version: LeafVersion = "V3") -> bytes:
        """The exact bytes hashed into the leaf, per App. F.3.

        V3 is current. V2 drops h_ids and the TOPLOC hash; V1 also drops the decode
        policy; V0 also drops the three timing fields. A pinned decode policy forbids
        falling back to V1/V0, so they are built here only to reproduce the stated sizes
        and to decode legacy material — never to emit.
        """
        cid = _h256("channel_id", channel_id)
        parts = [
            cid,
            _uint("turn_index", self.turn_index, 4),
            _h256("h_in", self.h_in),
            _h256("h_out", self.h_out),
            _uint("g_n", self.g_n, 16),
        ]
        if version in ("V3", "V2"):
            parts.append(_h256("decode_policy_hash", self.decode_policy_hash))
        if version == "V3":
            parts.append(_h256("h_ids", self.h_ids))
            parts.append(_h256("toploc_commitment_hash", self.toploc_commitment_hash))
        if version in ("V3", "V2", "V1"):
            parts.append(_uint("miner_recv_ms", self.miner_recv_ms, 8))
            parts.append(_uint("miner_done_ms", self.miner_done_ms, 8))
            parts.append(_uint("latency_ms", self.latency_ms, 8))

        preimage = b"".join(parts)
        expected = LEAF_SIZES[version]
        if len(preimage) != expected:
            raise TranscriptError(
                f"{version} leaf preimage is {len(preimage)} bytes, spec says {expected}"
            )
        return preimage

    def leaf_hash(self, channel_id: bytes, version: LeafVersion = "V3") -> bytes:
        return blake2_256(self.leaf_preimage(channel_id, version))


# ── Merkle ───────────────────────────────────────────────────────────────────


def merkle_parent(left: bytes, right: bytes) -> bytes:
    """App. F.3: node = blake2_256(left ‖ right)."""
    return blake2_256(_h256("left", left) + _h256("right", right))


def merkle_root(leaves: Sequence[bytes], odd_policy: OddNodePolicy = "duplicate") -> bytes:
    """Build a root from leaf hashes.

    AMBIGUOUS (FINDINGS #2). The spec fixes the node rule and the path item shape but
    never says how a level with an odd node count is handled. The two conventions in
    common use disagree, and they produce different roots for any count that is not a
    power of two — so two conforming implementations would disagree on the very value the
    agent signs. Both are implemented; the caller must choose, and there is no default
    that can be called correct.

      duplicate — hash the odd node against itself
      promote   — carry the odd node up one level unchanged (Substrate binary-merkle-tree)
    """
    if not leaves:
        raise TranscriptError("cannot build a root from zero leaves")
    level = [_h256("leaf", x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(merkle_parent(level[i], level[i + 1]))
        if len(level) % 2:
            odd = level[-1]
            nxt.append(merkle_parent(odd, odd) if odd_policy == "duplicate" else odd)
        level = nxt
    return level[0]


def verify_merkle_path(
    leaf_hash: bytes, path: Iterable[tuple[bytes, bool]], root: bytes
) -> bool:
    """Fold a leaf up its path and compare to the root. False on any malformed input."""
    try:
        node = _h256("leaf_hash", leaf_hash)
        for sibling, sibling_is_left in path:
            sib = _h256("sibling", sibling)
            if not isinstance(sibling_is_left, bool):
                return False
            node = merkle_parent(sib, node) if sibling_is_left else merkle_parent(node, sib)
        return node == _h256("root", root)
    except TranscriptError:
        return False


# ── aggregate and receipt ────────────────────────────────────────────────────


def checked_aggregate_gn(turns: Sequence[VerifiedTurn]) -> int:
    """Sum g_n over distinct turns (App. F.3 `verified_work_from_turns`).

    Uniqueness is session_id‖turn_index (R12.1b), so a repeated turn_index is a malformed
    bundle rather than something to de-duplicate quietly.
    """
    if not turns:
        raise TranscriptError("no turns submitted")
    if len(turns) > CHANNEL_MAX_SETTLEMENT_TURNS:
        raise TranscriptError(
            f"{len(turns)} turns exceeds channel_max_settlement_turns "
            f"({CHANNEL_MAX_SETTLEMENT_TURNS})"
        )
    seen = set()
    for t in turns:
        if t.turn_index in seen:
            raise TranscriptError(f"duplicate turn_index {t.turn_index}")
        seen.add(t.turn_index)
    return sum(t.g_n for t in turns)


def receipt_preimage(
    channel_id: bytes, final_root: bytes, aggregate_gn: int, payable: int
) -> bytes:
    """App. F.3: sr25519 over channel_id ‖ final_root ‖ aggregate_gn:u128LE ‖ payable:u128LE.

    AMBIGUOUS (FINDINGS #3). `payable` appears exactly once in the Yellow Paper — in this
    row — and is never defined: not in §12.1, not in Appendix A. The receipt "authorizes
    the bound payout", so the agent is signing a number whose meaning the spec does not
    give it. Encoding it is unambiguous; knowing what to put there is not.
    """
    return (
        _h256("channel_id", channel_id)
        + _h256("final_root", final_root)
        + _uint("aggregate_gn", aggregate_gn, 16)
        + _uint("payable", payable, 16)
    )


# ── signature verification ───────────────────────────────────────────────────


def _sr25519_verify(sig: bytes, message: bytes, pubkey: bytes) -> bool:
    if sr25519 is None:
        raise TranscriptError(
            "sr25519 verification needs py-sr25519-bindings (pip install py-sr25519-bindings)"
        )
    if len(sig) != SIG_LEN or len(pubkey) != H256_LEN:
        return False
    try:
        return bool(sr25519.verify(sig, message, pubkey))
    except Exception:
        return False


Verifier = Callable[[bytes, bytes, bytes], bool]


def verify_turn_signature(
    turn: VerifiedTurn,
    channel_id: bytes,
    enclave_key: bytes,
    *,
    verifier: Verifier = _sr25519_verify,
    accept_v2: bool = True,
) -> LeafVersion | None:
    """Which leaf version this turn's signature validates under, or None.

    App. F.3: "no explicit version byte; verifier tries V3→V2". The signature covers the
    32-byte leaf hash, not the preimage.
    """
    versions: list[LeafVersion] = ["V3", "V2"] if accept_v2 else ["V3"]
    for v in versions:
        try:
            digest = turn.leaf_hash(channel_id, v)
        except TranscriptError:
            continue
        if verifier(turn.enclave_sig, digest, enclave_key):
            return v
    return None


# ── the agent-side gate ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class TranscriptCheck:
    ok: bool
    reason: str
    versions: tuple[LeafVersion, ...] = ()
    aggregate_gn: int = 0


def verify_transcript(
    *,
    channel_id: bytes,
    enclave_key: bytes,
    turns: Sequence[VerifiedTurn],
    final_root: bytes,
    claimed_aggregate_gn: int,
    verifier: Verifier = _sr25519_verify,
    accept_v2: bool = True,
) -> TranscriptCheck:
    """Everything the agent must confirm before counter-signing. Fail-closed.

    Returns a result rather than raising, so a caller cannot accidentally treat an
    exception path as success. Any false is a refusal to sign.
    """
    try:
        aggregate = checked_aggregate_gn(turns)
    except TranscriptError as e:
        return TranscriptCheck(False, str(e))

    if aggregate != claimed_aggregate_gn:
        return TranscriptCheck(
            False, f"aggregate mismatch: turns sum to {aggregate}, claim is {claimed_aggregate_gn}"
        )

    versions: list[LeafVersion] = []
    for t in turns:
        v = verify_turn_signature(
            t, channel_id, enclave_key, verifier=verifier, accept_v2=accept_v2
        )
        if v is None:
            return TranscriptCheck(False, f"turn {t.turn_index}: enclave signature does not verify")
        versions.append(v)

        try:
            leaf = t.leaf_hash(channel_id, v)
        except TranscriptError as e:
            return TranscriptCheck(False, f"turn {t.turn_index}: {e}")
        if not verify_merkle_path(leaf, t.merkle_path, final_root):
            return TranscriptCheck(False, f"turn {t.turn_index}: Merkle path does not reach the root")

    return TranscriptCheck(True, "ok", tuple(versions), aggregate)
