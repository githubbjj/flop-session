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
published test vectors for FLOP, so nothing here was checked against an authority the way
a port normally would be. That changed: `evidence/wire-format-v1.json` in flop-labs/yellowpaper
is a canonical vector set, and `test_vectors.py` runs this module against it — leaf preimages
and hashes for all four versions, the Merkle root and path, the receipt preimage, and
`channel_id`. Finding the receipt preimage wrong is what that file bought; see FINDINGS #5.
Where the spec still does not determine an answer the call is marked AMBIGUOUS and surfaced
as an explicit choice rather than guessed silently. See FINDINGS.md.

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

# App. F.1/F.3 domain separation. The leaf and the Merkle node deliberately carry no
# prefix — length alone separates a 64 B node from every leaf preimage — but the two
# signed-by-a-party messages do, and they carry a version byte with it.
CHANNEL_ID_DOMAIN = b"FLOP/COMPUTE_CHANNEL/ID"
RECEIPT_DOMAIN = b"FLOP/COMPUTE_CHANNEL/RECEIPT"
PROTOCOL_VERSION = 1
CHANNEL_ID_PREIMAGE_BYTES = 128
RECEIPT_PREIMAGE_BYTES = 125

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
    # F.3 lists `leaf_version` as the first field of the VerifiedTurn container: "mandatory
    # SCALE enum at the start of every current settlement/dispute turn container". It is
    # part of the submitted data, not something a verifier gets to infer.
    leaf_version: LeafVersion = "V3"

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

    Appendix F.3 settles the odd-node case: "an odd last node is duplicated". That is the
    default here, and it is the only value correct against FLOP.

      duplicate — hash the odd node against itself                        <- F.3
      promote   — carry the odd node up one level unchanged (Substrate binary-merkle-tree)

    `promote` stays implemented, and the argument stays explicit, because the two
    conventions give different roots for any leaf count that is not a power of two: code
    reused against some other Merkle spec must name that spec's convention rather than
    inherit FLOP's. FINDINGS #2 records that this file once claimed F.3 was silent here,
    and why that was wrong.
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


def channel_id(
    genesis_hash: bytes, agent: bytes, miner: bytes, nonce: int
) -> bytes:
    """App. F.1 channel_id v1.

    blake2_256(domain ‖ 01 ‖ genesis_hash ‖ agent ‖ miner ‖ nonce:u64LE) — 128 B preimage.

    The genesis hash is what stops a receipt signed on one deployment from replaying on
    another, and the nonce is what stops the same agent/miner pair from colliding across
    sessions. Both are inside the id, so every leaf and the receipt inherit that binding
    from their first field without needing a prefix of their own.
    """
    preimage = (
        CHANNEL_ID_DOMAIN
        + bytes([PROTOCOL_VERSION])
        + _h256("genesis_hash", genesis_hash)
        + _h256("agent", agent)
        + _h256("miner", miner)
        + _uint("nonce", nonce, 8)
    )
    if len(preimage) != CHANNEL_ID_PREIMAGE_BYTES:
        raise TranscriptError(
            f"channel_id preimage is {len(preimage)} bytes, spec says {CHANNEL_ID_PREIMAGE_BYTES}"
        )
    return blake2_256(preimage)


def receipt_preimage(
    channel_id_bytes: bytes, final_root: bytes, aggregate_gn: int, payable: int
) -> bytes:
    """App. F.3 agent receipt v1 — the bytes the agent counter-signs with sr25519.

        "FLOP/COMPUTE_CHANNEL/RECEIPT" ‖ 01 ‖ channel_id ‖ final_root
                                       ‖ aggregate_gn:u128LE ‖ payable:u128LE

    125 bytes. Earlier revisions of this file built the four fields without the domain tag
    and version byte, on the strength of R12.1b's prose ("counter-sign a receipt over the
    cumulative root"); the published vectors show the tag is part of the preimage. An agent
    signing the untagged 96 bytes produces a signature `settle` rejects — and, worse, one
    that is not domain-separated from any other 96-byte payload. See FINDINGS #5.

    AMBIGUOUS (FINDINGS #3). `payable` occurs exactly once in the Yellow Paper — in this
    row — and is never defined: not in §12.1, not in Appendix A, not as an argument of
    `settle`. The receipt authorizes the payout, so the agent is signing a number whose
    meaning the spec does not give it. Encoding it is unambiguous; knowing what to put
    there is not. Reported upstream as flop-labs/yellowpaper#56.
    """
    preimage = (
        RECEIPT_DOMAIN
        + bytes([PROTOCOL_VERSION])
        + _h256("channel_id", channel_id_bytes)
        + _h256("final_root", final_root)
        + _uint("aggregate_gn", aggregate_gn, 16)
        + _uint("payable", payable, 16)
    )
    if len(preimage) != RECEIPT_PREIMAGE_BYTES:
        raise TranscriptError(
            f"receipt preimage is {len(preimage)} bytes, spec says {RECEIPT_PREIMAGE_BYTES}"
        )
    return preimage


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
) -> bool:
    """Does the enclave signature verify under the version this turn declares?

    Exactly one preimage is tried — the one the turn's own `leaf_version` tag names. F.3:

        unknown tags reject; verifier selects exactly one preimage and never retries

    Earlier revisions of this file tried V3 and then fell back to V2, on the strength of an
    older F.3 wording. That is worse than a wrong answer: V2 omits `toploc_commitment_hash`,
    so a fallback quietly accepts a turn carrying less evidence than the channel requires,
    and reports it as verified. See FINDINGS #6, and the reason D-0505 gives for removing
    trial verification from the runtime.

    The signature covers the 32-byte leaf hash, not the preimage.
    """
    try:
        digest = turn.leaf_hash(channel_id, turn.leaf_version)
    except TranscriptError:
        return False
    return verifier(turn.enclave_sig, digest, enclave_key)


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
    pinned_decode_policy: bytes | None = None,
) -> TranscriptCheck:
    """Everything the agent must confirm before counter-signing. Fail-closed.

    Returns a result rather than raising, so a caller cannot accidentally treat an
    exception path as success. Any false is a refusal to sign.

    `pinned_decode_policy` is the channel's `ChannelDecodePolicies` entry, and passing it is
    how a caller says the channel is policy-bound. F.3's accepted-version cutoff then
    applies: only explicitly tagged V2/V3 leaves are admissible and each must carry an equal
    policy hash. Passing None models a channel opened before policy binding, which accepts
    explicit V0-V3. There is no default that is safe for both, so the caller states which.
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
        if pinned_decode_policy is not None:
            if t.leaf_version not in ("V3", "V2"):
                return TranscriptCheck(
                    False,
                    f"turn {t.turn_index}: {t.leaf_version} leaf on a policy-pinned channel "
                    "(UnsupportedLeafVersion)",
                )
            if t.decode_policy_hash != pinned_decode_policy:
                return TranscriptCheck(
                    False, f"turn {t.turn_index}: decode policy does not match the channel's"
                )

        if not verify_turn_signature(t, channel_id, enclave_key, verifier=verifier):
            return TranscriptCheck(
                False,
                f"turn {t.turn_index}: enclave signature does not verify as "
                f"{t.leaf_version}",
            )
        versions.append(t.leaf_version)

        try:
            leaf = t.leaf_hash(channel_id, t.leaf_version)
        except TranscriptError as e:
            return TranscriptCheck(False, f"turn {t.turn_index}: {e}")
        if not verify_merkle_path(leaf, t.merkle_path, final_root):
            return TranscriptCheck(False, f"turn {t.turn_index}: Merkle path does not reach the root")

    return TranscriptCheck(True, "ok", tuple(versions), aggregate)
