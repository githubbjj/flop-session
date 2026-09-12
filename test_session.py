#!/usr/bin/env python3
"""Checks for flop_session.

There are no published FLOP vectors, so nothing here claims to match an authority. Two
things are checked instead:

  1. Internal consistency with the sizes and rules the Yellow Paper does state.
  2. That the gate refuses everything it should refuse — a verifier that accepts a forged
     transcript is worse than none, since its whole purpose is to stop the agent signing.

The end-to-end case builds a transcript with a real sr25519 enclave key, so the signature
path is exercised rather than stubbed.

Run: python test_session.py
"""

from __future__ import annotations

import sys

import sr25519

from flop_session import (
    LEAF_SIZES,
    VERIFIED_TURN_FIXED_BYTES,
    TranscriptError,
    VerifiedTurn,
    blake2_256,
    checked_aggregate_gn,
    merkle_parent,
    merkle_root,
    receipt_preimage,
    verify_merkle_path,
    verify_transcript,
)

results: list[tuple[bool, str]] = []


def check(label: str, got, want) -> None:
    ok = got == want
    results.append((ok, label))
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"      got : {got!r}\n      want: {want!r}")


def refuses(label: str, fn) -> None:
    try:
        r = fn()
    except TranscriptError:
        results.append((True, label))
        print(f"PASS  {label}")
        return
    ok = r is False or (hasattr(r, "ok") and r.ok is False)
    results.append((ok, label))
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"      accepted something it should have refused: {r!r}")


CHANNEL_ID = bytes(range(32))
SEED = bytes([7]) * 32
PUB, PRIV = sr25519.pair_from_seed(SEED)[0], sr25519.pair_from_seed(SEED)[1]


def make_turn(i: int, g_n: int, path=()) -> VerifiedTurn:
    return VerifiedTurn(
        turn_index=i,
        h_in=blake2_256(f"in{i}".encode()),
        h_out=blake2_256(f"out{i}".encode()),
        g_n=g_n,
        decode_policy_hash=blake2_256(b"decode-policy"),
        h_ids=blake2_256(b"ids"),
        toploc_commitment_hash=blake2_256(f"toploc{i}".encode()),
        miner_recv_ms=1_756_703_600_000 + i,
        miner_done_ms=1_756_703_600_500 + i,
        latency_ms=500,
        enclave_sig=b"\x00" * 64,
        merkle_path=path,
    )


def sign_turn(t: VerifiedTurn) -> VerifiedTurn:
    """Sign the leaf the turn declares — an enclave signs one version, not a menu."""
    digest = t.leaf_hash(CHANNEL_ID, t.leaf_version)
    sig = sr25519.sign((PUB, PRIV), digest)
    return VerifiedTurn(**{**t.__dict__, "enclave_sig": sig})


print("leaf layout (App. F.3)")
t0 = make_turn(0, 1000)
for v, size in LEAF_SIZES.items():
    check(f"{v} preimage is {size} bytes", len(t0.leaf_preimage(CHANNEL_ID, v)), size)

fixed = 4 + 32 + 32 + 16 + 32 + 32 + 32 + 8 + 8 + 8 + 64
check("VerifiedTurn fixed fields sum to 268", fixed, VERIFIED_TURN_FIXED_BYTES)
check("receipt preimage is 125 bytes", len(receipt_preimage(CHANNEL_ID, b"\x11" * 32, 5, 7)), 125)

print()
print("merkle")
a, b, c = (blake2_256(x) for x in (b"a", b"b", b"c"))
check("two leaves fold to one parent", merkle_root([a, b]), merkle_parent(a, b))
check(
    "path verifies for the right sibling",
    verify_merkle_path(a, [(b, False)], merkle_parent(a, b)),
    True,
)
check(
    "sibling_is_left flips the concatenation order",
    verify_merkle_path(b, [(a, True)], merkle_parent(a, b)),
    True,
)
refuses("a wrong sibling is refused", lambda: verify_merkle_path(a, [(c, False)], merkle_parent(a, b)))
refuses("a truncated hash is refused", lambda: verify_merkle_path(a[:31], [(b, False)], merkle_parent(a, b)))

# The ambiguity, made visible: three leaves, two conventions, two different roots.
dup = merkle_root([a, b, c], odd_policy="duplicate")
pro = merkle_root([a, b, c], odd_policy="promote")
check("odd-count roots differ between the two conventions", dup != pro, True)
# F.3: "an odd last node is duplicated" — so the default must be that one, not the other.
check("the default odd-node policy is F.3's duplicate", merkle_root([a, b, c]), dup)

print()
print("aggregate")
check("distinct turns sum", checked_aggregate_gn([make_turn(0, 10), make_turn(1, 32)]), 42)
refuses("a duplicate turn_index is refused", lambda: checked_aggregate_gn([make_turn(0, 1), make_turn(0, 1)]))
refuses("an empty bundle is refused", lambda: checked_aggregate_gn([]))
refuses("over the 1024-turn cap is refused", lambda: checked_aggregate_gn([make_turn(i, 1) for i in range(1025)]))

print()
print("end-to-end transcript, real sr25519 enclave key")
raw = [make_turn(0, 100), make_turn(1, 250)]
leaves = [t.leaf_hash(CHANNEL_ID, "V3") for t in raw]
root = merkle_parent(leaves[0], leaves[1])
turns = [
    sign_turn(VerifiedTurn(**{**raw[0].__dict__, "merkle_path": [(leaves[1], False)]})),
    sign_turn(VerifiedTurn(**{**raw[1].__dict__, "merkle_path": [(leaves[0], True)]})),
]

good = verify_transcript(
    channel_id=CHANNEL_ID, enclave_key=PUB, turns=turns,
    final_root=root, claimed_aggregate_gn=350,
)
check("a well-formed transcript verifies", (good.ok, good.aggregate_gn), (True, 350))
check("both turns verified as V3", good.versions, ("V3", "V3"))

refuses(
    "an inflated aggregate claim is refused",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB, turns=turns,
        final_root=root, claimed_aggregate_gn=351,
    ),
)
refuses(
    "a wrong enclave key is refused",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=bytes(32), turns=turns,
        final_root=root, claimed_aggregate_gn=350,
    ),
)
refuses(
    "a wrong final_root is refused",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB, turns=turns,
        final_root=bytes(32), claimed_aggregate_gn=350,
    ),
)
refuses(
    "a transcript from another channel is refused",
    lambda: verify_transcript(
        channel_id=bytes(32), enclave_key=PUB, turns=turns,
        final_root=root, claimed_aggregate_gn=350,
    ),
)

# g_n is the payment term; tampering with it must break the signature, not just the sum.
tampered = VerifiedTurn(**{**turns[0].__dict__, "g_n": 100_000})
refuses(
    "raising g_n after signing is refused",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB, turns=[tampered, turns[1]],
        final_root=root, claimed_aggregate_gn=100_250,
    ),
)

print()
print("the accepted-version cutoff (App. F.3, D-0505)")
POLICY = blake2_256(b"decode-policy")

# A turn whose fields are V3 but whose tag says V2. Trial verification would hash it as V3,
# find a match and report "verified"; selecting the declared version refuses it. This is the
# whole of FINDINGS #6 in one case.
mislabelled = VerifiedTurn(**{**turns[0].__dict__, "leaf_version": "V2"})
refuses(
    "a V2 tag over V3 fields is refused, not retried as V3",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB, turns=[mislabelled, turns[1]],
        final_root=root, claimed_aggregate_gn=350, pinned_decode_policy=POLICY,
    ),
)

# V2 omits toploc_commitment_hash, so admitting one on a policy-pinned channel is an
# evidence downgrade whatever the signature says.
v2_raw = VerifiedTurn(**{**raw[0].__dict__, "leaf_version": "V2", "merkle_path": [(leaves[1], False)]})
v2_signed = sign_turn(v2_raw)
v2_leaf = v2_signed.leaf_hash(CHANNEL_ID, "V2")
v2_root = merkle_parent(v2_leaf, leaves[1])
v2_ok = verify_transcript(
    channel_id=CHANNEL_ID, enclave_key=PUB,
    turns=[VerifiedTurn(**{**v2_signed.__dict__, "merkle_path": [(leaves[1], False)]}),
           VerifiedTurn(**{**turns[1].__dict__, "merkle_path": [(v2_leaf, True)]})],
    final_root=v2_root, claimed_aggregate_gn=350, pinned_decode_policy=POLICY,
)
check("a correctly tagged V2 turn is admissible on a pinned channel", v2_ok.ok, True)
check("and is reported as V2, not silently as V3", v2_ok.versions[0], "V2")

legacy = sign_turn(VerifiedTurn(**{**raw[0].__dict__, "leaf_version": "V1"}))
refuses(
    "a legacy V1 tag is refused on a policy-pinned channel",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB,
        turns=[VerifiedTurn(**{**legacy.__dict__, "merkle_path": [(leaves[1], False)]})],
        final_root=root, claimed_aggregate_gn=100, pinned_decode_policy=POLICY,
    ),
)
refuses(
    "a turn whose decode policy is not the channel's is refused",
    lambda: verify_transcript(
        channel_id=CHANNEL_ID, enclave_key=PUB, turns=turns,
        final_root=root, claimed_aggregate_gn=350, pinned_decode_policy=bytes(32),
    ),
)

print()
passed = sum(1 for ok, _ in results if ok)
print(f"{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
