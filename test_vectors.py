"""Run flop_session against FLOP's own published wire vectors.

`test_session.py` checks this implementation against itself — the sizes the spec states
and the forgeries it must refuse. That catches a lot, but it cannot catch agreeing with
yourself about the wrong bytes. `evidence/wire-format-v1.json` in flop-labs/yellowpaper is
the canonical vector set, so this file is the check that actually has an authority behind
it. It found the receipt preimage wrong (FINDINGS #5).

The vector file is not vendored. It is fetched from a pinned commit and checked against a
pinned SHA-256, so this test is either running against exactly those bytes or not running:

    python test_vectors.py              # fetch (cached in ./vectors/) and check
    python test_vectors.py path.json    # check a copy you already have

Offline with no cached copy, it says so and exits 0 rather than reporting a pass.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from flop_session import (
    VerifiedTurn,
    blake2_256,
    channel_id,
    merkle_root,
    receipt_preimage,
    verify_merkle_path,
)

try:
    import sr25519
except ImportError:
    sr25519 = None

PIN_COMMIT = "3eaf2f25bc46a501df225cae4e4e991975f6b2a9"
PIN_SHA256 = "80d4a7e70f984342eb474ae5285a17a6b9348eca887e1689b15e641922051d93"
VECTOR_URL = (
    f"https://raw.githubusercontent.com/flop-labs/yellowpaper/{PIN_COMMIT}"
    "/evidence/wire-format-v1.json"
)
CACHE = Path(__file__).with_name("vectors") / "wire-format-v1.json"

passed = failed = 0


def check(name: str, got, want) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}\n        got  {got!r}\n        want {want!r}")


def load_vectors(argv: list[str]) -> dict | None:
    if len(argv) > 1:
        raw = Path(argv[1]).read_bytes()
    elif CACHE.exists():
        raw = CACHE.read_bytes()
    else:
        try:
            with urllib.request.urlopen(VECTOR_URL, timeout=30) as response:
                raw = response.read()
        except (urllib.error.URLError, OSError) as error:
            print(f"cannot reach the pinned vectors ({error});")
            print("run this again with network, or pass a local copy as an argument.")
            return None
        CACHE.parent.mkdir(exist_ok=True)
        CACHE.write_bytes(raw)

    digest = hashlib.sha256(raw).hexdigest()
    if digest != PIN_SHA256:
        # Refusing is the whole point: a vector file that is not the pinned one proves
        # nothing about conformance to the pinned one.
        raise SystemExit(
            f"vector file sha256 {digest}\n"
            f"            expected {PIN_SHA256}\n"
            "Upstream may have republished. Re-pin deliberately; do not relax this."
        )
    return json.loads(raw)


def main(argv: list[str]) -> int:
    vectors = load_vectors(argv)
    if vectors is None:
        return 0
    cc = vectors["compute_channel_v1"]
    negatives = {c["id"]: c for c in vectors.get("negative_cases", [])}
    hx = bytes.fromhex

    print(f"vectors: {vectors.get('profile')} {vectors.get('status')} @ {PIN_COMMIT[:7]}\n")

    print("channel_id (App. F.1)")
    ci = cc["channel_id"]
    inputs = ci["inputs"]
    check(
        "channel_id over the stated inputs",
        channel_id(
            hx(inputs["genesis_hash_hex"]),
            hx(inputs["agent_account_id32_hex"]),
            hx(inputs["miner_account_id32_hex"]),
            inputs["nonce"],
        ).hex(),
        ci["hash_hex"],
    )

    print("\nleaf preimages and hashes (App. F.3)")
    li = cc["leaf_inputs"]
    turn = VerifiedTurn(
        turn_index=li["turn_index"],
        h_in=hx(li["h_in_hex"]),
        h_out=hx(li["h_out_hex"]),
        g_n=int(li["g_n"]),
        decode_policy_hash=hx(li["decode_policy_hash_hex"]),
        h_ids=hx(li["h_ids_hex"]),
        toploc_commitment_hash=hx(li["toploc_commitment_hash_hex"]),
        miner_recv_ms=int(li["miner_recv_ms"]),
        miner_done_ms=int(li["miner_done_ms"]),
        latency_ms=li["latency_ms"],
        enclave_sig=b"\x00" * 64,
    )
    cid = hx(li["channel_id_hex"])
    # The inputs sit at the edges on purpose — turn_index is u32 max, g_n is u128 max,
    # the timings are u64 max minus one and two. A width mistake shows up here or nowhere.
    for entry in cc["leaf_versions"]:
        version = entry["version"]
        check(f"{version} preimage", turn.leaf_preimage(cid, version).hex(), entry["preimage_hex"])
        check(f"{version} leaf hash", turn.leaf_hash(cid, version).hex(), entry["hash_hex"])

    print("\nmerkle (App. F.3)")
    merkle = cc["merkle"]
    check("stated odd-node rule is the one we default to", merkle["odd_node_behavior"], "duplicate last")
    by_version = {e["version"]: hx(e["hash_hex"]) for e in cc["leaf_versions"]}
    leaves = [by_version[v] for v in merkle["leaf_order"]]
    check("root over the stated leaf order", merkle_root(leaves).hex(), merkle["root_hex"])
    path = [(hx(p["sibling_hex"]), p["sibling_is_left"]) for p in merkle["path_for_index_2"]]
    check(
        "stated path for index 2 verifies",
        verify_merkle_path(leaves[2], path, hx(merkle["root_hex"])),
        True,
    )
    # Three leaves is the smallest tree where the odd-node rule can be got wrong, which is
    # presumably why the vector set uses three.
    flipped = [(sibling, not is_left) for sibling, is_left in path]
    check(
        "the same path with orientations flipped is refused",
        verify_merkle_path(leaves[2], flipped, hx(merkle["root_hex"])),
        False,
    )

    print("\nagent receipt (App. F.3)")
    receipt = cc["receipt"]
    ri = receipt["inputs"]
    preimage = receipt_preimage(
        hx(ri["channel_id_hex"]), hx(ri["final_root_hex"]), ri["aggregate_gn"], ri["payable"]
    )
    check("receipt preimage", preimage.hex(), receipt["preimage_hex"])

    print("\nsignatures (sr25519)")
    if sr25519 is None:
        print("SKIP  py-sr25519-bindings is not installed")
    else:
        check(
            "the stated receipt signature verifies over our preimage",
            sr25519.verify(hx(receipt["signature_hex"]), preimage, hx(receipt["public_key_hex"])),
            receipt["expected"] == "accept",
        )
        leaf_sig = cc["v3_leaf_signature"]
        check(
            "the stated V3 leaf signature verifies over our leaf hash",
            sr25519.verify(
                hx(leaf_sig["signature_hex"]),
                turn.leaf_hash(cid, "V3"),
                hx(leaf_sig["public_key_hex"]),
            ),
            leaf_sig["expected"] == "accept",
        )
        check(
            "our leaf hash is the one that signature was made over",
            turn.leaf_hash(cid, "V3").hex(),
            leaf_sig["leaf_hash_hex"],
        )
        # A signature that verifies over a tampered message would make every check above
        # meaningless, so prove the verifier is not just answering True.
        check(
            "the receipt signature is refused over a mutated preimage",
            sr25519.verify(
                hx(receipt["signature_hex"]),
                preimage[:-1] + bytes([preimage[-1] ^ 0x01]),
                hx(receipt["public_key_hex"]),
            ),
            False,
        )

    print("\nthe published negative cases that this module is in scope for")
    # The vector set ships 14 cases that MUST be rejected. Accepting a forgery is the one
    # failure mode a verifier cannot have, so these matter more than the accept cases —
    # and the accept cases alone would not have caught the receipt bug in FINDINGS #5.
    wrong_genesis = negatives["wrong_genesis_network"]
    check(
        "wrong_genesis_network — a different chain gives a different channel_id",
        channel_id(
            bytes([hx(inputs["genesis_hash_hex"])[0] ^ 1]) + hx(inputs["genesis_hash_hex"])[1:],
            hx(inputs["agent_account_id32_hex"]),
            hx(inputs["miner_account_id32_hex"]),
            inputs["nonce"],
        ).hex(),
        wrong_genesis["bytes_hex"],
    )
    # The vector states the mutated channel_id but not which of agent/miner/nonce moved, so
    # the reproducible claim here is inequality, not the exact hash.
    check(
        "wrong_session — a different nonce gives a different channel_id",
        channel_id(
            hx(inputs["genesis_hash_hex"]),
            hx(inputs["agent_account_id32_hex"]),
            hx(inputs["miner_account_id32_hex"]),
            inputs["nonce"] + 1,
        ).hex()
        != ci["hash_hex"],
        True,
    )
    if sr25519 is not None:
        check(
            "invalid_receipt_signature — one flipped byte is refused",
            sr25519.verify(
                hx(negatives["invalid_receipt_signature"]["bytes_hex"]),
                preimage,
                hx(receipt["public_key_hex"]),
            ),
            False,
        )
        # This case is FINDINGS #5 shipped as a vector: its bytes are the untagged 96-byte
        # preimage this module used to build, followed by a signature over it. A verifier
        # with the old bug counter-signs exactly this and the chain refuses to settle.
        legacy = hx(negatives["legacy_receipt_current_channel"]["bytes_hex"])
        untagged = (
            hx(ri["channel_id_hex"])
            + hx(ri["final_root_hex"])
            + ri["aggregate_gn"].to_bytes(16, "little")
            + ri["payable"].to_bytes(16, "little")
        )
        check("legacy_receipt_current_channel is the untagged 96-byte form", legacy[:96], untagged)
        check(
            "legacy_receipt_current_channel — its signature is refused over the tagged preimage",
            sr25519.verify(legacy[96:], preimage, hx(receipt["public_key_hex"])),
            False,
        )

    # Out of scope here, and named rather than quietly skipped: unknown_leaf_enum,
    # unknown_retention_enum, truncated_fcc4, trailing_fcc4, unknown_fcc_version,
    # duplicate_turn_index, wrong_path_orientation, wrong_leaf_version,
    # legacy_leaf_current_channel and invalid_validator_signature all act on SCALE-encoded
    # wire bytes. This module takes structured turns, not a TranscriptBlob, so it has no
    # decoder to point at them. (duplicate_turn_index and path orientation are covered on
    # structured input in test_session.py — which is not the same as decoding the blob.)
    print(f"\n{passed}/{passed + failed} checks passed against the pinned vectors")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
