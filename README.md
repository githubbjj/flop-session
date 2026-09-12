# flop-session

Agent-side transcript verification for FLOP compute-channel sessions, written from
**Yellow Paper v0.5.0** before the network exists.

The FLOP testnet is planned for Q4 2026. Agents will buy inference by opening a payment
channel, receiving signed turns, and counter-signing a receipt at settlement. The Yellow
Paper puts one duty squarely on the agent (R12.1b):

> the agent MUST verify and counter-sign a receipt over the cumulative root before
> accepting output

An agent that counter-signs without verifying is paying for work it never checked, and the
receipt is what authorises the payout. This is that check, runnable today.

## What it does

- Builds the transcript leaf preimage exactly as Appendix F.3 states it (V3, with V2/V1/V0
  for legacy decode and size checks)
- Verifies the enclave's sr25519 signature over the 32-byte leaf hash
- Folds each turn up its Merkle path to the final root
- Recomputes the checked aggregate over distinct turn indices
- Derives `channel_id` (App. F.1) rather than taking it on trust
- Builds the receipt preimage the agent signs, domain-tagged as F.3 states it

Fail-closed throughout: `verify_transcript` returns a result rather than raising, so a
caller cannot mistake an exception path for success, and every refusal names its reason.

## Status, stated plainly

This was written when there was no reference implementation and no published test vectors
for FLOP, so for its first week nothing here was checked against an authority. That is no
longer the case, and the correction matters more than the original claim: FLOP publishes
canonical wire vectors at
[`evidence/wire-format-v1.json`](https://github.com/flop-labs/yellowpaper/blob/main/evidence/wire-format-v1.json),
and running against them found this module's receipt preimage **wrong** — see
[FINDINGS #5](FINDINGS.md). So there are two suites, and they do different jobs.

**Against FLOP's vectors** — pinned by commit and SHA-256, refusing to run if the bytes
differ. Leaf preimages and hashes for all four versions, the Merkle root and an
authentication path, the receipt preimage, `channel_id`, and both sr25519 signatures:

```console
$ python test_vectors.py
18/18 checks passed against the pinned vectors
```

**Against itself** — the sizes the spec states (236 / 172 / 140 / 116 for the leaf
versions, 268 for `VerifiedTurn`'s fixed part, 125 for the receipt preimage) and, mostly,
what it must refuse. A verifier that accepts a forged transcript is worse than no
verifier, so most of this suite is negative cases: tampered `g_n`, inflated aggregate,
wrong enclave key, wrong root, a transcript from another channel, duplicate turn indices:

```console
$ python test_session.py
24/24 checks passed
```

Both are needed. The vectors prove the bytes are right; they say nothing about whether a
forgery is refused, because a vector set of accepted cases cannot. The second suite proves
refusal but, on its own, proved the receipt was 96 bytes for five days.

The spec is a draft and iterating. Treat this as a reading of that draft, not a client.

## The point of it

Implementing surfaced four places where the Yellow Paper looked underdetermined — a leaf
definition in the normative body that the format appendix forbids, and a value the agent
is required to sign that the document never defines, among them. Two are filed upstream as
[#56](https://github.com/flop-labs/yellowpaper/issues/56) and
[#57](https://github.com/flop-labs/yellowpaper/issues/57); one had already been filed by
someone else, and better, as [#4](https://github.com/flop-labs/yellowpaper/issues/4); one
was my own misreading and is **retracted in place** rather than deleted. The fifth entry
is a bug in this code, not in the spec. See **[FINDINGS.md](FINDINGS.md)**.

## Install and run

```console
python -m pip install py-sr25519-bindings
python test_vectors.py     # fetches the pinned vectors on first run
python test_session.py
```

`blake2_256` comes from the standard library (`hashlib.blake2b(digest_size=32)`), which is
Substrate's `BlakeTwo256`. The sr25519 binding is only needed for signature checks; the
hashing and Merkle paths work without it.

## Use

```python
from flop_session import VerifiedTurn, verify_transcript

check = verify_transcript(
    channel_id=channel_id,
    enclave_key=enclave_key,        # attested once at open_channel
    turns=turns,
    final_root=final_root,
    claimed_aggregate_gn=claimed,
)
if not check.ok:
    raise SystemExit(f"refusing to counter-sign: {check.reason}")
```

`merkle_root` takes an explicit `odd_policy`, defaulting to F.3's `"duplicate"`. The
argument stays because the two conventions give different roots for any leaf count that is
not a power of two, so code reused against a different Merkle spec has to name that spec's
convention rather than inherit FLOP's. See FINDINGS #2 for why this used to say the spec
was silent here.

## Scope

Transcript verification only. `channel_id` derivation is included because a receipt is
only bound to one deployment and one session through it. Not the chain, not
`open_channel`/`settle` extrinsic encoding, not TOPLOC or TEE attestation, not disputes,
not the SOFT tier (whose end-to-end definition is open item E.33).

## License

Apache-2.0, matching the FLOP project's published material.
