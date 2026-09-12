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
- Builds the receipt preimage the agent signs

Fail-closed throughout: `verify_transcript` returns a result rather than raising, so a
caller cannot mistake an exception path for success, and every refusal names its reason.

## Status, stated plainly

There is **no reference implementation and no published test vectors for FLOP** — the
chain does not exist yet. So unlike a port of a live protocol, nothing here is checked
against an authority. What is verified is:

- **Internal consistency** with the sizes the spec states: 236 / 172 / 140 / 116 for the
  four leaf versions, 268 for `VerifiedTurn`'s fixed part, 96 for the receipt preimage.
- **That it refuses what it must refuse.** A verifier that accepts a forged transcript is
  worse than no verifier, so most of the suite is negative cases: tampered `g_n`, inflated
  aggregate, wrong enclave key, wrong root, a transcript from another channel, duplicate
  turn indices.

```console
$ python test_session.py
23/23 checks passed
```

The spec is a draft and iterating — v0.5.0 was updated the day this was written. Treat
this as a reading of that draft, not a client.

## The point of it

Implementing surfaced four places where the Yellow Paper looked underdetermined — a leaf
definition in the normative body that the format appendix forbids, and a value the agent
is required to sign that the document never defines, among them. One of the four was my
own misreading and is **retracted in place** rather than deleted. See
**[FINDINGS.md](FINDINGS.md)**.

## Install and run

```console
python -m pip install py-sr25519-bindings
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

`merkle_root` takes an explicit `odd_policy` and has **no default**. For FLOP the answer is
fixed — Appendix F.3 duplicates the odd last node — so pass `"duplicate"`; the argument
stays required so that code reused against a different Merkle spec has to name that one's
convention rather than inherit FLOP's. See FINDINGS #2 for why this used to say otherwise.

## Scope

Transcript verification only. Not the chain, not `open_channel`/`settle` extrinsic
encoding, not TOPLOC or TEE attestation, not disputes, not the SOFT tier (whose end-to-end
definition is open item E.33).

## License

Apache-2.0, matching the FLOP project's published material.
