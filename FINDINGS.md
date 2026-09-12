# What an agent-side verifier runs into in the Yellow Paper — and one thing I got wrong

Found by implementing the agent's R12.1b duty — verify every turn and counter-sign the
receipt — against **Yellow Paper v0.5.0, updated 2026-09-05**.

Each one is a place where two people reading the spec carefully would ship different
bytes. Three are on the money path: they change the root the agent signs, or the number it
authorises.

None of them appear in the open-items list (E.8–E.51) as far as that list is referenced in
the body. E.51 (canonical wire-format closure) is adjacent to #1 but is about the accepted
legacy cutoff, not about the body and the appendix disagreeing.

**Status, 2026-09-12.** #1 was already filed upstream by someone else, and is the more
thorough write-up: [flop-labs/yellowpaper#4]. #2 is retracted — it was my misreading. #3
and #4 are filed as [#56] and [#57], and an independent conformance lab reproduced both
within the hour. #5 is not a spec problem at all; it is a bug the spec's own published
vectors found in **this** code.

[flop-labs/yellowpaper#4]: https://github.com/flop-labs/yellowpaper/issues/4
[#56]: https://github.com/flop-labs/yellowpaper/issues/56
[#57]: https://github.com/flop-labs/yellowpaper/issues/57

---

## 1. §12.1b and Appendix C.4 state the leaf as the form Appendix F.3 forbids

**R12.1b** (normative body):

> the enclave … MUST sign each turn (`session_id ‖ turn_index ‖ H(input) ‖ H(output) ‖ G_n`)
> into a running Merkle accumulator

**Appendix C.4** repeats the same five fields.

**Appendix F.3** specifies the V3 leaf as eleven fields:

> `channel_id ‖ turn_index ‖ h_in ‖ h_out ‖ g_n ‖ decode_policy_hash ‖ h_ids ‖
> toploc_commitment_hash ‖ miner_recv_ms ‖ miner_done_ms ‖ latency_ms`

Count the body's five fields in bytes: 32 + 4 + 32 + 32 + 16 = **116**. That is exactly
what F.3 calls the **V0 legacy leaf** — and F.3 says a pinned decode policy **forbids**
falling back to V1/V0.

So the normative body describes a leaf the format appendix prohibits. An implementer
working from §12.1b, which reads as the definition, produces a forbidden leaf and every
signature fails against a conforming counterparty.

The two also disagree on the first field's name: `session_id` in the body, `channel_id` in
F.3. In a byte-level preimage that is not a cosmetic difference — a reader has to guess
whether they are the same value.

**Suggested fix:** have §12.1b and C.4 cite F.3 rather than restate a field list, or state
the V3 list in full. One definition, one place.

## 2. ~~Odd node counts leave the Merkle root undefined~~ — RETRACTED

**This finding was wrong. Retracted 2026-09-12.** The rule is specified, in the notes
column of the same Appendix F.3 table row whose node rule I quoted:

> leaf order is turn order; left is first; **an odd last node is duplicated**; empty root
> is `00×32`; single-leaf root is the leaf

So F.3 names the convention — hash the odd node against itself — and there is no
ambiguity to report. I read the rule out of the row and not the note beside it.

What I originally claimed is left below, struck, rather than deleted, because a verifier
that quietly edits its own error record is not one you should trust with a root.

> ~~It never says what happens at a level with an odd number of nodes. The two conventions
> in common use are to hash the odd node against itself, or to promote it unchanged to the
> next level — the second is what Substrate's own `binary-merkle-tree` does. They produce
> different roots for any leaf count that is not a power of two.~~

The divergence itself is real and `test_session.py` still asserts it, so the test stays.
What changes is the conclusion: `merkle_root` keeps its explicit `odd_policy` argument,
but no longer because the spec is silent — it is there so a caller reusing this code
against a **different** Merkle spec has to say which convention that one uses. Against
FLOP, the answer is F.3's: duplicate.

Upstream now has a related, sharper report from someone else —
[flop-labs/yellowpaper#44](https://github.com/flop-labs/yellowpaper/issues/44) — showing
that the duplication rule makes F.3's own `wrong_path_orientation` corpus case pass.

## 3. `payable` is signed but never defined

The receipt is:

> agent receipt — sr25519 over `channel_id ‖ final_root ‖ aggregate_gn:u128LE ‖ payable:u128LE`
> — authorizes the bound payout and claimed aggregate

`payable` occurs **exactly once in the whole document** — in that row. It is not in
§12.1, not in Appendix A's parameter reference, not in the extrinsic signature for
`settle`, which takes `agent_receipt_sig` but no separate payable argument.

Encoding it is unambiguous. Knowing what value to put is not. The agent is required to
sign a number described as authorising the payout, with no rule saying whether it is the
escrow, the two-part tariff `P` from R12.1d, something derived from `aggregate_gn`, or
something else — and it cannot recompute the chain's expectation to check.

This is the one that worries me most: an agent that guesses wrong either signs an
unpayable receipt or authorises more than it meant to.

**Suggested fix:** define `payable` where the receipt is specified, and say who computes
it and how the agent validates it before signing.

## 4. "sum-tree" (§6.5) versus a plain hash tree (F.3)

§6.5's hash table says:

> Merkle (BlakeTwo256 leaves) — the session transcript accumulator **+ aggregate_gn
> sum-tree** (§12.1b, App. F.3)

A sum-tree normally means interior nodes commit to the sum of their subtree, so the root
proves the total. But F.3's node rule carries no sum, and the aggregate is checked as
plain arithmetic over the submitted turns (`verified_work_from_turns`), which is why
R11.2a can call it "arithmetic/authentication only".

If it is one plain hash tree, "sum-tree" is misleading. If a second sum-committing
structure is intended, its node rule is not specified anywhere.

Minor next to the first three, but it sends an implementer looking for a structure that
may not exist.

---

## 5. The receipt preimage here was wrong, and FLOP's own vectors caught it

**Mine, not the spec's. Found and fixed 2026-09-12.**

This module built the agent receipt as four bare fields:

    channel_id ‖ final_root ‖ aggregate_gn:u128LE ‖ payable:u128LE     # 96 bytes — wrong

That came from reading R12.1b's prose, which says the agent "counter-signs a receipt over
the cumulative root" and never mentions a domain tag. Appendix F.3's actual row does:

> agent receipt v1 — sr25519 over `"FLOP/COMPUTE_CHANNEL/RECEIPT" ‖ 01 ‖ channel_id ‖
> final_root ‖ aggregate_gn:u128LE ‖ payable:u128LE`

28 bytes of ASCII domain plus a version byte, so **125 bytes, not 96**. An agent signing
the untagged form produces a signature `settle` rejects outright — and a payload with no
domain separation from any other 96-byte message, which is the exact class of mistake
R6.5e exists to prevent.

Two things are worth saying about how this was caught.

**It was not caught by the test suite.** `test_session.py` asserted the preimage was 96
bytes and passed, because the assertion and the implementation shared the same wrong
belief. A suite written against your own reading cannot find a misreading.

**It was caught the day the vectors were noticed.** `evidence/wire-format-v1.json` at
flop-labs/yellowpaper has been public since 10 September, and this repository claimed in
print that "no reference implementation and no published test vectors for FLOP" existed —
which was true when written and stopped being true without anyone here checking. The fix
is `test_vectors.py`, which runs this module against those vectors pinned by commit and
SHA-256: leaf preimages and hashes for all four versions, the Merkle root and path, the
receipt preimage, `channel_id`, and both sr25519 signatures. 18/18.

The lesson is the one this repository was written about in the first place. A verifier
that only ever agrees with itself is not a verifier, and I shipped one for five days.

---

## What this implementation chose

- **V3 leaf** per F.3, with V2 accepted on verification only, since F.3 says the verifier
  tries V3→V2. V1/V0 are constructed only to reproduce the stated sizes.
- **Odd-node policy stays an explicit argument**, defaulting to F.3's `duplicate`. The
  argument survives #2's retraction so that code reused against a different Merkle spec
  has to name that spec's convention rather than inherit FLOP's.
- **`payable` is passed in.** The module encodes it correctly and documents that it cannot
  tell the caller what it should be.

- **`channel_id` is derived here** rather than taken on trust, so the genesis hash and the
  session nonce that bind a receipt to one deployment are checked, not assumed.

Sizes reproduce the spec exactly — 236 / 172 / 140 / 116 for the leaf versions, 268 for
the fixed part of `VerifiedTurn`, 125 for the receipt preimage, 128 for the `channel_id`
preimage — and, since #5, every one of those is confirmed against FLOP's published
vectors rather than against this file's own reading.
