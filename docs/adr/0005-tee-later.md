# ADR-0005: Transparency log now, TEE signer later

## Status

Accepted.

## Context

A receipt says "this Rebut ran these engines on these commits with this seed and
got this verdict". Someone has to sign it. If the orchestrator signs with a key it
holds, then whoever runs the orchestrator (us) can sign anything. A signer inside a
TEE (SEV-SNP, TDX, Nitro Enclaves) can attest which code produced the signature, so
the operator can't forge receipts. That removes the need to trust the operator.

TEEs add real cost and complexity: attestation verification, enclave builds, vendor
lock-in, side-channel history. They would also delay phase 1.

## Decision

- **Phase 1:** receipts are [in-toto](https://in-toto.io) statements signed by the
  **orchestrator's key** and appended to an **append-only transparency log**
  ([Rekor](https://github.com/sigstore/rekor) or
  [Trillian](https://github.com/google/trillian)). The log does not stop us from
  signing a false receipt. It makes every receipt public and permanent, so a
  forged or inconsistent receipt can be caught and proven afterwards.
- We state this plainly in the docs and on every receipt: **in phase 1, you trust the
  operator.** The transparency log makes misbehavior detectable, not impossible.
- **Phase 2:** the signer moves into a TEE. Receipts then carry an attestation that
  binds the signing key to a measured signer build.

## Consequences

- Phase 1 ships without enclave work.
- Everything that goes into a receipt (transcripts by digest, seed, environment
  digest) is already reproducible, so a third party can re-run and check a receipt
  without trusting us at all. This is the stronger guarantee, and it doesn't depend
  on the TEE.
- The receipt format must carry the signer identity type from day one, so TEE-signed
  receipts are an addition and don't break the format.

## Vote

3–2 (Security & Crypto Engineer and Skeptic dissenting).

Dissent (Security & Crypto Engineer, Skeptic): The product's pitch is neutrality: "you don't have to trust the contributor *or* us".
Shipping with an operator-held key weakens that pitch exactly when first impressions
form, and "we'll add the TEE later" is a promise that competitors can point at. Both
asked for the TEE signer in phase 1, or for launching without claiming neutrality.
The majority chose to ship, with the honest "trust us" statement.
