---
title: Verifiable Reporting and Operator Transparency for Encrypted Publications
description: A committing encryption envelope, a verifiable report format, and auditable operator receipts for end-to-end encrypted Lens publications.
author: Kimmo <kkpsiren@gmail.com>
discussions-to: TBD
status: Draft
type: Lens Ecosystem Standard
created: 2026-07-20
---

## Abstract

This standard defines how end-to-end encrypted Lens publications can be reported to moderators in a way that is cryptographically verifiable, and how the operators that serve decryption key shares produce auditable, transparency-loggable receipts. It specifies (1) a committing encryption envelope (`lens_cipher` v2) that binds each encrypted post to a 32-byte key commitment and to per-field associated data, (2) a report envelope by which a member who can already decrypt a post reveals its post key together with a citation of the violated policy clause, plus a deterministic verification algorithm, (3) optional on-chain anchoring of signed reports, (4) an operator response format whose exact signed bytes are returned to the requester and may be submitted to an RFC-6962-style transparency log, (5) an on-chain governance requirement for the operator registry (timelock ownership), and (6) optional advertisement of report-escalation parameters. The design goal is moderation of encrypted communities as a bounded, auditable power: reports reveal exactly one post, only by someone who could already read it, and every trust-relevant action leaves verifiable evidence. What this standard makes verifiable is the *process* — key commitments, report checks, operator receipts, log inclusion — never the moderation *judgment* itself, which remains human (see Security Considerations).

## Motivation

**Non-committing AES-GCM makes reports unfalsifiable.** The v1 `lens_cipher` envelope encrypts fields with AES-256-GCM. AES-GCM authenticates but does not commit to its key: for a fixed (nonce, associated data, ciphertext) triple, more than one key can pass tag verification, and the resulting plaintexts differ — the "invisible salamanders" problem. Consequently, a member who reveals "the key" of an abusive encrypted post proves nothing: successful decryption is not evidence that the revealed key is the key the community actually used, so a true report cannot be verified and a false report cannot be conclusively rebutted. Any report mechanism built on a non-committing envelope produces unfalsifiable claims. The v2 envelope closes this by pinning a key commitment inside the content-addressed, author-signed post metadata.

**Operator denials are unauditable.** Threshold operators decide, per request, whether an account is eligible to receive key shares. Today an operator signs its response, but the exact signed byte string is serialized internally and never returned; verifiers must re-serialize the response and hope to reproduce the same bytes, and no durable, third-party-verifiable record of the decision exists. A member wrongly denied access cannot prove the denial happened; an honest operator cannot prove it behaved correctly. This standard makes every operator response a portable receipt and defines a transparency log for receipts.

**Moderation as bounded, auditable power.** Encrypted communities still need moderation, but granting platforms or bots decryption capability would break the end-to-end model. This standard takes the position that moderation of encrypted content is report-driven only: the only party who can initiate a reveal is a member who could already decrypt the post, the reveal is scoped to exactly that post, the evidence is verifiable by anyone holding the report, and the surrounding operator and governance machinery (receipts, transparency log, timelocked registry ownership) is auditable. No party gains new decryption capability at any point.

**Trusted third parties, named and removed.** Each mechanism follows Szabo's design method: imagine the ideal trusted third party, then remove the trust — encryption and zero-knowledge proofs are partial removals (Szabo, "The God Protocols", 1997). Naming the trust that *remains* is part of this standard:

- The *report envelope* (§2) simulates a referee who reads members' messages to confirm abuse reports. Removed: any standing party with content access — verification is a deterministic public check, and the reveal is one post, by someone who could already read it. Retained: human judgment of the plaintext against the cited clause.
- The *operator transparency log* (§4) simulates a notary recording every key-share decision completely and truthfully. Removed: trust in the integrity of included receipts and in non-omission of dual-submitted ones. Retained: completeness for operator-only receipts and a single log view, until ≥ 2 witnesses exist.
- The *timelocked registry* (§5) simulates a registrar that never changes the operator set without warning members. Removed: silent or instant mutation. Retained: the power to mutate at all — constrained to act in public, at least 48 hours ahead.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Conventions used throughout:**

- `b64url` denotes base64url encoding without padding (RFC 4648 §5).
- `JCS(x)` denotes the RFC 8785 (JSON Canonicalization Scheme) serialization of JSON value `x`. Every JSON object that is hashed or signed under this standard MUST be canonicalized with JCS before hashing/signing, with one deliberate exception: operator receipt payloads are verified against the exact transmitted bytes (§4) and MUST NOT be re-serialized.
- `keccak256` outputs are rendered in JSON as lowercase `0x`-prefixed hex.
- `lp(x) = u32_be(byte_length(x)) ‖ x` — a length prefix of the byte string `x` as a 4-byte big-endian unsigned integer, followed by `x`. `‖` is byte-string concatenation.
- All timestamps and epoch numbers are JSON integers (never floats); JCS number serialization then yields deterministic bytes.
- HKDF-SHA256 is per RFC 5869; where no salt is given, the salt is absent (equivalently, a zero-filled string of hash length).

### 1. Committing encryption envelope (`lens_cipher` v2)

Encrypted posts continue to use the standard Lens metadata schema with placeholder public fields; all encryption data lives in the single `lens_cipher` JSON attribute. The v2 attribute value has this exact shape:

```json
{
  "v": 2,
  "suite": "X25519_MLKEM768_AES256GCM_HKDF_SHA256",
  "vault": "0x5cf39e64cff8d99f7c65f79c1b921c1fbc84bbdb",
  "epoch": 12,
  "postId": "42",
  "author": "0x3d5a1c9e0e2f6d8b7a4c0f1e2d3c4b5a69788766",
  "policy": "lens://policy-document-uri",
  "keyCommitment": "Q29tbWl0bWVudEV4YW1wbGUzMkJ5dGVzTG9uZ0FB",
  "fields": {
    "content": { "ct": "b64url…", "nonce": "b64url…" },
    "image":   { "ct": "b64url…", "nonce": "b64url…", "grove_uri": "lens://encrypted-blob" }
  }
}
```

| Member | Type | Requirement |
|---|---|---|
| `v` | integer | MUST be `2`. |
| `suite` | string | MUST be exactly `"X25519_MLKEM768_AES256GCM_HKDF_SHA256"`. |
| `vault` | string | Vault contract address, lowercase hex with `0x` prefix. |
| `epoch` | integer | Vault epoch under which the post key is derived. |
| `postId` | string | The Lens post id (predictable client-side before publication). |
| `author` | string | Author account address, lowercase hex with `0x` prefix. |
| `policy` | string | OPTIONAL. URI of the moderation policy document governing the vault/community. |
| `keyCommitment` | string | b64url of the 32-byte key commitment defined below. |
| `fields` | object | Map from field name to encrypted-field object. |

Each encrypted-field object contains:

| Member | Type | Requirement |
|---|---|---|
| `ct` | string | b64url of the AES-256-GCM ciphertext with the 16-byte tag appended. |
| `nonce` | string | b64url of the 96-bit AEAD nonce. Nonces MUST be unique per field under a given post key (fresh random per field). |
| `grove_uri` | string | OPTIONAL. Grove URI of an out-of-line encrypted blob for large binary fields; the referenced bytes are protected under the same post key and AAD discipline. |

**Key derivation.** Let `epoch_key` be the vault epoch key obtained via threshold reconstruction. The per-post message key (post key) is:

```
post_key = HKDF-SHA256(salt = none,
                       ikm  = epoch_key ‖ lp(postId) ‖ lp(author),
                       info = "lens-cipher-v2-message-key",
                       L = 32)
```

where `postId` and `author` are the exact UTF-8 bytes of the corresponding envelope members, used as given — no case canonicalization is applied here (canonicalization exists only inside the AAD construction below). This is the v1 structural shape (`epoch_key ‖ post_id ‖ author` as input keying material) with length prefixes added and the context string bumped; v1-derived keys are incompatible by construction. One post key protects all fields of one post. The exact derivation bytes are pinned by the reference vectors (see Test Cases).

**Key commitment.** The envelope commits to the post key:

```
keyCommitment = HKDF-SHA256(ikm = post_key,
                            info = "lens-cipher-v2-key-commit",
                            L = 32)
```

encoded as b64url (43 characters). Exactly one commitment exists per post.

**Per-field associated data.** Every AEAD operation over a field named `fieldName` MUST use:

```
AAD = ASCII("lens-cipher-v2-field-aad")
      ‖ lp(suite)
      ‖ lp(lowercase(vault))
      ‖ lp(decimal(epoch))
      ‖ lp(postId)
      ‖ lp(lowercase(author))
      ‖ lp(fieldName)
```

where every component is the exact UTF-8 byte string of the corresponding envelope member (`vault` and `author` lowercased; `epoch` rendered as its minimal decimal representation; `fieldName` is the field's key in the `fields` map). The length-prefix discipline makes the encoding injective: no two distinct component tuples produce the same AAD bytes.

**Decryption validation rules.** A decryptor:

1. MUST verify `v == 2` and reject any other version. v1 envelopes MUST be rejected.
2. MUST verify `suite` equals the exact string above; any other suite MUST be rejected.
3. MUST recompute the key commitment from the candidate post key and compare it to `keyCommitment` using a constant-time comparison, before any decryption is attempted. On mismatch, decryption MUST NOT be attempted.
4. MUST reconstruct the AAD as specified for each field and fail closed on any AEAD error.

### 2. Report envelope

A report is filed by a vault member who can already decrypt the post. The report envelope is a JSON document:

```json
{
  "v": 1,
  "kind": "lens-cipher-report",
  "post": {
    "feed": "0xfeedaddress…",
    "postId": "42",
    "author": "0x3d5a…",
    "metadataUri": "lens://metadata-uri",
    "revision": "revision-id"
  },
  "vault": "0x5cf3…",
  "epoch": 12,
  "metadataHash": "0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
  "revealedKey": "b64url-32-byte-post-key",
  "reason": {
    "policyUri": "lens://policy-document-uri",
    "clauseId": "harassment-2",
    "note": "optional free-text context"
  },
  "reporter": {
    "account": "0xreporter…",
    "sig": "0x…eip712-signature…"
  },
  "ts": 1784937600
}
```

| Member | Requirement |
|---|---|
| `v` | MUST be `1`. |
| `kind` | MUST be `"lens-cipher-report"`. |
| `post` | Identifies the reported publication: `feed` and `postId` locate it on-chain, `author` is its author, `metadataUri` is its metadata location, and `revision` is the exact metadata revision being reported (posts are editable; every report pins one revision). |
| `vault`, `epoch` | MUST equal the corresponding members of the embedded `lens_cipher` envelope. |
| `metadataHash` | `keccak256` over the exact byte serialization of the `lens_cipher` attribute value as it appears in the pinned metadata revision. |
| `revealedKey` | b64url of the 32-byte post key. |
| `reason` | Citation of the violated policy: `policyUri` and `clauseId` are REQUIRED, `note` is OPTIONAL. |
| `reporter` | Either an attribution object (`account`, `sig`) or `null` for anonymous reports. |
| `ts` | Unix time in seconds (integer) at which the report was created. |

**Canonicalization and reporter signature.** All hashing and signing of the report envelope operates on `JCS(envelope)`. The reporter signature is EIP-712 typed data with domain:

```
{ name: "lens-cipher-report", version: "1", chainId: <Lens Chain id> }
```

and message type:

```
LensCipherReport(bytes32 envelopeHash)
```

where `envelopeHash = keccak256(JCS(E₀))` and `E₀` is the report envelope with the `reporter` member set to `null`. Verifiers MUST recover the EIP-712 signer and check it equals `reporter.account`.

**Verification algorithm.** A verifier evaluates a report in four steps:

1. **Metadata fetch and hash check.** Confirm on-chain (or via a Lens API) that `(post.feed, post.postId)` exists with author `post.author` and metadata at `post.metadataUri`. Fetch the exact revision `post.revision` of the metadata. If that revision cannot be retrieved, verification MUST fail closed: the report is unverifiable and MUST be treated as invalid — a missing revision never yields a positive verdict. Extract the exact bytes of the `lens_cipher` attribute value and check `keccak256(bytes) == metadataHash`. Mismatch ⇒ invalid.
2. **Commitment check.** Parse the envelope from those bytes; validate `v == 2`, exact suite, and that `vault`/`epoch` match the report. Compute `HKDF-SHA256(ikm = revealedKey, info = "lens-cipher-v2-key-commit", L = 32)` and compare to `keyCommitment` in constant time. On mismatch the report is invalid **and nothing has been revealed**: a key that fails the commitment decrypts nothing and discloses nothing about the plaintext.
3. **AAD decryption.** Reconstruct each field's AAD from the envelope members (§1) and AES-256-GCM-decrypt every field with `revealedKey`, its `nonce`, and its AAD. Any AEAD failure ⇒ invalid.
4. **Human judgment.** The verifier reads the recovered plaintexts and judges them against the cited clause (`reason.policyUri`, `reason.clauseId`). The protocol guarantees that the plaintext is the authentic content of that post revision; the verdict itself is and remains human.

**Reveal scope and distribution.** A valid report reveals the plaintext of exactly one post — all of its fields — to every holder of the report envelope. (Because the post key is derived per post, not per revision, other revisions of the same post are decryptable with the same key by holders who fetch them; the reveal never extends to any other post or to the epoch key.) Report envelopes SHOULD be distributed confidentially to the moderators of record rather than published, since possession of the envelope is possession of the plaintext.

### 3. On-chain anchoring

Signed reports MAY be anchored on-chain for censorship-resistant timestamping via the existing `ReportRule`:

```
ReportRule.reportPost(reporter, feed, postId, reason = keccak256(JCS(envelope)))
```

where `envelope` is the complete signed report envelope (including the `reporter` object). The current `ReportRule` requires `msg.sender == reporter`; therefore anonymous reports (`reporter: null`) are off-chain only in v1 of this standard. Relayer-anchored anonymous reports are a possible future extension.

### 4. Operator receipts and transparency log

**Operator response v2.** An operator's response to a share request MUST be:

```json
{ "payload_b64": "…", "signature": "0x…" }
```

where `payload_b64` is the standard base64 encoding (RFC 4648 §4 — standard alphabet, not base64url, matching the existing operator-signature encoding convention) of the **exact byte string that was signed**. The signing preimage is:

```
"\x19Lens Cipher Operator Response v2:\n" ‖ ascii_decimal(byte_length(payload)) ‖ payload
```

and `signature` is a 65-byte secp256k1 ECDSA signature (r ‖ s ‖ v, hex) over `keccak256(preimage)` by the operator's registered key. Verifiers MUST decode `payload_b64`, reconstruct the preimage from those exact bytes, verify/recover the signer against the registry, and only then parse the payload JSON. Verifiers MUST NOT re-serialize the parsed payload for signature purposes.

The payload is a JSON document:

```json
{
  "v": 2,
  "operator": "0xoperator…",
  "requester": "0xaccount…",
  "client_public_key": "…",
  "shares": [ "…" ],
  "denied": [ { "vault": "0x…", "reason": "…" } ],
  "log": { "seq": 1041 }
}
```

`v` MUST be `2`. `operator`, `requester`, `client_public_key`, `shares`, and `denied` carry the same semantics as the v1 signed response (the request's client public key and the per-vault share grants and denials). `log` is OPTIONAL and present only when the operator participates in a transparency log; `log.seq` is the operator-assigned, monotonically increasing sequence number of this receipt in the operator's receipt stream.

**Witness/log service.** Operator receipts MAY be submitted to a transparency log: an independently operated service (the operator API itself stays stateless) that maintains an append-only, RFC-6962-style Merkle tree over receipt leaves and periodically issues signed tree heads (STHs: tree size, root hash, timestamp, log signature). A leaf is `JCS({ "payload_b64": …, "signature": … })`; leaf and interior node hashing follow RFC 6962 §2.1 (SHA-256; `0x00` leaf prefix, `0x01` node prefix). The log SHOULD serve inclusion proofs and consistency proofs. Operators SHOULD push every receipt they issue; requesters MAY dual-submit receipts they receive (the same leaf submitted twice deduplicates).

**Transparency claims (v1).** Implementations and documentation MUST state the guarantees at exactly this strength and no stronger:

- Receipts are **tamper-evident after inclusion**: once a receipt is included under an STH, its alteration or removal is detectable via inclusion and consistency proofs.
- **Omission is evident only for dual-submitted receipts**: a receipt the requester submitted (and holds an inclusion proof or signed submission acknowledgment for) cannot be silently omitted without detection; a receipt that only the operator held can be silently withheld from the log.
- **Equivocation is detectable via STH gossip once at least two independent witnesses exist**; with a single log instance and no witnesses, equivocation (serving forked tree views) is not detectable in v1.

A fuller consistency-proof and witness ecosystem is a future version of this standard.

### 5. Governance requirement

The owner of `OperatorRegistry` MUST be a timelock controller (e.g., OpenZeppelin `TimelockController`) with a minimum delay of at least 48 hours, so that every operator-set mutation (register, update, remove, threshold change) is publicly visible at least 48 hours before it takes effect. The arrangement MUST be verifiable on-chain by anyone: `OperatorRegistry.owner()` returns the timelock address, and `getMinDelay()` on that address returns ≥ 172800 (seconds). Clients and SDKs MAY verify this before trusting registry-served operator sets; deployments SHOULD monitor both values continuously and alert on deviation.

### 6. Escalation parameters (OPTIONAL)

A moderation policy document (referenced by the envelope's `policy` member and by `reason.policyUri`) MAY advertise report-escalation parameters:

```json
{ "report": { "windowSeconds": 604800, "threshold": 3 } }
```

- `windowSeconds`: the duration after publication (or after a revision) during which the community commits to acting on reports.
- `threshold`: the number of distinct valid reports after which escalation (e.g., review by additional moderators) SHOULD occur.

These parameters are advisory coordination values in v1; the protocol does not enforce them.

## Rationale

**Rejected cryptographic alternatives: computing on ciphertext (FHE, FE, iO).** The obvious alternative to report-driven reveal is to evaluate moderation over the ciphertext itself — a classifier under fully homomorphic encryption, functional-encryption keys for a violates-policy predicate, or an obfuscated policy program — so that no key is ever revealed. This family is rejected on two independent grounds. *Overhead:* at the current state of the art, functional encryption alone carries overhead "in the trillions of trillions"; the rigorously provable iO pipeline has expected runtimes exceeding the lifetime of the universe; and the most aggressive published construction (diamond iO) is still "planetary" and restricted to low-depth circuits — nothing classifier-shaped fits at any assumption level (Buterin, "Obfuscation: building the final boss of cryptography", parts I–II, 2026: https://vitalik.eth.limo/general/2026/06/29/obfuscation1.html, https://vitalik.eth.limo/general/2026/07/28/obfuscation_part_ii_diamond_io.html). *Reintroduced trust:* FE requires a trusted key-issuing authority, violating this standard's invariant that operators never hold decryption capability; and iO-based moderation would make the policy rules hidden-but-enforced, reversing the anchored, auditable-clause transparency that this standard treats as a governance requirement, not as a stopgap awaiting stronger cryptography. Report-driven franking by members who can already decrypt is therefore the frontier optimum for moderating end-to-end encrypted content, not an interim compromise.

**External key commitment, not CTX, not HMAC franking.** Three families of fixes to non-committing AEAD were considered. (a) *HMAC-based message franking* (the Facebook design analyzed by Grubbs et al.) requires an online franking authority that MACs each ciphertext at send time; Lens has no central message path to host such an authority, and the content-addressed, author-signed metadata already pins the ciphertext bytes, so a stored commitment achieves verifiable reveal with no new online party. (b) *Committing AEAD transforms such as CTX* add a committing tag to every AEAD invocation, changing the ciphertext format in every SDK and the AEAD core. (c) The chosen design — an *external key commitment*, one 32-byte HKDF output per post stored in the envelope — leaves AES-GCM untouched and recovers full binding by composition, because the nonce, AAD inputs, ciphertext, and metadata revision are already immutably pinned by content addressing (see Security Considerations). CTX remains the designated fallback: if independent review rejects the composition argument, a suite revision shipping per-field CTX tags is committing by construction and is still acceptable pre-launch.

**Why JCS (RFC 8785).** Four language ecosystems (Rust, TypeScript, Dart, backend JS) must produce byte-identical serializations wherever JSON is hashed or signed; ad-hoc canonicalization is a classic source of interoperability and security bugs, and JCS is a published RFC with multiple existing implementations. The operator receipt path deliberately avoids canonicalization at verification time instead: the signer transmits the exact signed bytes (`payload_b64`), which is strictly more robust than any re-serialization scheme. Canonicalization is used only where the hashing party and the producing party are different (report envelopes, log leaves).

**Why the log claims are weakened.** A single transparency log without a witness ecosystem cannot honestly promise completeness (no omission) or a single view (no equivocation). Rather than overclaim, v1 states exactly what the mechanism enforces — tamper-evidence after inclusion — plus the two upgrade paths that strengthen it: dual submission (turns omission into evidence) and STH gossip among ≥ 2 witnesses (turns equivocation into evidence). The claim ladder strengthens as ecosystem pieces appear, without any change to the receipt format.

## Backwards Compatibility

lens-cipher is pre-launch (testnet only); this standard is part of a deliberate pre-launch protocol reset, alongside the suite-1 definition. v2 decryptors MUST reject v1 envelopes; there is no dual-stack operation and no migration of v1 content. The operator response v2 format replaces the v1 signed response; SDKs verifying v2 responses verify against `payload_b64` only.

## Test Cases

Reference vectors live in the lens-cipher repository at `crates/crypto/tests/vectors/v2.json`: cross-SDK golden vectors covering post-key derivation, key commitment, raw AAD byte strings, per-field ciphertexts, and complete envelopes; negative vectors covering v1 envelopes (must reject), wrong suite strings, commitment mismatches, and single-component AAD mutations; and property-test corpora for commitment binding and AAD injectivity. Conformant implementations MUST pass all vectors.

## Security Considerations

**The invisible-salamanders problem.** AES-GCM (like all GMAC-based AEADs) is not committing: for a fixed (nonce, AAD, ciphertext, tag), multiple keys can pass authentication, each yielding a different plaintext (Grubbs–Lu–Ristenpart, "Message Franking via Committing Authenticated Encryption"; Dodis–Grubbs–Ristenpart–Woodage, "Fast Message Franking: From Invisible Salamanders to Encryptment"; practical exploitation in Albertini et al., "How to Abuse and Fix Authenticated Encryption Without Key Commitment"). In a reporting system this is fatal: a revealed key that "successfully decrypts" proves nothing about what the community actually read.

**Why the commitment closes it for this composition.** The v2 design pins every input of the deterministic function AES-GCM-Decrypt(K, N, AAD, CT):

- **K** is pinned by `keyCommitment`: exhibiting two distinct keys that both satisfy one pinned 32-byte HKDF-SHA256 commitment is a collision (or, against an honest post, a second preimage) on the commitment derivation.
- **N, AAD, CT** are pinned by content addressing: they are bytes of the `lens_cipher` attribute inside a specific metadata revision, referenced from an author-signed Lens post, and the report additionally pins `metadataHash = keccak256(attribute bytes)` and the revision id. Presenting different ciphertext material to different verifiers requires a keccak256 collision or a different revision (which verification would reject).
- AES-GCM decryption is **deterministic** in (K, N, AAD, CT).

Pinned key + pinned ciphertext material + deterministic decryption ⇒ at most one plaintext vector per (envelope, revision).

**RFC 9771 framing — stated precisely.** In the terminology of RFC 9771 ("Properties of AEAD Algorithms"), this mechanism is an **external key commitment** — CMT-1-flavored in the Bellare–Hoang taxonomy the RFC references — not a committing AEAD. Full commitment in the sense of RFC 9771 §4.3.2 is claimed **only for the composition described above** (commitment + content-addressed pinning + deterministic decryption), and never for AES-GCM itself. The complete game-style argument, with the reduction to HKDF-SHA256 collision resistance, is published in the lens-cipher repository (`docs/commitment-composition-argument.md`). **Independent cryptographic review of that argument is pending; this LIP MUST NOT advance beyond Draft, and the v2 cutover MUST NOT be declared final, until that review completes.** If review rejects the argument, the fallback is a suite revision with per-field CTX committing tags.

**Cryptographic assumptions.** Binding rests on SHA-256 collision and second-preimage resistance (hence collision resistance of the HKDF-SHA256 commitment derivation) and on keccak-256 collision resistance (attribute pinning, JCS hashes, EIP-712). Confidentiality of everything *not* revealed rests on HMAC-SHA256 as a PRF: revealing a post key leaks nothing about the epoch key or about sibling post keys (the derivation is one-way), and the published commitment leaks nothing useful about the post key.

**Assumption conservatism.** On the published robustness ordering of quantum-safe assumptions — hashes above plain LWE, plain LWE above HPLS-style leakage assumptions, those above evasive/all-product LWE (Buterin, obfuscation parts I–II, cited in Rationale) — this standard's entire trust base, hash collision resistance plus a standard committing-AEAD composition in the sense of RFC 9771, sits at the most conservative deployable point of the spectrum. That is the deployability argument for this design: it buys verifiability without betting on young lattice assumptions, and any future replacement mechanism resting on such assumptions MUST justify that trade explicitly rather than inherit this standard's claims.

**Reveal-scope griefing bounds.** Reporting grants no new capability: a reporter can only reveal what they could already decrypt, so the worst-case griefing by a malicious reporter is disclosure of one post (all fields; all revisions of that post, which share the post key) to the holders of the report envelope. Confidential distribution to moderators (§2) bounds that audience. A fabricated report with a wrong key fails the commitment check and reveals nothing. Signed frivolous reports carry attribution; anonymous reports cannot be anchored on-chain in v1.

**Transparency log limits.** The log guarantees are exactly those in §4: tamper-evident after inclusion; omission-evident only for dual-submitted receipts; equivocation detectable via STH gossip once ≥ 2 witnesses exist. A single-log deployment proves nothing about completeness of the receipt set; requesters who want omission evidence MUST dual-submit. No stronger property may be claimed for v1.

**Claim discipline.** This standard's deliberately weakened claim vocabulary — "tamper-evident after inclusion; omission-evident only for dual-submitted receipts" (§4), and the pending-review status of the commitment composition (above) — follows the documented failure taxonomy of verification claims: partial verification, missing properties, wrong specifications, and false claims silently accepted by tooling (Kobeissi, Cryptology ePrint Archive 2026/192; Buterin, "A shallow dive into formal verification," https://vitalik.eth.limo/general/2026/05/18/fv.html). Accordingly, implementations and documentation MUST NOT describe this standard or its implementations as "formally verified" or "proven secure"; every claim MUST be scoped to the specific property, mechanism, and conditions stated here.

**Verifiable requires verifiers.** Every "verifiable" and "-evident" property above is conditional on independent parties actually running the checks; evidence nobody examines detects nothing. The intended verifier story is: requesters dual-submit receipts (§4); at least two independent witnesses gossip STHs (§4); and a public verifier tool implements report verification (§2), receipt verification (§4), inclusion/consistency-proof checking (§4), and the registry/timelock check (§5). Deployments SHOULD operate or recruit ≥ 2 independent witnesses and SHOULD publish and maintain such a verifier tool. Absent these, the guarantees degrade — honestly, but materially — to "auditable by the operator": the evidence trail exists, but only the operator is positioned to have checked it.

**Verified process, not verified judgment.** This standard makes the moderation *process* cryptographically verifiable: key commitments, the four-step report check, exact-byte operator receipts, and log inclusion/consistency. It does not — and cannot — verify moderation *judgment*. Whether a plaintext violates the cited clause is a comparison against human intent, and no proof system can ingest intent; the limit is permanent, not an artifact of current tooling (Buterin, https://vitalik.eth.limo/general/2026/05/18/fv.html). §2 step 4 therefore terminates in a human verdict by construction, and any claim that this standard "verifies moderation decisions" is an overclaim prohibited by the claim-discipline rule above.

**Revision availability (fail closed).** Verification requires fetching the exact pinned metadata revision. If the revision has been garbage-collected or is otherwise unavailable, verification fails closed: the report becomes unverifiable, never falsely verifiable. Moderators SHOULD verify reports promptly, and MAY pin reported revisions (ciphertext only) for the duration of a case.

**Operator and governance surface.** Receipts make share denials attributable and log-includable, closing the "silent deny" gap. The timelock requirement (§5) bounds governance capture of the operator set: any registry mutation is publicly visible at least 48 hours before effect, and the arrangement is verifiable by anyone via `owner()` and `getMinDelay()`. Monitoring SHOULD alert on any deviation.

**Implementation pitfalls.** Commitment comparisons MUST be constant-time. Validation (version, suite, commitment) MUST precede any decryption. Signed operator payloads MUST be verified against the transmitted bytes, never a re-serialization. AEAD nonces MUST be unique per field under a post key. All hashed/signed JSON MUST use integer numbers only, keeping JCS serialization exact. EIP-712 domain separation (name, version, chainId) prevents cross-chain and cross-protocol replay; replaying an unchanged signed report is idempotent by content (same `envelopeHash`).

## Copyright

Copyright and related rights waived via CC0.
