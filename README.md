# Lens Improvement Proposals (LIPs)

This fork tracks Lens Improvement Proposals.

## Proposals in this fork

`main` contains [LIP-16](./LIPs/lip-16.md).
The title in that file is "LIP-16 Standardizing Fees for Collecting NFTs and Other Paid Actions".
The LIP-16 status is Draft.
Most of the proposal body is still inside HTML comments.

Branch `lip-6-encrypted-reporting` contains `LIPs/lip-6.md`.
LIP-6 is on that branch.
The title in that file is "Verifiable Reporting for Encrypted Publications".
The LIP-6 status is Draft.
LIP-6 describes a committing encryption envelope, a verifiable report format, and auditable operator receipts for end-to-end encrypted Lens publications.
A member who can already read an abusive encrypted post can report that post to a moderator.
The report contains proof that the revealed text is the content of that post.
The report reveals that one post.
The proposal defines the `lens_cipher` v2 envelope.
The envelope binds each encrypted post to a key commitment.
The report format includes a deterministic verification algorithm.
The proposal defines signed operator receipts.
The proposal requires a timelock to own the operator registry.

## Contributing

These proposal types are in use:

- Protocol
- Lens Ecosystem Standard
- Lens Metadata Standard
- Lens Open Algorithm Standard

Each type can go through the LIP process.
Lens Open Algorithm Standards also have a separate contribution flow.
You can still open an LIP to change a Lens Open Algorithm Standard.

The template is [LIPs/lip-template.md](./LIPs/lip-template.md).
The template follows the Ethereum Improvement Proposal format.

Supported standards are listed in [supported-standards/README.md](./supported-standards/README.md).
The `lens-open-algorithm-standards` folder holds the Lens Open Algorithm Standards.
