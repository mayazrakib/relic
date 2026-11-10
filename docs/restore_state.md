## 1. Restore Intent Journal

The restore journal durably records an immutable restore request and snapshots the linked sealed manifest and payload identities before filesystem work. It reserves each endpoint and target name until abandonment, including after publication. Prepared, staging, and verified intents are available through bounded recovery pages.

A caller records the staging identity, verifies the staged tree, publishes it without replacement, and records publication with the same identity. Abandonment is limited to prepared and staging intents and preserves any staging identity. The journal records caller-supplied evidence; it does not inspect files, verify cryptography, or perform filesystem operations.
