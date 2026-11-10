## 1. Artifact Journal

A prepared artifact records an immutable capture, storage endpoint and identity, generated relative filename, and opaque key reference before the caller performs storage effects. Pending records can be listed in bounded pages. One capture can have one artifact intent, including an abandoned intent.

Sealing atomically records the ciphertext digest and length, freezes the manifest digest and entry count, and links the capture to the artifact. A conflicting retry fails. Abandonment applies only to a prepared artifact and prevents reuse of that capture's artifact slot.

The journal records caller-supplied evidence. It does not write, synchronize, authenticate, or inspect the artifact, obtain keys, or establish storage durability. The caller must complete those checks before sealing and reconcile prepared intents after interruption.
