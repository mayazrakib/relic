## 1. Payload Artifact Journal

A prepared payload artifact binds a capture to an immutable storage endpoint, storage identity, generated relative name, and opaque key reference before storage effects. One capture has one payload intent, including an abandoned intent. Pending intents can be listed in bounded pages.

Sealing atomically records caller-supplied ciphertext and manifest measurements and links the payload to its capture. The capture must already link a sealed manifest artifact with matching digest and entry count. Identical seal retries return the existing result; changed measurements fail. A prepared intent can be abandoned, after which its capture cannot acquire another payload intent.

The journal does not read, authenticate, write, or synchronize artifacts. Callers must verify the encrypted payload and storage durability before sealing and reconcile prepared effects after interruption.
