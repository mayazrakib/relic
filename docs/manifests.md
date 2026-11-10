## 1. Manifest Validation

The manifest module validates a stream of typed header and entry records and computes the canonical framed digest. Entries must arrive in source and decoded-component order. Validation rejects duplicate identities, mixed path encodings, unsafe components, unsorted or duplicate metadata, invalid content fields, and oversized frames. File content is verified separately through a reader using a 64 KiB buffer.

## 2. Temporary Ordering Spool

The manifest spool stores individually validated frames in a new SQLite file and orders them by source and decoded path bytes. It bounds the entry count, frame size, and database pages, and iterates records without loading the tree into memory. The SQLite journal is disabled because this spool is disposable intermediate data and is not durable publication authority. A database write failure poisons the instance; callers must discard it and rebuild. The caller must create the spool in a private directory, remove it after use, and verify the referenced file content independently.

This component does not enumerate files, acquire source snapshots, or capture metadata. The separate [source scanner](source_scan.md) produces a limited best-effort filesystem inventory. Callers must associate verified file bytes with their corresponding entries and retain the validated manifest through publication. Neither component is durable publication authority, and the spool is not yet encrypted.
