## 1. Bounded Multipass Ordering

The Unix encrypted manifest sorter spills bounded sorted chunks into authenticated encrypted runs. Runs at the same level compact in groups of two to four. Each such merge raises the level, so growing captures do not repeatedly rewrite a single ever-growing prefix after every chunk. Before the final visit, the smallest available runs merge until no more than the configured fan-in remain.

The run catalogue permits up to 128 resident input files, plus one temporary merge output. `max_runs` bounds that catalogue, not the total number of runs created over the sort's lifetime. Large fixtures configure 64 slots with fan-in four. A smaller catalogue can reject a capture whose occupied levels exceed its capacity. Fan-in is between two and four, chunk sizes and entry counts are finite, and the declared memory envelope is at most 8 MiB. None of these limits increases because the input grows.

Run IDs are monotonic for one sorter lifetime and form part of each run's authenticated context. Merging opens at most four input readers and one output writer. It preserves the logical manifest's decoded byte ordering and validates strict ordering, duplicate absence, canonical frames, declared row/byte counts, and every input's final authentication. The output's final authenticated record is withheld until all inputs pass. Final visitors remain provisional until the complete visit returns its validated logical manifest digest.

## 2. Disk, Memory, and Failure Accounting

The ciphertext quota includes all retained inputs and the complete output reservation before a merge creates its output. It is a peak live quota, not merely a final-file-size check. Inputs retire only after the output is finalized. The directory catalogue, merge heads, chunk storage, parser/validation scratch, reusable encryption buffers, and one output are included in the declared memory estimate. Path sort keys reserve their encoded capacity once, avoiding repeated reallocations and keeping their storage inside the estimate. Keys and frame buffers are zeroized on release.

`get_usage` reports accepted entries, resident runs, allocated run IDs, completed merges, current ciphertext reservation, peak reservation, and cumulative output reservations. The counters are internal reservation evidence, not process RSS or throughput measurements. The 257-entry fixture checks exact order and digest against an independent manifest validator and bounds cumulative reservations to eight times separately encrypted input runs, guarding against repeated prefix rewriting. It also checks live files and quota bounds throughout ingestion and verifies repeatable final visits.

Every failed append, merge, callback, or read poisons the sorter. A caller cannot ignore a rejected entry and then finalize a valid-looking prefix. Cancellation and deadline checks run between bounded operations. Sort errors expose fixed display categories rather than private I/O details.

## 3. Ownership and Qualification Limits

Runs use private exclusive creation, no-follow nonblocking reads, and registered device/inode identity. Reads reject unexpected file type, owner, mode, link count, length, or identity. Retirement and best-effort destructor cleanup unlink only a matching registered inode. A replaced path and unrelated files remain untouched. Corruption, truncation, invalid final tags, cross-tier duplicates, quota exhaustion, and callback failures cannot produce a successful final visit.

This remains a disposable encrypted ordering component. It does not provide a durable run journal, process-crash cleanup, Windows ordering, key-provider lifecycle, or production source/archive authority. Aggregate resource admission and filesystem namespace exclusivity remain caller responsibilities. No standalone crypto review or sustained performance qualification is established by these tests.
