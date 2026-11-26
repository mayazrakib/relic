# Destination Growth Reservations

## 1. Scope

The restricted local implementation keeps destination growth separate from staging quota and retained repository data. Schema fourteen records one immutable reservation for each gateway initialization or physical publication execution. The [qualification evidence](evidence/destination_growth.json) records the checked source and tests. Enabled production jobs and full-system acceptance remain gated.

## 2. Accounting

A reservation binds the operation kind and identity, execution ordinal, resource, pinned storage identity, observed device, receiver epoch, fence, and maximum additional bytes. Initialization has ordinal zero; publication permits the existing bounded execution ordinals. A hold is limited to 512 MiB, and the journal admits at most 10,000 reservation records. Arithmetic is checked, including persisted totals read from SQLite.

Accounting uses one conservative node-wide bucket. Every new staging or destination obligation includes all charged staging bytes and all held destination growth, regardless of device number. It then adds the greater of 512 MiB or five percent of the current target capacity, rounded up. Final retained repository bytes are not added to the 1 GiB staging limit: they reduce the target's next actual free-space sample instead.

This deliberately overcounts independent volumes. It avoids claiming that Btrfs subvolume device identities describe separate free-space pools. The observed `unix:<device>` remains an immutable root binding and an informational reporting field, not proof of capacity independence. A held maximum can also count already-written bytes again when admitting another operation; this is conservative.

## 3. Coordination and Effects

The pinned private physical-registry coordinator also serializes capacity admission and release for the node. Production controllers acquire it before sampling capacity and keep it through the short immediate journal transaction. Filesystem operations stay outside the write transaction. A second controller cannot use the same coordinator while it is held, and a replaced coordinator is rejected.

Initialization and publication record their growth hold in the same transaction that permits the mutating worker to start. A failed reservation rolls back the operation transition. The worker compares the durable hold, exact resource and root, epoch, fence, and byte bound before using repository credentials. Both staging and destination inventory gates must be open. Existing per-worker write, scratch, descriptor, memory, and runtime limits still apply.

Trusted raw journal methods remain available for fixtures and administrative composition. They do not establish filesystem proof and do not release an existing hold. The production controllers use the coupled reservation methods.

## 4. Replay and Recovery

Unknown outcomes, crashes, pending workers, and failed verification retain the full growth hold. A verified receipt or authenticated negative census releases it atomically with the qualifying journal transition, under the same coordinator. The controller first proves recorded mutating and verification scopes quiescent or revokes an unbound launch. A successful response does not grant permission to credit an unresolved old worker.

Exact staging replay acknowledges the original aggregate maximum; it does not reserve another maximum against already-reduced free space. Both inventory gates remain mandatory for writable replay. This relies on exclusive object ownership, fixed namespaces, bounded attempts, and retained output plus additional output staying inside the original charge. It does not permit duplicate parallel output or an increased bound.

Gateway recovery requires its exact pre-existing scratch charge and cannot create one. Private native recovery similarly checks its existing complete charge. Old scopes are excluded before recovery, and workers subtract retained scratch from the remaining sort budget. This allows bounded recovery to resolve a hold without re-admitting its full, partly spent data budget. Source staging files need not survive final-repository verification.

## 5. Legacy Inventory

Migration closes destination admission when unresolved initialization or publication records lack growth reservations. Trusted inventory can record conservative existing obligations while the gate is closed. It validates journal ownership and immutable bindings, preserves exact replay, and rejects changed charges. Completion requires coverage for every unresolved operation and complete staging inventory. It retains every charge and does not infer deletion, quiescence, or successful publication.

These journal APIs require independently established physical identity, a valid conservative bound on the old worker, and the common coordinator. They are not an automatic filesystem or process census. Unrecorded scopes and changed physical identities still require the existing trusted exclusion and startup reconciliation procedures.

## 6. Capacity Domains

Btrfs mixes the subvolume root ID into `f_fsid`, so generic `fstatvfs().f_fsid` cannot identify its common pool either. A future partitioned capacity model needs verified filesystem evidence, including the full Btrfs filesystem ID from `BTRFS_IOC_FS_INFO` on a suitable pinned descriptor. See [Btrfs statfs](https://github.com/torvalds/linux/blob/v6.12/fs/btrfs/super.c), [filesystem information ioctl](https://github.com/torvalds/linux/blob/v6.12/fs/btrfs/ioctl.c), and [glibc statvfs conversion](https://github.com/bminor/glibc/blob/glibc-2.40/sysdeps/unix/sysv/linux/internal_statvfs.c).

Real mounted subvolume, alias, project-quota, and legacy-root mapping qualification remains open. Arbitrary thin backing pools and external writers are outside the current capacity guarantee. The conservative bucket does not prove provisioned physical capacity beneath a filesystem's reported free space.

## 7. Remaining Limits

The profile assumes one canonical node database, protected roots, and cooperating writers whose aggregate bounds are enforced. Capacity and filesystem identity calls can block; isolating and bounding these metadata operations remains a production gate. Observed process tests and synchronization calls do not establish power-loss durability.

Complete startup census, source-view lifetime, safe cleanup and quota credits, record retirement, reboot and namespace rebasing, stable chunking, selected-platform containment, remote storage, and all later full-system gates remain incomplete. This milestone does not enable production jobs or complete a full plan phase.
