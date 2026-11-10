# Physical Root Registry

## 1. Purpose

Schema thirteen records the physical roots controlled by one node database. New local staging, gateway, restore, and worker executable admissions compare their roots with this registry before creating owned files or launching effects. This implements a restricted Linux conflict domain, rather than a distributed storage authority.

## 2. Physical Evidence

The controller pins each root and records its device, inode, mount identity, ancestor chain, boot, mount namespace, filesystem, and translated mount origin. Observations use the kernel descriptor path rather than the caller's cached spelling. Mount information is bounded to 512 KiB and 4,096 records; each encoded observation is bounded to 256 KiB. Only the local ext4, Btrfs, and XFS profile is admitted.

Registry operations admit at most eight claims, read eight rows per page, and inspect at most 4,096 roots with a five-second cooperative deadline. A private pinned coordinator lock excludes concurrent registry updates. Filesystem observations occur outside the short SQLite write transaction; generation and coordinator identity are compared again before committing. Unknown layouts, changed identities, unsupported filesystems, and ambiguous mount information fail closed.

Read-only roots may overlap each other. A staging root may be shared exactly by typed staging stores in the same node authority. Writable gateway and restore roots may not overlap state, executable, source, or staging roots. Existing non-source owners cannot silently relocate their roots. Source owners may register several roots.

## 3. Admission and Recovery

Fresh producer admission reobserves the complete registered root set. Existing worker access checks only the worker's admitted physical root, reading registry metadata without opening other roots. Staging workers may access a physically proven descendant of their admitted staging root. These checks require an open inventory gate and immutable root registrations.

Verification after a lost response uses the existing destination, state, and executable registrations. Private native verification also requires the exact persistent staging reservation. It does not register new roots or require source staging files to survive. This separation preserves recovery after source removal without granting fresh publication or staging admission through the recovery path. Recorded worker exclusion, owner locks, bounded attempts, authenticated repository verification, and correlated receipts remain required.

## 4. Worker State Access

Contained workers receive read access to the private SQLite database and its existing WAL and shared-memory sidecars. They do not receive recursive access to the state directory. The parent rejects links, changed canonical directories, unexpected ownership, and permissive file modes before granting these paths. The state-directory descriptor used for identity inspection has metadata-only access. Landlock file rules retain read-only access and do not grant directory traversal rights through a recursive state rule.

The worker still reads node database metadata. Per-operation metadata snapshots and replacement exclusion during capability setup remain separate qualification concerns.

## 5. Inventory and Limits

Migration closes the inventory gate when prior owned records exist. Trusted inventory can seed roots before completing journal coverage. This checks registered references, not the complete physical object census. Unknown files and outstanding quota charges remain retained.

The registry assumes one canonical node database, protected root ancestors, and exclusion of external writers and namespace mutations across admission and effects. It does not fence another database, host, or remote request. Kernel observations are not authenticated authorization proof. Raw journal mutation APIs remain trusted controller interfaces.

Legitimate reboot, mount-namespace replacement, root relocation, source-view lifecycle, complete object census, and cleanup need durable reconciliation before production enablement. This checkpoint deliberately refuses automatic adoption of changed physical identities. Destination growth reservations, shared-storage fencing, Windows and macOS equivalents, and all remaining release gates remain required.
