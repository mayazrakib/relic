## 1. Scope

The preflight planner accepts a fully normalized job and explicitly supplied evidence for every source and destination. It verifies definition and endpoint revisions, node and endpoint grants, revocation, supported methods, requested metadata, source consistency, destination verification, resource budgets, secret-reference resolution, and the spool free-space reserve. It rejects overlapping source and destination scopes and overlapping destination scopes. Scope domains and path components are evidence from the endpoint resolver; the planner does not discover aliases, mount identities, symlinks, object-store ownership, or physical overlap itself.

For each destination it produces the specified effective-policy binding and digest, with source bindings and secret references sorted. The plan retains the supplied job and evidence for review, along with selected replica snapshot identities. This API has no filesystem, network, or publication effects and does not reserve resources. The caller must obtain trustworthy, current endpoint and authorization evidence, hold actual resource reservations, resolve credentials without exposing secret values, and revalidate material state before admission. Latest replica selections require an exact snapshot identity in the evidence.

This is a preflight foundation, not proof that an adapter can execute or that a backup will be recoverable. Capability and scope evidence are assertions supplied by the caller, not probes. The planner has no authority to authorize a destructive action or to create a durable approved plan. Published policy digests do not include the separate endpoint evidence; callers must durably bind the applicable evidence and revisions to the later execution record.

## 2. Resource and Scope Evidence

The planner intersects requested resources with the selected low or balanced class and the supplied hard cap. Each endpoint must provide a nonzero minimum memory requirement, a minimum spool requirement, and evidence that it can enforce the budget. Throughput profiles are rejected until their measured, explicitly configured limits are implemented. Availability and budget evidence must reflect the node that will execute the plan.

The endpoint resolver must normalize paths and conflict domains according to the backend, including Windows separators, case rules, aliases, volume identity, and reparse points. The planner compares supplied components as exact strings and does not infer Windows path semantics.
