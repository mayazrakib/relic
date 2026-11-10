## 1. Capture Records

A capture record binds an authority, job, occurrence, capture, source view, achieved consistency, and source-selection digest. The store rejects attempts to replace that binding. A manifest digest and entry count can be frozen once and are required before binding a publication intent. The store also provides bounded pagination for captures whose manifests are not frozen.

Callers must durably bind the capture before admitting source reads and must supply a digest that identifies the actual selected-source policy. The store does not acquire or preserve the source view, validate manifest content, enforce read admission, or prove that a best-effort source remains unchanged. A replacement source view requires a distinct occurrence and capture.

Version 2 migrates version 1 databases transactionally and preserves their jobs and publication records. Migration does not invent capture records for older publication intents. Recovery can inspect those intents, but a new publication binding requires a real matching frozen capture. A future executor must reconcile legacy effects before admitting any new work; the current management daemon still rejects enabled jobs.
