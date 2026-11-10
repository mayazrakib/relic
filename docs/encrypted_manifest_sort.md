## 1. Encrypted Manifest Sorting

The sorter creates bounded in-memory sorted runs and writes each run through the authenticated encrypted spool format. Names contain random identifiers and no source paths. Unix run files are created relative to an open, private, owner-controlled directory, with exclusive creation and no symlink following. Drop removes the run names owned by the sorter. Windows is unsupported until equivalent handle-relative protection is available.

The sorter permits at most four runs and merges them directly into the visitor without a merge file. Its limits cap entries, frame and chunk sizes, fan-in, accounted memory, and the aggregate encrypted run bytes. Accounted memory is capped at 8 MiB and frames at 256 KiB. The caller controls the private directory and must handle cleanup after process termination. The limits exclude visitor-owned allocations and unrelated process memory.

The visitor receives provisional entries while encrypted runs are read. It must not commit external effects until iteration returns successfully, because a later frame, final authentication tag, duplicate, or ordering error can invalidate the entire result. The sorter does not verify file content, provide source consistency, or publish a manifest.
