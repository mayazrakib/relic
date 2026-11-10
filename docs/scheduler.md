## 1. Calendar Projection

The scheduler module provides pure calendar projection and catch-up selection. It does not run a daemon, persist claims, enforce overlap, or execute scheduled jobs. Callers supply the IANA zone, its database version, a bounded local-time search interval, and result limits. They must persist claims and exclude completed identities when recalculating.

The five-field cron parser accepts numeric lists, ranges, and steps. Day of month and day of week use OR when both are restricted. The default gap policy resolves each nonexistent nominal time to the first valid local instant, and the default fold policy selects the earlier instant. Distinct nominal labels retain distinct occurrence identities even when they resolve to the same UTC instant.

Catch-up selection reports expired, policy-dropped, and capacity-dropped occurrences. Callers provide the age horizon and capacity; the specification defaults are 24 hours and ten occurrences for bounded replay. Overlap policy is represented as configuration data and needs admission, safety, and persistence enforcement by a future scheduler service.
