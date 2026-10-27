"""Every numeric threshold, one named constant each (spec §6.9).

Changing a value needs, in the same PR: the spec updated, a test pinning the new behaviour, and
a Decisions-log entry. Values marked _(initial)_ in the spec are to be calibrated on the first
real week.
"""

# ---- §6.1 coverage & exclusions ---------------------------------------------------------------
COVERED_MIN_HEARTBEATS = 3  # heartbeats needed in a minute for it to count as covered
GAP_MS = 30_000  # no heartbeat for longer than this = a gap ("no data", never "outage")
NQ_EXCLUSION_MARGIN_MS = 30_000  # minutes overlapping a successful nq run ± this are excluded
LOCAL_LOAD_MBPS = 20.0  # _(initial)_ the Mac's own rx or tx above this excludes the minute
WINDOW_COVERED_SHARE = 0.5  # a window is covered if ≥ this share of its minutes are covered

# Gateway blocked (Local Network privacy): ≥ N consecutive minutes with every gateway ping lost
# while more than this share of downstream targets lost fewer than DOWNSTREAM_OK_MAX_LOST.
BLOCKED_MIN_MINUTES = 10
BLOCKED_DOWNSTREAM_SHARE = 0.5
DOWNSTREAM_OK_MAX_LOST = 2  # "had < 2 lost"

# Target unresponsive: > this loss share across its first N rolled-up minutes of an IP epoch,
# while the gateway lost fewer than UNRESPONSIVE_GATEWAY_MAX_LOST pings in those minutes.
UNRESPONSIVE_FIRST_MINUTES = 10
UNRESPONSIVE_LOSS_SHARE = 0.5
UNRESPONSIVE_GATEWAY_MAX_LOST = 2
