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

# ---- §6.2 baseline ------------------------------------------------------------------------------
BASELINE_LOOKBACK_DAYS = 7  # look-back ending at the end of the day being judged
BASELINE_HOUR_MIN_COVERED = 45  # covered minutes (with a row for the target) for a candidate hour
BASELINE_MIN_HOURS = 4  # fewer chosen hours → no baseline that day
BASELINE_FALLBACK_SHARE = 0.25  # quiet window too thin → this share of the calmest candidate hours

# ---- §6.3 bad minute _(initial)_ ------------------------------------------------------------------
BAD_LOST_PINGS = 2  # ≥ this many lost pings in a minute (one isolated loss is background noise)
EDGE_LOST_MARGIN = 2  # ISP edge: lost ≥ its baseline-hours median lost per minute + this
BAD_P95_MARGIN_MS = 40.0  # p95 > baseline + this
BAD_JITTER_MARGIN_MS = 15.0  # jitter > baseline jitter + this

# ---- §6.4 attribution ----------------------------------------------------------------------------
MIN_DOWNSTREAM = 3  # |D| below this → inconclusive
MAJORITY_MIN_BAD = 2  # "majority of X bad" also needs at least this many bad
VIDEO_PATH_MIN_CDNS = 2  # ≥ this many CDNs bad at once → video_path
VIDEO_PATH_STREAK = 3  # …or the same CDN bad in this and the previous 2 covered minutes
WEAK_RSSI_DBM = -70  # WiFi context: weak_signal below this
LOW_SNR_DB = 20  # WiFi context: low_snr below this
AF6_MIN_SHARE = 0.5  # verdict uses af 6 if it had |D| ≥ 3 in ≥ this share of covered minutes
