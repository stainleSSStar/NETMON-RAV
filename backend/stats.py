"""Uptime statistics computed from the events table.

The events table (up/down transitions) is the single source of truth; this
module turns it into availability percentages, per-bucket uptime series for
charts, and downtime period lists.
"""
import time

from . import db


def _state_segments(host_id: int, since_ts: float):
    """Return [(start, end, up_bool)] covering [since_ts, now] with known state."""
    now = time.time()
    events = db.state_events_since(host_id, since_ts)
    prior = db.last_state_event_before(host_id, since_ts)
    segments = []
    if prior is not None:
        current = prior["type"] == "up"
        cursor = max(since_ts, prior["ts"])
    elif events:
        # No state before the window, but the first transition inside it tells
        # us the host's state from that moment on.
        current = events[0]["type"] == "up"
        cursor = events[0]["ts"]
        events = events[1:]
    else:
        return []
    for event in events:
        ts = event["ts"]
        if ts <= cursor:  # same-instant events: the last one wins
            current = event["type"] == "up"
            continue
        segments.append((cursor, min(ts, now), current))
        current = event["type"] == "up"
        cursor = ts
        if cursor >= now:
            break
    if cursor < now:
        segments.append((cursor, now, current))
    return _merge_segments(segments)


def _merge_segments(segments):
    """Collapse touching segments that share the same state.

    Duplicate or imported state events would otherwise split one continuous
    outage into several rows in the downtime table.
    """
    merged = []
    for start, end, is_up in segments:
        if merged:
            prev_start, prev_end, prev_up = merged[-1]
            if prev_up == is_up and start <= prev_end:
                merged[-1] = (prev_start, max(prev_end, end), prev_up)
                continue
        merged.append((start, end, is_up))
    return merged


def compute_availability(host_id: int, window_seconds: float):
    since = time.time() - window_seconds
    segments = _state_segments(host_id, since)
    up = sum(end - start for start, end, is_up in segments if is_up)
    down = sum(end - start for start, end, is_up in segments if not is_up)
    total = up + down
    pct = round(up / total * 100, 3) if total > 0 else None
    periods = [
        {"start": start, "end": end, "seconds": round(end - start)}
        for start, end, is_up in segments
        if not is_up
    ]
    # Chronological order: the UI renders From | To | Duration, so an
    # unspecified order read as a timeline but was not one.
    periods.sort(key=lambda p: p["start"])
    return {
        "availability_pct": pct,
        "up_seconds": round(up),
        "down_seconds": round(down),
        "downtime_periods": periods[:20],
    }


def uptime_buckets(host_id: int, hours: float):
    since = time.time() - hours * 3600
    now = time.time()
    if hours <= 24:
        bucket = 300
    elif hours <= 168:
        bucket = 3600
    else:
        bucket = 86400
    segments = _state_segments(host_id, since)
    buckets = []
    start = since
    while start < now:
        end = min(start + bucket, now)
        known = 0.0
        up = 0.0
        for seg_start, seg_end, is_up in segments:
            overlap_start = max(seg_start, start)
            overlap_end = min(seg_end, end)
            if overlap_end > overlap_start:
                known += overlap_end - overlap_start
                if is_up:
                    up += overlap_end - overlap_start
        # Percentage of the time we actually know about, not of the whole
        # bucket width: the leading bucket of a newly added host is mostly
        # unknown, and counting that unknown as downtime drew a false red bar
        # while the summary on the same page said 100%.
        pct = round(up / known * 100, 2) if known > 0 else None
        buckets.append({"t": start, "up_pct": pct})
        start = end
    return {
        "bucket_seconds": bucket,
        "buckets": buckets,
        "availability": compute_availability(host_id, hours * 3600),
    }
