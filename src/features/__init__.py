"""
features — flow records -> device-window feature vectors.

    windowing.py    assign flow records to (device, 5-minute bucket) groups
    derive.py       compute the 16 features from one group's flows

UNIT OF ANALYSIS: one output row = ONE DEVICE over ONE 5-MINUTE WINDOW.

This is the single easiest thing to get wrong in the project, and it has been
gotten wrong before. Zeek and CICFlowMeter both emit one record per FLOW. Five
of the sixteen features — distinct_dst_ports, flow_fanout, scan_rate,
login_burst_count, beacon_jitter — are undefined for a single flow:
distinct_dst_ports is 1 by definition, and beacon_jitter needs at least three
timestamps. A per-flow pipeline therefore produces columns that look populated
and mean nothing.

The aggregation step in windowing.py is not an optimisation. It is what makes
the feature set well-defined.
"""
