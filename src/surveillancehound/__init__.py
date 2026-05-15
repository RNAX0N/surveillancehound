"""SurveillanceHound — always-running NVR / IP-camera network monitor.

A standalone daemon that watches the wire (live on an NVR / firewall / switch
host via tcpdump, or offline replaying a saved capture) and flags activity
that the surveillance threat model cares about: bulk transfers *toward* a
camera (model-weight / firmware push), suspicious long-lived sessions from
cameras to public hosts (control channels), telemetry to non-manufacturer
hosts, brand-new devices on the camera segment, brand-new peers for a known
camera, and cameras that have gone silent.

The daemon writes a SQLite case record of every flow + alert, and dispatches
notifications through any combination of operator-selected channels (stdout,
plain log, JSON-lines, webhook). The pcap parser is pure-Python; the only
hard runtime dependency for live capture is `tcpdump` on PATH.

Originally extracted from the footageanalyzer project — the offline pcap
forensic surface there has moved here; SurveillanceHound is now its own app.
"""
