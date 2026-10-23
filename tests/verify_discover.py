#!/usr/bin/env python3
"""Verify the device classifier never mistakes the sensor for a camera.

This exists because of a live false-alarm storm. The NVR's VLAN gateway
addresses (117.111.10N.1) carry Frigate's MASQUERADED RTSP, so once the
explicit `nvr_ips` entries for them were removed, the port heuristic saw
117.111.105.1 connecting to a camera's tcp/554 and concluded the gateway
was a camera. Camera-to-camera traffic is alerted as "unusual for most
deployments; investigate" — so the recorder doing its job generated a
`camera_to_camera` alert every minute, and the gateway was liveness
tracked and reported "down" by the very host that owns it.

Run: PYTHONPATH=src python3 tests/verify_discover.py
"""
from __future__ import annotations

import socket
import sys

from surveillancehound.config import load_from_dict
from surveillancehound.discover import DeviceClassifier

FAILURES: list[str] = []
CHECKS = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}" + (f" — {detail}" if detail else ""))
        FAILURES.append(label)


def an_own_address() -> str:
    """An address this machine really has, other than loopback.

    Taken from the kernel rather than hardcoded, so the test is about
    the behaviour and not about one network.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        try:
            sk.connect(("192.0.2.1", 9))     # TEST-NET-1, no packet sent
            return sk.getsockname()[0]
        except OSError:
            return "127.0.0.1"


MINE = an_own_address()
THEIRS = "117.111.105.2"
GATEWAY_SHAPED = "117.111.105.1"


def classifier(**net) -> DeviceClassifier:
    cfg = load_from_dict({
        "capture": {"interface": "eth0"},
        "network": dict({"camera_ips": [THEIRS],
                         "lan_subnets": ["117.111.0.0/16"]}, **net),
    })
    return DeviceClassifier(cfg.network)


print(f"\nown-address guard (this host is {MINE})")

d = classifier()
check("an address of this host is 'other'", d.role_for(MINE) == "other",
      d.role_for(MINE))
check("a remote configured camera is still 'camera'",
      d.role_for(THEIRS) == "camera")

# Explicit config must NOT be able to override it: a configured
# own-address cannot work either, and config-check says so.
d = classifier(camera_ips=[THEIRS, MINE])
check("configuring our own address as a camera does not take",
      d.role_for(MINE) == "other", d.role_for(MINE))
d = classifier(nvr_ips=[MINE])
check("...nor as an NVR", d.role_for(MINE) == "other", d.role_for(MINE))

# A camera subnet covering our own address must not promote it either.
d = classifier(camera_subnets=["0.0.0.0/0"])
check("a camera subnet containing our address does not promote it",
      d.role_for(MINE) == "other", d.role_for(MINE))
check("...while a genuinely remote address in that subnet is a camera",
      d.role_for("203.0.113.7") == "camera")

print("\nthe regression: masqueraded RTSP from our own gateway")

d = classifier()
# What Frigate's traffic looks like after masquerade: the NVR's own
# gateway address connecting to the camera's RTSP port.
for _ in range(5):
    d.observe(MINE, THEIRS, 40000, 554)
check("our own address serving/using 554 is not promoted to camera",
      d.role_for(MINE) == "other", d.role_for(MINE))
d.observe(THEIRS, MINE, 40000, 554)
check("...not even as the destination of a camera-port connection",
      d.role_for(MINE) == "other", d.role_for(MINE))

# The NVR heuristic: a LAN device talking to >= 3 cameras. Our own
# address does that constantly (it is the recorder's masquerade
# address), and being called an NVR is what got it liveness tracked.
d = classifier(camera_ips=["117.111.101.2", "117.111.102.2",
                           "117.111.103.2", "117.111.104.2"])
for cam in ("117.111.101.2", "117.111.102.2", "117.111.103.2",
            "117.111.104.2"):
    d.observe(MINE, cam, 40000, 554)
check("talking to four cameras does not make our own address an NVR",
      d.role_for(MINE) == "other", d.role_for(MINE))

# ...but it must still work for a real NVR.
d = classifier(camera_ips=["117.111.101.2", "117.111.102.2",
                           "117.111.103.2", "117.111.104.2"])
for cam in ("117.111.101.2", "117.111.102.2", "117.111.103.2",
            "117.111.104.2"):
    d.observe("117.111.99.9", cam, 40000, 554)
check("a REMOTE host talking to four cameras is still an NVR",
      d.role_for("117.111.99.9") == "nvr", d.role_for("117.111.99.9"))

print("\nthe check is about ownership, not about address shape")

d = classifier()
check("a gateway-shaped address we do NOT own is classified normally",
      d.role_for(GATEWAY_SHAPED) in ("other", "camera"),
      d.role_for(GATEWAY_SHAPED))
check("is_own_address is False for a remote address",
      d.is_own_address(THEIRS) is False)
check("is_own_address is True for loopback", d.is_own_address("127.0.0.1"))
check("is_own_address tolerates nonsense",
      d.is_own_address("not-an-ip") is False)
check("...and an unroutable literal", d.is_own_address("203.0.113.254") is False)

# Cached, so the question is asked once per address and not per packet.
d = classifier()
d.is_own_address(MINE)
check("the answer is cached", MINE in d._own_cache)

print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
if FAILURES:
    print("\nFAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("device classifier OK")
