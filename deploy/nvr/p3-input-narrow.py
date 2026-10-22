"""P3: narrow inet myfw's input chain. Run ONCE; kept as the record.

    python3 -I p3-input-narrow.py /etc/nftables.conf /tmp/candidate.conf

Writes a candidate rather than editing in place, so the result can be
diffed and loaded in a throwaway netns before it goes near /etc. That
sequence is not ceremony: `nft -c -f` proves a file parses, not what it
destroys, and this file has an outage in its history.

It replaces three rules that named no interface -- `tcp dport
{22,8971}`, `udp dport {22,123,8971}` and a global `ip protocol icmp
accept` -- so every camera VLAN could reach this host's ssh. It matches
on the exact rule text and asserts it found them, so a second run
against an already-narrowed config fails loudly instead of silently
doing nothing.

Note it tracks which chain it is in: `input` and `output` both contain
an identically worded `ct state established,related accept`, and a
first-match edit lands in the wrong one, where it looks right and does
nothing.
"""
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines(keepends=True)

NEW = [
 '\t\t# P3 (2026-10-22): the three rules below replaced a blanket\n',
 '\t\t# `tcp dport { 22, 8971 }`, `udp dport { 22, 123, 8971 }` and\n',
 '\t\t# `ip protocol icmp accept`, none of which named an interface --\n',
 '\t\t# so every camera VLAN could reach this host\'s ssh. The 24h\n',
 '\t\t# observation window recorded ZERO camera-to-NVR traffic outside\n',
 '\t\t# ntp/wireguard/icmp, and zero management from off-LAN.\n',
 '\t\t#\n',
 '\t\t# udp/22 and udp/8971 are gone because nothing listens on them,\n',
 '\t\t# and tcp/8971 is gone because it was never the Frigate UI path:\n',
 '\t\t# that port is DNAT\'d to the container, so it is handled in the\n',
 '\t\t# forward chain of inet gsfw_enforce, restricted to the same one\n',
 '\t\t# address.\n',
 '\t\tiifname "enp4s0" ip saddr 88.255.1.221 tcp dport 22 accept\n',
 '\t\tiifname "enp4s0" ip saddr 88.255.1.221 ip protocol icmp accept\n',
 '\t\t# Cameras: time, tunnel, ping. Nothing else, per the window.\n',
 '\t\tiifname "enp6s0.*" udp dport 123 accept\n',
 '\t\tiifname "enp6s0.*" udp dport 51820 accept\n',
 '\t\tiifname "enp6s0.*" ip protocol icmp accept\n',
 '\t\t# LAN time service: kept, because nothing here knows whether a\n',
 '\t\t# LAN host depends on it. in_ntp_lan in the observe table is\n',
 '\t\t# measuring that now; narrow it once there is evidence.\n',
 '\t\tiifname "enp4s0" udp dport 123 accept\n',
]
DROP = ('tcp dport { 22, 8971 } accept',
        'udp dport { 22, 123, 8971 } accept',
        'ip protocol icmp accept')

out, chain, done = [], None, False
for ln in lines:
    if "chain " in ln and "{" in ln:
        chain = ln.split("chain", 1)[1].split("{")[0].strip()
    if chain == "input" and any(ln.strip() == d for d in DROP):
        if not done:
            out.extend(NEW)
            done = True
        continue                      # drop the old blanket rule
    out.append(ln)
assert done, "did not find the input rules to replace"
open(dst, "w").write("".join(out))
print("  input chain rewritten")
