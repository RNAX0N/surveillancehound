# SurveillanceHound → Wazuh integration

Wazuh ingests Hound alerts via either path; pick whichever fits your topology.

| | **A: jsonlines + agent (recommended)** | **B: syslog → manager** |
|---|---|---|
| Where Hound runs | Same host as a Wazuh agent | Anywhere reachable from the manager |
| Hound config | `[[notify]] type = "jsonlines"` | `[[notify]] type = "syslog"` |
| Wazuh config | `<localfile>` snippet + rules file | Decoder file + rules file |
| Field extraction | Built-in `json` decoder | Custom RFC 5424 decoder we ship |
| Network round trip | None (local file) | UDP 514 / TCP 6514 |
| MITRE tagging | Yes (rules file) | Yes (rules file) |

Both paths use the same rules file; only the field-extraction layer differs.

## Files

```
deploy/wazuh/
├── hound-rules.xml         → /var/ossec/etc/rules/local_hound_rules.xml
├── hound-decoder.xml       → /var/ossec/etc/decoders/local_hound_decoder.xml   (Path B only)
├── localfile-snippet.xml   → inside <ossec_config> in /var/ossec/etc/ossec.conf (Path A only)
└── README.md               → you are here
```

The rules ship MITRE ATT&CK tags (T1190 / T1071 / T1041 / T1095 / T1542 /
T1499 / T1078) so Wazuh's MITRE dashboard lights up cleanly when Hound
fires. Correlation rules also flag *sustained* attack patterns (3+
high-severity events on the same camera in 5 minutes) at level 13 so
on-call gets paged.

## Path A — jsonlines + Wazuh agent (recommended)

On the host running Hound (which also runs `wazuh-agent`):

```bash
# 1) tell Hound to also write a jsonlines log (add to your hound.toml)
cat >> /etc/hound.toml <<'EOF'

[[notify]]
type      = "jsonlines"
path      = "/var/log/hound/hound.alerts.jsonl"
level     = "low"
max_bytes = 10485760
keep      = 5
EOF
systemctl restart hound

# 2) tell the Wazuh agent to read it as JSON
sudo cat deploy/wazuh/localfile-snippet.xml      # preview what we're adding
# manually paste the <localfile> stanza inside <ossec_config>...</ossec_config>
# in /var/ossec/etc/ossec.conf, OR:
sudo python3 -c '
import re, pathlib
cfg = pathlib.Path("/var/ossec/etc/ossec.conf")
snippet = pathlib.Path("deploy/wazuh/localfile-snippet.xml").read_text()
# strip the comment block from the snippet for cleanliness
snippet = re.sub(r"<!--.*?-->", "", snippet, flags=re.DOTALL).strip()
text = cfg.read_text()
if "/var/log/hound/hound.alerts.jsonl" in text:
    print("already installed"); raise SystemExit(0)
text = text.replace("</ossec_config>", snippet + "\n</ossec_config>")
cfg.write_text(text)
print("installed")
'
sudo systemctl restart wazuh-agent

# 3) on the Wazuh manager — install the rules
scp deploy/wazuh/hound-rules.xml wazuh-mgr:/tmp/
ssh wazuh-mgr 'sudo cp /tmp/hound-rules.xml /var/ossec/etc/rules/local_hound_rules.xml \
            && sudo chown wazuh:wazuh /var/ossec/etc/rules/local_hound_rules.xml \
            && sudo systemctl restart wazuh-manager'
```

Fire a test alert (or wait for a real one). It should land in Wazuh
under `Security events` → filter on `rule.groups: surveillancehound`.

## Path B — syslog → Wazuh manager

If Hound runs on the firewall and the Wazuh manager is elsewhere on the
LAN, point Hound's syslog channel at the manager and add both the
decoder + rules:

```bash
# 1) Hound side — add a syslog channel
cat >> /etc/hound.toml <<'EOF'

[[notify]]
type     = "syslog"
host     = "wazuh-mgr.lan"
port     = 514
proto    = "udp"          # or "tcp" if your Wazuh manager listens on TCP/6514
facility = 16             # local0
app_name = "hound"
level    = "low"
EOF
systemctl restart hound

# 2) Wazuh manager — make sure syslog ingestion is on (ossec.conf):
#   <remote>
#     <connection>syslog</connection>
#     <allowed-ips>10.0.0.0/8</allowed-ips>
#     <port>514</port>
#     <protocol>udp</protocol>
#   </remote>

# 3) install decoder + rules on the manager
sudo cp deploy/wazuh/hound-decoder.xml /var/ossec/etc/decoders/local_hound_decoder.xml
sudo cp deploy/wazuh/hound-rules.xml   /var/ossec/etc/rules/local_hound_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/decoders/local_hound_decoder.xml \
                       /var/ossec/etc/rules/local_hound_rules.xml
sudo systemctl restart wazuh-manager
```

## Verifying the integration

Wazuh ships a `wazuh-logtest` tool that lets you replay a log line and
see which decoder + rule chain matches. From the manager:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a Hound jsonlines alert, e.g.:
{"ts": 1.7e9, "device_ip": "192.168.10.22", "kind": "bulk_inbound",
 "severity": "high", "summary": "...", "detail": "...",
 "dedup_key": "bulk_inbound:192.168.10.22"}
# expected: rule 100200 (anchor) + 100210 (bulk_inbound) match; level=11

# and the empty-device_ip case:
{"ts": 1.7e9, "device_ip": "", "kind": "capture_stalled",
 "severity": "high", "summary": "...", "detail": "...",
 "dedup_key": "capture_stalled"}
# expected: rule 100206 (sensor anchor) + 100219 (capture_stalled) match; level=12
```

For the syslog path:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste an RFC 5424 line:
<131>1 2026-05-16T14:00:00.000000Z fw.lan hound - bulk_inbound [hound@32473 kind="bulk_inbound" severity="high" device="192.168.10.22"] bulk_inbound: 198.51.100.5:80 -> 192.168.10.22:52000
# expected: surveillancehound-syslog-fields decodes kind/severity/device_ip/summary, then 100210 fires
```

## Rule IDs in this pack

| ID | Level | What it matches |
|----|-------|-----------------|
| 100200 | 0  | anchor — any Hound JSON event with `kind`/`severity`/`device_ip` |
| 100206 | 0  | sensor-level anchor — Hound JSON events with an empty `device_ip` (`capture_stalled`) |
| 100201 | 3  | severity = info (fallback) |
| 100202 | 5  | severity = low (fallback) |
| 100203 | 8  | severity = medium (fallback) |
| 100204 | 11 | severity = high (fallback) |
| 100205 | 13 | severity = critical (fallback) |
| 100210 | 11 | kind = bulk_inbound (firmware/model push toward camera) — T1190 T1542 |
| 100211 | 10 | kind = control_channel_suspect — T1071 T1095 |
| 100212 | 8  | kind = telemetry_offnet — T1041 |
| 100213 | 8  | kind = behavioral_anomaly — T1499 |
| 100214 | 5  | kind = new_device — T1078 |
| 100215 | 5  | kind = new_peer |
| 100216 | 8  | kind = camera_offline — T1499 |
| 100217 | 3  | kind = camera_recovered (camera visible again) — T1499 |
| 100218 | 8  | kind = camera_never_seen (configured camera never observed) — T1499 |
| 100219 | 12 | kind = capture_stalled (sensor blind, all detection stopped) — T1562.001 |
| 100220 | 13 | 3+ bulk_inbound on same camera in 5 min — SUSTAINED |
| 100221 | 13 | 3+ control_channel on same camera in 5 min — SUSTAINED |
| 100222 | 13 | 3+ capture_stalled from one log source in 2h — FLAPPING capture |

The 100200 range is operator-defined; renumber if you already use it.

`capture_stalled` is the only kind whose `device_ip` is empty — the alert is
about the sensor, not a camera — so it chains off anchor 100206 instead of
100200 and its description never interpolates `$(device_ip)`. Rule 100222's
2h window is sized for Hound's 1800s default `dedup_window_seconds`: three
identical alerts cannot arrive closer than ~30 min apart, so the 5-min
window used by the other correlation rules would never match.

## Active Response

Wazuh's Active Response can shoot back when a rule fires. A natural pair
with Hound's `bulk_inbound` (rule 100210) is to drop the offending
source IP at the firewall:

```xml
<command>
    <name>firewall-drop-source</name>
    <executable>firewall-drop</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
    <command>firewall-drop-source</command>
    <location>local</location>
    <rules_id>100210,100220</rules_id>
    <timeout>3600</timeout>
</active-response>
```

This is operator-territory — Hound emits the alert; what you do about
it is your policy. (Be aware: `firewall-drop-source` needs `srcip` —
Hound's alert is keyed on `device_ip` which is the *camera*, not the
attacker. Use Wazuh's `_data` field or extract from `summary` if you
want to action on the public source.)
