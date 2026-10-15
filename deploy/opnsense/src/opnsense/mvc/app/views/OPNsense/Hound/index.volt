{#-
  SurveillanceHound — Volt view rendered at /ui/hound/

  Visual brief: match the dark / neon-cyan / magenta dashboard aesthetic from
  `surveillancehound.web`. Stays inside OPNsense's MVC + Bootstrap chassis so
  the form, validation, save+restart wiring keeps working — only the *look*
  is reskinned, scoped under `.hound-plugin-page` so we don't bleed into
  the rest of the firewall UI.

  Hard constraints kept verbatim:
    - no external assets (no Google Fonts, no CDN JS, no remote images)
    - no inline tracking, no analytics
    - all JS still uses OPNsense's helpers (mapDataToFormUI / saveFormToEndpoint
      / updateServiceControlUI) so the framework owns CSRF + validation
-#}

<script>
$(document).ready(function() {
    /* Pull the model state into the form fields */
    var data_get_map = {'frm_general_settings': "/api/hound/settings/get"};
    mapDataToFormUI(data_get_map).done(function () {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    /* Save & restart — chains save → configd reload → status refresh */
    $("#saveAct").click(function () {
        $("#saveAct").addClass("hound-busy");
        saveFormToEndpoint("/api/hound/settings/set", 'frm_general_settings',
            function() {
                ajaxCall("/api/hound/service/reload", {}, function() {
                    updateServiceStatusUI('hound');
                    $("#saveAct").removeClass("hound-busy");
                    $("#hound-toast").addClass("show");
                    setTimeout(function(){ $("#hound-toast").removeClass("show"); }, 2200);
                });
            });
    });

    updateServiceControlUI('hound');

    /* Light up the status pill from the service controller's JSON */
    function refreshStatusPill() {
        $.getJSON("/api/hound/service/status", function(d) {
            var pill = $("#hound-status-pill");
            pill.removeClass("status-running status-stopped status-unknown");
            if (d && d.status === "running") {
                pill.addClass("status-running").find(".dot-label").text("RUNNING");
            } else if (d && d.status === "stopped") {
                pill.addClass("status-stopped").find(".dot-label").text("STOPPED");
            } else {
                pill.addClass("status-unknown").find(".dot-label").text("UNKNOWN");
            }
        });
    }
    refreshStatusPill();
    setInterval(refreshStatusPill, 5000);

    /* Wire the dashboard iframe from the configured bind host/port.
       Two rules:
         (1) Scheme matches the parent page — a mixed-content iframe
             (HTTP under HTTPS) is silently blocked by every modern browser.
             The OPNsense reload action mints a self-signed cert
             automatically when the parent is HTTPS.
         (2) "Bind everywhere" addresses (0.0.0.0 / :: / blank) aren't
             routable from a browser; fall back to the hostname the
             operator used to reach this UI. That works whether they
             browsed to the firewall via IP or DNS. */
    $.getJSON("/api/hound/settings/get", function(d) {
        var web = (d.hound && d.hound.web) || {};
        var host = web.host || "";
        if (!host || host === "0.0.0.0" || host === "::" || host === "0:0:0:0:0:0:0:0") {
            host = window.location.hostname;
        }
        var port = web.port || "8080";
        var scheme = window.location.protocol.replace(":", "");  // 'http' | 'https'
        var url = scheme + "://" + host + ":" + port + "/";
        $("#hound-dash").attr("src", url);
        $("#hound-dash-url").text(url);
        $("#hound-dash-link").attr("href", url);
    });
});
</script>

<style>
/* ─────────────────────────────────────────────────────────────────────────
   SurveillanceHound — futuristic skin, scoped under .hound-plugin-page so
   it never leaks out of /ui/hound/. Uses CSS variables so themers can rebrand
   in one place without touching markup.
   ───────────────────────────────────────────────────────────────────────── */
.hound-plugin-page {
    --hp-bg:        #03060d;
    --hp-bg-2:      #0a1020;
    --hp-bg-card:   linear-gradient(160deg, rgba(10,16,32,0.95) 0%, rgba(3,6,13,0.95) 100%);
    --hp-border:    rgba(0, 212, 255, 0.22);
    --hp-border-2:  rgba(255, 0, 170, 0.18);
    --hp-text:      #d6e4f0;
    --hp-muted:     #6c87a5;
    --hp-cyan:      #00d4ff;
    --hp-magenta:   #ff00aa;
    --hp-green:     #00ff9c;
    --hp-amber:     #ffaa00;
    --hp-red:       #ff3860;
    --hp-glow-c:    0 0 14px rgba(0, 212, 255, 0.55);
    --hp-glow-m:    0 0 14px rgba(255, 0, 170, 0.55);
    --hp-mono:      ui-monospace, "SF Mono", "JetBrains Mono", "IBM Plex Mono",
                    Menlo, Consolas, "Courier New", monospace;

    background: var(--hp-bg);
    color: var(--hp-text);
    padding: 18px 22px 32px;
    margin: -15px -15px 0;        /* erase OPNsense's default content padding */
    min-height: calc(100vh - 100px);
    font-family: var(--hp-mono);
}

/* Subtle scanline texture for the futuristic vibe — pure CSS, no images. */
.hound-plugin-page::before {
    content: "";
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        180deg,
        rgba(255,255,255,0.012) 0px,
        rgba(255,255,255,0.012) 1px,
        transparent 1px,
        transparent 3px
    );
    pointer-events: none;
    z-index: 1;
}
.hound-plugin-page > * { position: relative; z-index: 2; }

/* ── Header bar with logo, status pill, action buttons ─────────────────── */
.hound-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    padding: 14px 18px;
    margin-bottom: 18px;
    background: var(--hp-bg-card);
    border: 1px solid var(--hp-border);
    border-radius: 4px;
    box-shadow: var(--hp-glow-c), inset 0 1px 0 rgba(255,255,255,0.04);
    position: relative;
    overflow: hidden;
}
.hound-header::after {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(circle at 100% 0%, rgba(255,0,170,0.10), transparent 50%);
    pointer-events: none;
}
.hound-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    font-family: var(--hp-mono);
}
.hound-brand-mark {
    width: 38px;
    height: 38px;
    border-radius: 4px;
    background: linear-gradient(135deg, var(--hp-cyan), var(--hp-magenta));
    box-shadow: var(--hp-glow-c);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--hp-bg);
    font-weight: 700;
    font-size: 18px;
    letter-spacing: 1px;
}
.hound-brand-text .title {
    font-size: 18px;
    font-weight: 600;
    color: var(--hp-text);
    letter-spacing: 0.5px;
    margin: 0;
}
.hound-brand-text .sub {
    font-size: 11px;
    color: var(--hp-muted);
    letter-spacing: 2px;
    text-transform: uppercase;
}
.hound-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 6px 14px;
    background: rgba(0,0,0,0.4);
    border: 1px solid var(--hp-border);
    border-radius: 999px;
    font-family: var(--hp-mono);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--hp-muted);
}
.hound-status-pill .dot {
    width: 8px; height: 8px; border-radius: 999px;
    background: var(--hp-muted);
    box-shadow: 0 0 0 transparent;
    animation: hp-pulse 2.4s ease-in-out infinite;
}
.hound-status-pill.status-running .dot { background: var(--hp-green); box-shadow: 0 0 10px var(--hp-green); }
.hound-status-pill.status-running .dot-label { color: var(--hp-green); }
.hound-status-pill.status-stopped .dot { background: var(--hp-red); box-shadow: 0 0 10px var(--hp-red); }
.hound-status-pill.status-stopped .dot-label { color: var(--hp-red); }
.hound-status-pill.status-unknown .dot { background: var(--hp-amber); box-shadow: 0 0 10px var(--hp-amber); }
.hound-status-pill.status-unknown .dot-label { color: var(--hp-amber); }
@keyframes hp-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.55; } }

/* ── Tab bar (overrides Bootstrap nav-tabs inside our scope) ───────────── */
.hound-plugin-page .nav-tabs {
    border-bottom: 1px solid var(--hp-border);
    background: transparent;
    margin-bottom: 0;
    padding: 0 6px;
}
.hound-plugin-page .nav-tabs > li > a {
    background: transparent !important;
    color: var(--hp-muted) !important;
    border: 1px solid transparent !important;
    border-radius: 4px 4px 0 0 !important;
    font-family: var(--hp-mono);
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 10px 18px !important;
    margin-right: 4px;
    transition: color 120ms ease, background 120ms ease, box-shadow 120ms ease;
}
.hound-plugin-page .nav-tabs > li > a:hover {
    color: var(--hp-cyan) !important;
    background: rgba(0,212,255,0.05) !important;
}
.hound-plugin-page .nav-tabs > li.active > a,
.hound-plugin-page .nav-tabs > li.active > a:focus,
.hound-plugin-page .nav-tabs > li.active > a:hover {
    background: var(--hp-bg-2) !important;
    color: var(--hp-cyan) !important;
    border-color: var(--hp-border) !important;
    border-bottom-color: var(--hp-bg-2) !important;
    box-shadow: 0 -2px 0 var(--hp-cyan), 0 -10px 14px -8px var(--hp-cyan) inset;
}

/* ── Card content panels ──────────────────────────────────────────────── */
.hound-plugin-page .tab-content.content-box {
    background: var(--hp-bg-2);
    border: 1px solid var(--hp-border);
    border-top: none;
    border-radius: 0 0 4px 4px;
    padding: 22px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
}

/* Note callouts — replace washed-out gray with a glowing cyan-stripe box */
.hound-note {
    background: linear-gradient(90deg, rgba(0,212,255,0.08), rgba(0,212,255,0.0) 60%);
    border-left: 2px solid var(--hp-cyan);
    box-shadow: -2px 0 12px -4px var(--hp-cyan);
    padding: 12px 16px;
    margin: 0 0 18px;
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--hp-text);
    font-family: var(--hp-mono);
    border-radius: 0 2px 2px 0;
}
.hound-note strong { color: var(--hp-cyan); letter-spacing: 0.5px; }
.hound-note code {
    background: rgba(0,0,0,0.45);
    color: var(--hp-magenta);
    padding: 1px 6px;
    border-radius: 2px;
    font-size: 11.5px;
    border: 1px solid var(--hp-border-2);
}
.hound-note a { color: var(--hp-cyan); }
.hound-note a:hover { color: var(--hp-magenta); text-decoration: underline; }
.hound-note ol, .hound-note ul { margin: 6px 0 0 20px; padding: 0; }
.hound-note li { margin: 4px 0; }

/* ── OPNsense base_form overrides — header rows + inputs ───────────────── */
.hound-plugin-page .table > tbody > tr > td {
    border-color: rgba(255,255,255,0.04) !important;
    color: var(--hp-text);
    padding: 10px 12px !important;
    background: transparent !important;
}
.hound-plugin-page .table > tbody > tr.label_block,
.hound-plugin-page .table > tbody > tr > th {
    background: linear-gradient(90deg, rgba(255,0,170,0.10), transparent 70%) !important;
    color: var(--hp-magenta) !important;
    border-top: 1px solid var(--hp-border-2) !important;
    border-bottom: 1px solid var(--hp-border-2) !important;
    font-family: var(--hp-mono);
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 10px 12px !important;
}
.hound-plugin-page .control-label {
    color: var(--hp-text);
    font-weight: 500;
    font-family: var(--hp-mono);
    font-size: 13px;
}
.hound-plugin-page .help-block {
    color: var(--hp-muted);
    font-size: 11.5px;
    line-height: 1.5;
    margin-top: 4px;
}
.hound-plugin-page input.form-control,
.hound-plugin-page select.form-control,
.hound-plugin-page textarea.form-control {
    background: rgba(0,0,0,0.40) !important;
    border: 1px solid rgba(0,212,255,0.18) !important;
    color: var(--hp-text) !important;
    border-radius: 3px !important;
    box-shadow: inset 0 1px 0 rgba(0,0,0,0.4) !important;
    font-family: var(--hp-mono);
    transition: border-color 120ms ease, box-shadow 120ms ease;
}
.hound-plugin-page input.form-control:focus,
.hound-plugin-page select.form-control:focus,
.hound-plugin-page textarea.form-control:focus {
    border-color: var(--hp-cyan) !important;
    box-shadow: 0 0 0 1px var(--hp-cyan), 0 0 10px rgba(0,212,255,0.35) !important;
    outline: none;
}
/* selectpicker / bootstrap-select reskin */
.hound-plugin-page .btn-default,
.hound-plugin-page .dropdown-toggle {
    background: rgba(0,0,0,0.40) !important;
    color: var(--hp-text) !important;
    border: 1px solid rgba(0,212,255,0.18) !important;
}
.hound-plugin-page .dropdown-menu {
    background: var(--hp-bg-2) !important;
    border: 1px solid var(--hp-border) !important;
}
.hound-plugin-page .dropdown-menu > li > a {
    color: var(--hp-text) !important;
}
.hound-plugin-page .dropdown-menu > li > a:hover {
    background: rgba(0,212,255,0.10) !important;
    color: var(--hp-cyan) !important;
}
/* Checkbox accent — keep the native control but tint it */
.hound-plugin-page input[type="checkbox"] {
    accent-color: var(--hp-cyan);
    transform: scale(1.15);
    margin-right: 6px;
}

/* ── Action bar (Save button + status echo) ────────────────────────────── */
.hound-actions {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-top: 18px;
    padding-top: 18px;
    border-top: 1px dashed var(--hp-border);
}
.hound-plugin-page .btn-primary,
.hound-plugin-page #saveAct {
    background: linear-gradient(135deg, var(--hp-cyan), #0099cc) !important;
    color: var(--hp-bg) !important;
    border: none !important;
    border-radius: 3px !important;
    padding: 9px 22px !important;
    font-family: var(--hp-mono);
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    box-shadow: 0 0 14px rgba(0,212,255,0.5), 0 2px 0 rgba(0,0,0,0.4);
    transition: transform 120ms ease, box-shadow 120ms ease;
}
.hound-plugin-page .btn-primary:hover,
.hound-plugin-page #saveAct:hover {
    transform: translateY(-1px);
    box-shadow: 0 0 22px rgba(0,212,255,0.85), 0 3px 0 rgba(0,0,0,0.4);
}
.hound-plugin-page #saveAct.hound-busy {
    background: linear-gradient(135deg, var(--hp-magenta), #aa006e) !important;
    box-shadow: 0 0 22px rgba(255,0,170,0.7);
    pointer-events: none;
    animation: hp-pulse 1.2s ease-in-out infinite;
}
.hound-actions .meta {
    color: var(--hp-muted);
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

/* ── Iframe wrap ───────────────────────────────────────────────────────── */
.hound-iframe-wrap {
    background: var(--hp-bg);
    border: 1px solid var(--hp-border);
    border-radius: 3px;
    box-shadow: var(--hp-glow-c), inset 0 0 30px rgba(0,0,0,0.6);
    margin-top: 14px;
    height: 720px;
    position: relative;
    overflow: hidden;
}
.hound-iframe-wrap iframe {
    width: 100%;
    height: 100%;
    border: 0;
    display: block;
    background: var(--hp-bg);
}
.hound-iframe-wrap .corner {
    position: absolute;
    top: 8px; right: 12px;
    font-family: var(--hp-mono);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--hp-muted);
    pointer-events: none;
    text-shadow: 0 0 6px rgba(0,0,0,0.8);
}

/* ── Save toast ────────────────────────────────────────────────────────── */
#hound-toast {
    position: fixed;
    right: 24px;
    bottom: 24px;
    padding: 12px 18px;
    background: var(--hp-bg-2);
    border: 1px solid var(--hp-cyan);
    border-radius: 4px;
    box-shadow: var(--hp-glow-c);
    color: var(--hp-cyan);
    font-family: var(--hp-mono);
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    opacity: 0;
    transform: translateY(8px);
    pointer-events: none;
    transition: opacity 200ms ease, transform 200ms ease;
    z-index: 1050;
}
#hound-toast.show { opacity: 1; transform: translateY(0); }
#hound-toast::before {
    content: "▸ ";
    color: var(--hp-magenta);
}

/* ── Help-tab kbd / cmd styling ────────────────────────────────────────── */
.hound-plugin-page kbd {
    background: rgba(0,0,0,0.5);
    border: 1px solid var(--hp-border);
    color: var(--hp-cyan);
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 11px;
    font-family: var(--hp-mono);
}

/* Print-friendly fallback — never let the dark scheme stain a printout */
@media print {
    .hound-plugin-page,
    .hound-plugin-page .tab-content.content-box {
        background: #fff !important;
        color: #000 !important;
        box-shadow: none !important;
    }
    .hound-plugin-page::before { display: none; }
}
</style>

<div class="hound-plugin-page">

    <div class="hound-header">
        <div class="hound-brand">
            <div class="hound-brand-mark">SH</div>
            <div class="hound-brand-text">
                <div class="title">SurveillanceHound</div>
                <div class="sub">NVR / IP-camera network monitor</div>
            </div>
        </div>
        <div class="hound-status-pill" id="hound-status-pill">
            <span class="dot"></span>
            <span class="dot-label">CHECKING…</span>
        </div>
    </div>

    <ul class="nav nav-tabs" role="tablist" id="maintabs">
        <li class="active"><a data-toggle="tab" href="#settings">▸ Settings</a></li>
        <li><a data-toggle="tab" href="#dashboard">▸ Live dashboard</a></li>
        <li><a data-toggle="tab" href="#help">▸ Help</a></li>
    </ul>

    <div class="tab-content content-box">

        <div id="settings" class="tab-pane fade in active">
            <div class="hound-note">
                <strong>What runs here.</strong> The daemon watches the selected
                interface for activity the surveillance threat model cares about:
                bulk transfers <em>toward</em> a camera, long-lived camera↔public
                sessions on non-routine ports, off-allowlist telemetry, behavioral
                anomalies vs each camera's learned baseline, new devices, new
                peers, and silent cameras. Saving regenerates
                <code>/usr/local/etc/hound.toml</code> and restarts the service.
                Headers only — no payload inspection, no DNS, no video.
            </div>

            {{ partial("layout_partials/base_form",
                       ['fields': generalForm, 'id': 'frm_general_settings']) }}

            <div class="hound-actions">
                <button class="btn btn-primary" id="saveAct"
                        data-endpoint="/api/hound/settings/set"
                        data-label="{{ lang._('Save') }}"
                        data-error-title="{{ lang._('Error saving') }}">
                    ▸ {{ lang._('Save & restart') }}
                </button>
                <span class="meta">writes /usr/local/etc/hound.toml + bounces hound.service</span>
            </div>
        </div>

        <div id="dashboard" class="tab-pane fade">
            <div class="hound-note">
                <strong>Embedded view.</strong> Below is the read-only dashboard
                <code>hound web</code> serves at
                <a id="hound-dash-link" href="#" target="_blank"><code><span id="hound-dash-url">…</span></code></a>.
                The dashboard's protocol is matched to the firewall UI's
                automatically — HTTPS here gets HTTPS there, HTTP gets HTTP.
                On HTTPS, a self-signed cert is generated on first save and
                stored under <code>/var/lib/hound/</code>; your browser will
                prompt once to trust it. To replace the self-signed cert with
                your own, set the optional PEM paths under <em>Settings</em>.
            </div>
            <div class="hound-iframe-wrap">
                <div class="corner">// EMBEDDED VIEW</div>
                <iframe id="hound-dash" src="about:blank"
                        title="SurveillanceHound dashboard"></iframe>
            </div>
        </div>

        <div id="help" class="tab-pane fade">
            <div class="hound-note">
                <strong>Quickstart.</strong>
                <ol>
                    <li>Pick the <em>Listen interface</em> — typically your
                        camera VLAN or a SPAN/mirror port.</li>
                    <li>Enter your cameras under <em>Camera IPs</em> /
                        <em>Camera subnets</em>. List NVRs separately so the
                        daemon doesn't treat them as cameras.</li>
                    <li>Add your camera vendor's cloud CIDRs to
                        <em>Manufacturer allowlist</em> so legitimate telemetry
                        doesn't fire <code>telemetry_offnet</code>.</li>
                    <li>Tick <em>Enable</em> and hit <em>Save &amp; restart</em>.
                        Within seconds, alerts start landing.</li>
                    <li>(Optional) Enable <em>Behavioral baselining</em> for
                        per-camera anomaly detection. Cold start needs ~1 week of
                        traffic per camera before alerts arm.</li>
                    <li>(Optional) Enable <em>Forensic snapshots</em> — the
                        daemon keeps the last <em>N</em> seconds of raw packets
                        per camera in RAM and dumps a Wireshark-openable pcap
                        on every alert above the configured severity.</li>
                </ol>
            </div>

            <div class="hound-note">
                <strong>Alert kinds &amp; severity.</strong>
                <ul>
                    <li><code>bulk_inbound</code> — HIGH. Large transfer
                        <em>toward</em> a camera (model push / firmware).</li>
                    <li><code>control_channel_suspect</code> — MEDIUM.
                        Long-lived camera↔public on a non-routine port.</li>
                    <li><code>telemetry_offnet</code> — MEDIUM. Camera talks
                        to a public host not in the manufacturer allowlist.</li>
                    <li><code>behavioral_anomaly</code> — MEDIUM. Per-flow
                        stats drift &gt; <em>N</em>σ from learned baseline.</li>
                    <li><code>new_device</code> — LOW. Previously-unseen IP
                        appears on the segment.</li>
                    <li><code>new_peer</code> — LOW. Known camera contacts a
                        brand-new endpoint.</li>
                    <li><code>camera_offline</code> — MEDIUM. Camera silent
                        for longer than the silence threshold.</li>
                    <li><code>camera_recovered</code> — INFO. A camera that
                        was offline is being seen again.</li>
                    <li><code>camera_never_seen</code> — MEDIUM. A configured
                        camera has never been observed at all: powered down
                        before the monitor started, wrong IP in the config,
                        or on a segment this sensor cannot see.</li>
                    <li><code>capture_stalled</code> — HIGH. Zero packets
                        captured — the sensor is blind (dead tcpdump, mirror
                        port down), and per-camera offline alerts are
                        suppressed until it recovers.</li>
                </ul>
                <p>Liveness is <strong>passive</strong>:
                    a camera counts as up because packets from it crossed the
                    listen interface. Nothing is probed, so "offline" means
                    "not visible to this sensor", which is not always the same
                    as "powered down".</p>
            </div>

            <div class="hound-note">
                <strong>Where things live on the firewall.</strong>
                <ul>
                    <li>Daemon binary: <code>/usr/local/bin/hound</code></li>
                    <li>Config: <code>/usr/local/etc/hound.toml</code>
                        (rendered from this form on save)</li>
                    <li>State (SQLite): <code>/var/lib/hound/hound.sqlite</code></li>
                    <li>Log: <code>/var/log/hound/hound.log</code></li>
                    <li>Service control: <kbd>service hound onestart</kbd> /
                        <kbd>configctl hound restart</kbd></li>
                </ul>
            </div>
        </div>

    </div>

    <div id="hound-toast">Saved + service restarted</div>

</div>
