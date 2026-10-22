{#-
  SurveillanceHound — Volt view rendered at /ui/hound/

  Deliberately carries no styling of its own. Everything here uses stock
  OPNsense/Bootstrap markup so the page follows whichever theme the operator
  has selected — the default and opnsense-dark both work, and so will any
  other, because nothing hardcodes a colour.

  The dashboard is rendered natively rather than framed. OPNsense serves its
  UI under `Content-Security-Policy: default-src 'self'` with
  `X-Frame-Options: SAMEORIGIN`, so an iframe pointed at the daemon's own web
  server — a different port, therefore a different origin — is blocked by the
  browser. Data comes from /api/hound/dashboard/data, which runs
  `hound export` through configd and stays same-origin.

  Constraints kept: no external assets, and all form wiring still goes
  through OPNsense's helpers so the framework owns CSRF and validation.
-#}

<script>
$(document).ready(function() {
    var dashboardTimer = null;

    /* Pull the model state into the form fields */
    mapDataToFormUI({'frm_general_settings': "/api/hound/settings/get"}).done(function () {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    updateServiceControlUI('hound');

    /* Save & restart — chains save -> configd reload -> status refresh */
    $("#saveAct").click(function () {
        $("#saveAct").prop("disabled", true);
        saveFormToEndpoint("/api/hound/settings/set", 'frm_general_settings', function () {
            // Saving only writes config.xml. The daemon reads
            // /usr/local/etc/hound.toml, which this re-renders — without it
            // the settings look applied but the daemon keeps the old file.
            ajaxCall("/api/hound/service/reload", {}, function (data, status) {
                $("#saveAct").prop("disabled", false);
                if (!data || data.status !== 'ok') {
                    $("#hound-save-error")
                        .text((data && data.message)
                            ? data.message
                            : "{{ lang._('Settings were saved but the configuration could not be applied.') }}")
                        .show();
                } else {
                    $("#hound-save-error").hide();
                }
                updateServiceStatusUI('hound');
                if ($("#dashboard").hasClass("active")) {
                    loadDashboard();
                }
            });
        });
    });

    function esc(s) {
        return $('<div/>').text(s === null || s === undefined ? '' : s).html();
    }

    /* Numeric coercion for values interpolated into innerHTML. These
       fields are numbers by schema, and validate.py coerces relayed ones
       on arrival — but this view now renders rows produced on another
       host, and a single layer of validation between a remote sensor and
       innerHTML is one layer. A non-number becomes 0 rather than markup. */
    function num(v) {
        var n = Number(v);
        return isFinite(n) ? n : 0;
    }

    function fmtAgo(ts) {
        if (!ts) { return "{{ lang._('never') }}"; }
        var s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (s < 60) { return s + 's'; }
        if (s < 3600) { return Math.floor(s / 60) + 'm'; }
        if (s < 86400) { return Math.floor(s / 3600) + 'h'; }
        return Math.floor(s / 86400) + 'd';
    }

    function fmtDur(s) {
        s = Math.max(0, Math.floor(s || 0));
        if (!s) { return '-'; }
        if (s < 60) { return s + 's'; }
        if (s < 3600) { return Math.floor(s / 60) + 'm'; }
        if (s < 86400) { return Math.floor(s / 3600) + 'h'; }
        return Math.floor(s / 86400) + 'd';
    }

    function fmtBytes(n) {
        n = n || 0;
        if (n < 1024) { return n + ' B'; }
        if (n < 1048576) { return (n / 1024).toFixed(1) + ' KiB'; }
        if (n < 1073741824) { return (n / 1048576).toFixed(1) + ' MiB'; }
        return (n / 1073741824).toFixed(2) + ' GiB';
    }

    /* Bootstrap contextual classes, so severity colour comes from the theme
       rather than from hardcoded hex values that would clash in dark mode. */
    function severityLabel(sev) {
        var cls = {
            'critical': 'label-danger',
            'high': 'label-danger',
            'medium': 'label-warning',
            'low': 'label-info',
            'info': 'label-default'
        }[sev] || 'label-default';
        return '<span class="label ' + cls + '">' + esc(sev) + '</span>';
    }

    function stateLabel(state) {
        var cls = {
            'up': 'label-success',
            'down': 'label-danger',
            'never_seen': 'label-warning'
        }[state] || 'label-default';
        return '<span class="label ' + cls + '">' +
               esc(String(state).replace('_', ' ')) + '</span>';
    }

    /* Put every panel into an explicit unknown state.
     *
     * The monitor banner starts as "Loading…" and was only ever replaced
     * on the SUCCESS path, so a backend that never answered left the
     * dashboard saying "Loading…" and "—" indefinitely — indistinguishable
     * from a request still in flight, on the one panel whose job is to say
     * whether the monitor is alive. A surface that cannot tell you it
     * failed is the same defect as one that reports a figure it did not
     * observe. */
    function dashFailed(text) {
        $("#hound-monitor").attr('class', 'alert alert-warning').text(text);
        $("#stat-cameras,#stat-nvrs,#stat-devices,#stat-alerts").text('?');
    }

    function loadDashboard() {
        $("#hound-dash-error").hide();
        ajaxGet("/api/hound/dashboard/data", {}, function (d, status) {
            if (!d || d.status !== 'ok') {
                var msg = (d && d.message)
                    ? d.message
                    : "{{ lang._('Could not reach the hound backend.') }}";
                $("#hound-dash-error").text(msg).show();
                dashFailed("{{ lang._('Monitor state unknown — the backend did not answer.') }}");
                return;
            }

            /* A collector whose store predates relay support has no
               remote_* tables yet. The document still carries all the
               local data; say why the relay panels are empty rather
               than letting them read as "no sensor ever reported". */
            if (d.relay_unavailable) {
                $("#hound-dash-error")
                    .attr('class', 'alert alert-warning')
                    .text(d.relay_unavailable).show();
            } else {
                $("#hound-dash-error").attr('class', 'alert alert-danger');
            }

            $("#stat-cameras").text(d.counts.cameras);
            $("#stat-nvrs").text(d.counts.nvrs);
            $("#stat-devices").text(d.counts.devices);
            $("#stat-alerts").text(d.counts.alerts_24h);

            /* Monitor health first: if the sensor is blind, every row below
               it is stale and saying so matters more than the rows do. */
            var m = d.monitor, cls, txt;
            if (!m.alive) {
                cls = 'alert-danger';
                txt = "{{ lang._('Monitor is not running.') }}";
            } else if (m.blind) {
                cls = 'alert-danger';
                txt = "{{ lang._('Capture stalled — the monitor is running but seeing no packets. Per-camera offline alerts are suppressed until it recovers.') }}";
            } else {
                cls = 'alert-success';
                txt = "{{ lang._('Watching') }} " + esc(m.source) +
                      " — {{ lang._('last packet') }} " + fmtAgo(m.last_activity_ts) +
                      " {{ lang._('ago') }}";
            }
            // Relay sensors, if any. A sensor that has gone quiet means
            // its whole segment is unmonitored — and this box cannot see
            // that segment itself, which is why the agent exists. Saying
            // so here matters more than any row it last reported.
            var sensors = d.sensors || [];
            if (sensors.length) {
                var parts = [];
                $.each(sensors, function (i, x) {
                    // TWO independent questions, and this read only one.
                    // `reporting` is about the LINK — are its batches
                    // arriving. `mon_blind` is what the sensor says about
                    // its OWN capture. A sensor whose capture is dead but
                    // whose link is fine rendered a green "reporting"
                    // beside camera rows it could no longer see, at
                    // 100% availability. This is the collector's primary
                    // UI (the stdlib dashboard is CSP-blocked here), so
                    // fixing it only there fixed it nowhere an operator
                    // looks.
                    var state;
                    if (!x.reporting) {
                        state = "<span class='text-danger'>" +
                            "{{ lang._('NOT reporting') }}</span> (" +
                            fmtAgo(x.last_seen) + " {{ lang._('ago') }})";
                    } else if (x.mon_blind) {
                        state = "<span class='text-danger'>" +
                            "{{ lang._('capture stalled — camera rows " +
                            "below are stale') }}</span>";
                    } else {
                        state = "<span class='text-success'>" +
                            "{{ lang._('reporting') }}</span>";
                    }
                    parts.push('<strong>' + esc(x.sensor_id) + '</strong>: ' +
                               state);
                });
                txt += "<br/><small>{{ lang._('Relay sensors') }} — " +
                       parts.join(' &nbsp; ') + "</small>";
            }
            $("#hound-monitor").attr('class', 'alert ' + cls).html(txt);

            // Local rows and rows relayed by an agent are shown in one
            // table but never merged: each keeps its own sensor, because
            // their availability is computed over different monitored
            // windows. Without the relayed rows this box — which is the
            // collector — cannot see the segment it exists to watch.
            var cams = (d.uptime || []).concat(d.remote_uptime || []);

            /* An address reported by BOTH this box and a relay sensor is
               listed twice, and the two rows disagree: the sensor can see
               the device, this box demonstrably cannot, so the local row
               is a claim about something out of its reach. That is not a
               rendering quirk — it is the collector asserting a camera is
               "never seen" while the agent watching it reports it up.
               Mark the local one rather than hide it: silently dropping a
               row is how a dashboard starts lying in the other direction,
               and the fix is to remove the stale row (the button above),
               not to paper over it. */
            var bySensor = {};
            $.each(cams, function (i, c) {
                if (c.sensor && c.sensor !== 'local') bySensor[c.ip] = c.sensor;
            });

            var rows = '';
            $.each(cams, function (i, c) {
                var superseded = (!c.sensor || c.sensor === 'local') &&
                                 bySensor[c.ip];
                // A sensor that has stopped reporting tells us nothing
                // current, so its cameras read unknown and its
                // availability reads n/a rather than the figure it last
                // claimed — that number is as stale as the contact.
                var stale = (c.stale === true);
                rows += '<tr' + (superseded ? ' class="text-muted"' : '') + '>' +
                    '<td>' + stateLabel(c.state) + '</td>' +
                    '<td>' + esc(c.ip) +
                        (superseded
                            ? ' <span class="label label-warning" title="'
                              + "{{ lang._('Sensor ') }}" + esc(bySensor[c.ip])
                              + "{{ lang._(' also reports this address and can actually see it. This local row is left over from a configuration this box no longer has; use Remove unclaimed rows.') }}"
                              + '">{{ lang._('superseded') }}</span>'
                            : '') +
                        '</td>' +
                    '<td>' + esc(c.sensor || 'local') + '</td>' +
                    '<td>' + esc(c.role) + '</td>' +
                    '<td>' + (c.last_seen ? fmtAgo(c.last_seen) : "{{ lang._('never') }}") + '</td>' +
                    '<td>' + fmtDur(c.current_downtime) + '</td>' +
                    '<td>' + num(c.outage_count) + '</td>' +
                    '<td>' + ((stale || c.availability === null)
                        ? 'n/a'
                        : (num(c.availability) * 100).toFixed(2) + '%') + '</td>' +
                    /* Only local rows: this box can delete what it
                       recorded itself. A relayed row belongs to the
                       sensor that sent it, and the only lever for those
                       is dropping the whole sensor — too large a blast
                       radius to hang on a row-level button. */
                    '<td>' + ((!c.sensor || c.sensor === 'local')
                        ? '<button type="button" class="btn btn-default btn-xs hound-forget-row"' +
                          ' data-ip="' + esc(c.ip) + '" title="' +
                          "{{ lang._('Remove this row. Device rows come only from traffic this box observed, so one it can no longer see stays until deleted.') }}" +
                          '"><i class="fa fa-times"></i></button>'
                        : '') + '</td>' +
                    '</tr>';
            });
            $("#tbl-uptime tbody").html(rows ||
                '<tr><td colspan="9">' +
                "{{ lang._('No cameras known yet — set Camera IPs under Settings.') }}" +
                '</td></tr>');

            rows = '';
            // Local and relayed alerts together, newest first, each
            // tagged with the sensor that observed it. Showing only
            // local alerts hid the segment the relay exists to watch.
            // Sorted on OUR clock: `ts` comes from the sensor, so
            // sorting on it lets one alert dated 2099 pin itself above
            // every local row forever. Relayed rows carry ingested_at.
            function atime(a) { return num(a.ingested_at || a.ts); }
            var alerts = (d.alerts || []).concat(d.remote_alerts || [])
                .sort(function (x, y) { return atime(y) - atime(x); });
            $.each(alerts, function (i, a) {
                rows += '<tr>' +
                    '<td>' + esc(new Date(atime(a) * 1000).toLocaleString()) + '</td>' +
                    '<td>' + severityLabel(a.severity) + '</td>' +
                    '<td><code>' + esc(a.kind) + '</code></td>' +
                    '<td>' + esc(a.sensor || a.sensor_id || 'local') + '</td>' +
                    '<td>' + esc(a.device_ip) + '</td>' +
                    '<td>' + esc(a.summary) + '</td>' +
                    '</tr>';
            });
            $("#tbl-alerts tbody").html(rows ||
                '<tr><td colspan="6">' + "{{ lang._('No alerts yet.') }}" + '</td></tr>');

            rows = '';
            /* COLLAPSE REPEATED CONVERSATIONS.
             *
             * A flow is keyed on the full 5-tuple, and the client's
             * source port is ephemeral — a new one for every NTP poll
             * and every DNS lookup. So one chatty pair produced one row
             * per exchange and pushed everything else off the table: on
             * a real firewall this list was 100% NTP and DNS to the
             * gateway, repeating every 65 seconds, with nothing else
             * visible at all.
             *
             * Group on everything EXCEPT the ephemeral source port, sum
             * the counters, and keep the most recent timestamp. The
             * underlying rows are untouched — `hound flows` still shows
             * every one — this is a reading of them, and a dashboard
             * that cannot be read is not reporting. */
            var groups = {}, order = [];
            $.each((d.flows || []).concat(d.remote_flows || []), function (i, f) {
                var sensor = f.sensor || f.sensor_id || 'local';
                var k = [sensor, f.src_ip, f.dst_ip, f.dst_port, f.proto,
                         f.classification].join('|');
                var g = groups[k];
                if (!g) {
                    g = groups[k] = {
                        sensor: sensor, src_ip: f.src_ip, dst_ip: f.dst_ip,
                        dst_port: f.dst_port, proto: f.proto,
                        classification: f.classification,
                        packets: 0, bytes: 0, n: 0, last: 0, sortk: 0
                    };
                    order.push(g);
                }
                g.packets += num(f.packets);
                g.bytes += num(f.bytes);
                g.n += 1;
                g.last = Math.max(g.last, num(f.last_seen));
                /* Sort on OUR clock, display THEIRS. `last_seen` comes
                   from the sensor, so ordering on it lets one
                   future-dated relayed row pin itself to the top of the
                   dashboard forever — which is exactly what the
                   server-side ORDER BY ingested_at was changed to
                   close. Grouping must not quietly undo that. */
                g.sortk = Math.max(g.sortk, num(f.ingested_at || f.last_seen));
            });
            order.sort(function (x, y) { return y.sortk - x.sortk; });

            $.each(order, function (i, g) {
                /* "x12" only when it really is several, so a single
                   conversation does not read as a summary of one. */
                var times = g.n > 1
                    ? ' <span class="badge" title="'
                      + "{{ lang._('conversations collapsed into this row') }}"
                      + '">x' + g.n + '</span>'
                    : '';
                rows += '<tr>' +
                    '<td>' + esc(new Date(g.last * 1000).toLocaleTimeString()) + times + '</td>' +
                    '<td>' + esc(g.sensor) + '</td>' +
                    '<td>' + esc(g.src_ip) + '</td>' +
                    '<td>' + esc(g.dst_ip) + ':' + esc(g.dst_port) + '</td>' +
                    '<td>' + esc(g.proto) + '</td>' +
                    '<td>' + num(g.packets) + '</td>' +
                    '<td>' + fmtBytes(num(g.bytes)) + '</td>' +
                    '<td><code>' + esc(g.classification) + '</code></td>' +
                    '</tr>';
            });
            $("#tbl-flows tbody").html(rows ||
                '<tr><td colspan="8">' + "{{ lang._('No flows recorded yet.') }}" + '</td></tr>');
        }, function () {
            $("#hound-dash-error")
                .text("{{ lang._('Request to the hound backend failed.') }}")
                .show();
            dashFailed("{{ lang._('Monitor state unknown — the request failed.') }}");
        });
    }

    /* Remove local rows the config no longer claims.
     *
     * Confirm first: it deletes outage history, which is the only record
     * that a camera was ever down. Harmless for rows this box cannot
     * observe — which is the case it exists for — but not reversible. */
    $("#hound-forget-unclaimed").click(function () {
        if (!confirm("{{ lang._('Remove every camera/NVR row this box no longer has in its configuration, along with its outage history? Rows for devices still on the wire come back on the next packet.') }}")) {
            return;
        }
        var $b = $(this).prop("disabled", true);
        ajaxCall("/api/hound/dashboard/forgetUnclaimed", {}, function (d) {
            $b.prop("disabled", false);
            if (d && d.status === 'ok') {
                $("#hound-dash-error")
                    .attr('class', 'alert alert-success')
                    .text(d.response || "{{ lang._('Done.') }}").show();
                loadDashboard();
            } else {
                $("#hound-dash-error")
                    .attr('class', 'alert alert-danger')
                    .text((d && d.message) ||
                          "{{ lang._('Could not reach the hound backend.') }}")
                    .show();
            }
        });
    });

    /* Only poll while the dashboard tab is visible — each refresh spawns a
       configd process, so polling a hidden tab is pure waste. */
    function startPolling() {
        loadDashboard();
        if (dashboardTimer === null) {
            dashboardTimer = setInterval(loadDashboard, 10000);
        }
    }
    function stopPolling() {
        if (dashboardTimer !== null) {
            clearInterval(dashboardTimer);
            dashboardTimer = null;
        }
    }

    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        if ($(e.target).attr('href') === '#dashboard') {
            startPolling();
        } else {
            stopPolling();
        }
    });

    /* The dashboard is the landing tab, so no `shown.bs.tab` fires for it
       on load — that event is only emitted when a tab is switched TO.
       Without this the page opened on an empty table and stayed empty
       until the operator clicked away and back. */
    if ($("#dashboard").hasClass("active")) {
        startPolling();
    }
    /* Delegated: the rows are rebuilt on every poll, so a handler bound
       to the buttons themselves would be lost ten seconds later. */
    $("#tbl-uptime").on("click", ".hound-forget-row", function () {
        var $b = $(this).prop("disabled", true), ip = $b.data("ip");
        ajaxCall("/api/hound/dashboard/forgetDevice", {'ip': ip}, function (d) {
            if (d && d.status === 'ok') {
                $("#hound-dash-error")
                    .attr('class', 'alert alert-success')
                    .text(d.response || "{{ lang._('Removed.') }}").show();
                loadDashboard();
            } else {
                $b.prop("disabled", false);
                $("#hound-dash-error")
                    .attr('class', 'alert alert-danger')
                    .text((d && d.message) ||
                          "{{ lang._('Could not reach the hound backend.') }}")
                    .show();
            }
        });
    });

    $("#hound-refresh").click(function () { loadDashboard(); });
});
</script>

<!-- Dashboard first: this page is opened to look at the cameras far more
     often than to change a setting, and landing on a form invites editing
     something by accident on the way to a glance. -->
<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#dashboard">{{ lang._('Dashboard') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#help">{{ lang._('Help') }}</a></li>
</ul>

<div class="tab-content content-box">

    <div id="settings" class="tab-pane fade">
        <div class="content-box-main">
            {{ partial("layout_partials/base_form",
                       ['fields': generalForm, 'id': 'frm_general_settings']) }}
            <div class="col-md-12">
                <hr/>
                <div id="hound-save-error" class="alert alert-danger" style="display:none;"></div>
                <button class="btn btn-primary" id="saveAct" type="button"
                        data-endpoint="/api/hound/settings/set"
                        data-label="{{ lang._('Save') }}"
                        data-error-title="{{ lang._('Error saving settings') }}">
                    {{ lang._('Save & restart') }}
                </button>
                <br/><br/>
                <div class="text-muted">
                    {{ lang._('Saving writes /usr/local/etc/hound.toml and restarts the service. The daemon reads packet headers only — no payload inspection, no DNS resolution, no video.') }}
                </div>
            </div>
        </div>
    </div>

    <div id="dashboard" class="tab-pane fade in active">
        <div class="content-box-main">

            <div id="hound-dash-error" class="alert alert-danger" style="display:none;"></div>
            <div id="hound-monitor" class="alert alert-info">{{ lang._('Loading…') }}</div>

            <div class="row">
                <div class="col-xs-3 text-center">
                    <h3 id="stat-cameras">—</h3><small>{{ lang._('Cameras') }}</small>
                </div>
                <div class="col-xs-3 text-center">
                    <h3 id="stat-nvrs">—</h3><small>{{ lang._('NVRs') }}</small>
                </div>
                <div class="col-xs-3 text-center">
                    <h3 id="stat-devices">—</h3><small>{{ lang._('Devices seen') }}</small>
                </div>
                <div class="col-xs-3 text-center">
                    <h3 id="stat-alerts">—</h3><small>{{ lang._('Alerts (24h)') }}</small>
                </div>
            </div>

            <hr/>
            <button class="btn btn-default btn-xs pull-right" id="hound-refresh" type="button">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>

            <h4>
                {{ lang._('Camera uptime') }}
                <button id="hound-forget-unclaimed" type="button"
                        class="btn btn-default btn-xs pull-right"
                        title="{{ lang._('Delete rows for devices this box no longer has in its config — for example cameras that moved behind a relay agent. They cannot be cleared any other way: roles never downgrade and pruning keeps open outages.') }}">
                    <i class="fa fa-eraser"></i>
                    {{ lang._('Remove unclaimed rows') }}
                </button>
            </h4>
            <div class="table-responsive">
                <table class="table table-striped table-condensed" id="tbl-uptime">
                    <thead>
                        <tr>
                            <th>{{ lang._('State') }}</th>
                            <th>{{ lang._('Address') }}</th>
                            <th>{{ lang._('Sensor') }}</th>
                            <th>{{ lang._('Role') }}</th>
                            <th>{{ lang._('Last seen') }}</th>
                            <th>{{ lang._('Down for') }}</th>
                            <th>{{ lang._('Outages') }}</th>
                            <th>{{ lang._('Availability') }}</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
            <br/>
            <div class="text-muted">
                {{ lang._('Liveness is inferred from traffic observed on the monitored interface, not from active probing. A camera that is powered but no longer visible to this sensor reads the same as one that is off. Availability counts only time the monitor was running; it shows n/a rather than a figure invented from no observation.') }}
            </div>

            <br/>
            <h4>{{ lang._('Recent alerts') }}</h4>
            <div class="table-responsive">
                <table class="table table-striped table-condensed" id="tbl-alerts">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Kind') }}</th>
                            <th>{{ lang._('Sensor') }}</th>
                            <th>{{ lang._('Device') }}</th>
                            <th>{{ lang._('Summary') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

            <br/>
            <h4>{{ lang._('Recent flows') }}</h4>
            <div class="table-responsive">
                <table class="table table-striped table-condensed" id="tbl-flows">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Sensor') }}</th>
                            <th>{{ lang._('Source') }}</th>
                            <th>{{ lang._('Destination') }}</th>
                            <th>{{ lang._('Proto') }}</th>
                            <th>{{ lang._('Packets') }}</th>
                            <th>{{ lang._('Bytes') }}</th>
                            <th>{{ lang._('Classification') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

        </div>
    </div>

    <div id="help" class="tab-pane fade">
        <div class="content-box-main">
            <h4>{{ lang._('Getting started') }}</h4>
            <ol>
                <li>{{ lang._('Pick the listen interface — typically your camera VLAN or a SPAN/mirror port.') }}</li>
                <li>{{ lang._('Enter your cameras under Camera IPs or Camera subnets. List NVRs separately so they are not treated as cameras.') }}</li>
                <li>{{ lang._('Add your camera vendor cloud ranges to the manufacturer allowlist, so legitimate vendor telemetry does not alert.') }}</li>
                <li>{{ lang._('Tick Enable and press Save & restart.') }}</li>
            </ol>

            <h4>{{ lang._('Alert kinds') }}</h4>
            <div class="table-responsive">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('Kind') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Meaning') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td><code>bulk_inbound</code></td><td>{{ lang._('High') }}</td>
                            <td>{{ lang._('A large transfer toward a camera — the shape of a firmware or model-weight push. Identify the host and what was delivered.') }}</td></tr>
                        <tr><td><code>control_channel_suspect</code></td><td>{{ lang._('Medium') }}</td>
                            <td>{{ lang._('A camera is holding a long-lived or chatty session with a public host on a non-routine port.') }}</td></tr>
                        <tr><td><code>telemetry_offnet</code></td><td>{{ lang._('Medium') }}</td>
                            <td>{{ lang._('A camera is talking to a public host that is not in the manufacturer allowlist.') }}</td></tr>
                        <tr><td><code>behavioral_anomaly</code></td><td>{{ lang._('Medium') }}</td>
                            <td>{{ lang._('This camera is not behaving the way it normally does for this weekday and hour.') }}</td></tr>
                        <tr><td><code>new_device</code></td><td>{{ lang._('Medium / Info') }}</td>
                            <td>{{ lang._('An address never seen before has appeared on the segment.') }}</td></tr>
                        <tr><td><code>new_peer</code></td><td>{{ lang._('Low') }}</td>
                            <td>{{ lang._('A known camera has started talking to an endpoint it had not contacted before.') }}</td></tr>
                        <tr><td><code>camera_offline</code></td><td>{{ lang._('Medium') }}</td>
                            <td>{{ lang._('A known camera has gone silent. Detection is passive, so this means not visible to this sensor.') }}</td></tr>
                        <tr><td><code>camera_recovered</code></td><td>{{ lang._('Info') }}</td>
                            <td>{{ lang._('A camera that was offline is sending traffic again, with the outage duration.') }}</td></tr>
                        <tr><td><code>camera_never_seen</code></td><td>{{ lang._('Medium') }}</td>
                            <td>{{ lang._('A configured camera has never been observed: powered down before the monitor started, wrong address, or on a segment this sensor cannot see.') }}</td></tr>
                        <tr><td><code>capture_stalled</code></td><td>{{ lang._('High') }}</td>
                            <td>{{ lang._('No packets at all are arriving — the sensor itself is blind, so nothing else is being detected either. Per-camera offline alerts are suppressed until it recovers.') }}</td></tr>
                    </tbody>
                </table>
            </div>

            <h4>{{ lang._('Notes') }}</h4>
            <ul>
                <li>{{ lang._('The daemon reads packet headers only. It cannot leak video or credentials because it never reads a payload byte.') }}</li>
                <li>{{ lang._('It does not probe your cameras. Uptime is inferred from observed traffic.') }}</li>
                <li>{{ lang._('To add notification channels beyond the defaults, edit /usr/local/etc/hound.toml.local — the rendered config is overwritten on every save.') }}</li>
            </ul>
        </div>
    </div>

</div>
