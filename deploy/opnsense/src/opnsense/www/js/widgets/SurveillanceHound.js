/*
 * SurveillanceHound dashboard widget.
 *
 * A glance, not a console: is the monitor watching, how many of each
 * kind of device are up, and which ones are not. Everything else lives
 * on the plugin page, which the title links to.
 *
 * COUNT BY ROLE, NEVER BY LUMPING. The first version summed every
 * uptime row under one "Cameras up" label, so twelve cameras plus the
 * NVR's own twelve VLAN gateway addresses rendered "22 / 27 cameras" —
 * a number that is not the count of anything. Each role gets its own
 * line now, and a role with no rows gets no line rather than "0 / 0".
 *
 * WHY IT TICKS SLOWLY. Each refresh runs `hound export` through configd,
 * which is a process spawn and a database read, so this asks for the
 * smallest useful document (--limit 1) and leaves the default dashboard
 * cadence alone. A widget that costs a process every few seconds is a
 * widget somebody eventually removes.
 *
 * WHY "unknown" RATHER THAN A NUMBER when the monitor is not reporting:
 * availability over a window nobody watched is invented, and the rest of
 * this project refuses to invent it. A stalled capture makes every row
 * stale at once, so the widget says so instead of showing twelve cameras
 * as up on evidence that stopped arriving.
 */

export default class SurveillanceHound extends BaseTableWidget {
    constructor() {
        super();
    }

    getGridOptions() {
        return {
            // Grow with the number of down devices, then scroll.
            sizeToContent: 400,
        };
    }

    getMarkup() {
        return $('<div></div>').append(
            this.createTable('hound-widget-table', { headerPosition: 'left' })
        );
    }

    async onWidgetTick() {
        let data = null;
        try {
            // limit 1: the widget needs the counts and the uptime list,
            // not the alert and flow pages the full page renders.
            data = await this.ajaxCall('/api/hound/dashboard/data/1');
        } catch (e) {
            data = null;
        }

        if (!data || !data.monitor) {
            this.updateTable('hound-widget-table', [[
                this.translations.monitor,
                `<span class="text-danger">${this.translations.unreachable}</span>`
            ]]);
            return;
        }

        const counts = data.counts || {};
        const cams = (data.uptime || []).concat(data.remote_uptime || []);

        // An address reported by both this box and a relay agent appears
        // twice. The relay row is the one that can actually see it, so
        // the local duplicate is dropped HERE rather than counted twice
        // — the full page marks it "superseded" instead, because there
        // it is a finding; in a few rows of summary it is just noise,
        // and double-counting it would break the totals below.
        const bySensor = {};
        cams.forEach((c) => {
            if (c.sensor && c.sensor !== 'local') { bySensor[c.ip] = true; }
        });
        const shown = cams.filter(
            (c) => !((!c.sensor || c.sensor === 'local') && bySensor[c.ip])
        );

        const alive = !!data.monitor.alive;
        const blind = !!data.monitor.blind;

        let state;
        if (!alive) {
            state = `<span class="text-danger">${this.translations.stopped}</span>`;
        } else if (blind) {
            state = `<span class="text-danger">${this.translations.stalled}</span>`;
        } else {
            state = `<span class="text-success">${this.translations.watching}</span>`;
        }

        const rows = [[this.translations.monitor, state]];

        const byRole = {};
        shown.forEach((c) => {
            const r = c.role || 'other';
            if (!byRole[r]) { byRole[r] = { up: 0, total: 0 }; }
            byRole[r].total += 1;
            if (c.state === 'up') { byRole[r].up += 1; }
        });

        const roleLabel = {
            camera: this.translations.cameras,
            nvr: this.translations.nvrs,
            other: this.translations.other,
        };

        ['camera', 'nvr', 'other'].forEach((r) => {
            if (!byRole[r]) { return; }
            rows.push([
                roleLabel[r] || r,
                (!alive || blind)
                    ? `<span class="text-muted">${this.translations.unknown}</span>`
                    : `${byRole[r].up} / ${byRole[r].total}`
            ]);
        });

        rows.push([
            this.translations.alerts,
            `${counts.alerts_24h !== undefined ? counts.alerts_24h : '—'}`
        ]);

        // Name what is down, so "one short" is actionable without
        // opening the page.
        if (alive && !blind) {
            shown.filter((c) => c.state === 'down' || c.state === 'never_seen')
                .forEach((c) => {
                    const label = c.state === 'never_seen'
                        ? this.translations.neverseen
                        : this.translations.down;
                    const safeIp = $('<div>').text(c.ip).html();
                    rows.push([
                        `<span class="text-danger">${safeIp}</span>`,
                        `<span class="text-danger">${label}</span>`
                    ]);
                });
        }

        if (!this.dataChanged('hound-widget', rows)) {
            return;
        }
        this.updateTable('hound-widget-table', rows);
    }
}
