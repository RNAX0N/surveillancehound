/*
 * SurveillanceHound dashboard widget.
 *
 * A glance, not a console: is the monitor watching, are the cameras up,
 * and which ones are not. Everything else lives on the plugin page,
 * which the title links to.
 *
 * WHY IT TICKS SLOWLY. Each refresh runs `hound export` through configd,
 * which is a process spawn and a database read, so this asks for the
 * smallest useful document (--limit 1) and leaves the default dashboard
 * cadence alone rather than polling hard. A widget that costs a process
 * every few seconds is a widget somebody eventually removes.
 *
 * WHY "unknown" RATHER THAN A NUMBER when the monitor is not reporting:
 * availability over a window nobody watched is invented, and the rest of
 * this project refuses to invent it. A stalled capture makes every
 * camera row stale at once, so the widget says that plainly instead of
 * showing twelve cameras as up on evidence that stopped arriving.
 */

export default class SurveillanceHound extends BaseTableWidget {
    constructor() {
        super();
    }

    getGridOptions() {
        return {
            // Grow with the number of down cameras, then scroll.
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
        // it is a finding; in four rows of summary it is just noise.
        const bySensor = {};
        cams.forEach((c) => {
            if (c.sensor && c.sensor !== 'local') { bySensor[c.ip] = true; }
        });
        const shown = cams.filter(
            (c) => !((!c.sensor || c.sensor === 'local') && bySensor[c.ip])
        );

        const blind = !!data.monitor.blind;
        const alive = !!data.monitor.alive;

        let state;
        if (!alive) {
            state = `<span class="text-danger">${this.translations.stopped}</span>`;
        } else if (blind) {
            state = `<span class="text-danger">${this.translations.stalled}</span>`;
        } else {
            state = `<span class="text-success">${this.translations.watching}</span>`;
        }

        const down = shown.filter((c) => c.state === 'down' ||
                                         c.state === 'never_seen');
        const up = shown.filter((c) => c.state === 'up');

        let rows = [[this.translations.monitor, state]];

        // With no live capture every camera row is stale, so a count of
        // "up" would be a claim about something unobserved.
        rows.push([
            this.translations.cameras,
            (!alive || blind)
                ? `<span class="text-muted">${this.translations.unknown}</span>`
                : `${up.length} / ${shown.length}`
        ]);

        rows.push([
            this.translations.alerts,
            `${counts.alerts_24h !== undefined ? counts.alerts_24h : '—'}`
        ]);

        if (alive && !blind) {
            down.forEach((c) => {
                const label = c.state === 'never_seen'
                    ? this.translations.neverseen
                    : this.translations.down;
                rows.push([
                    `<span class="text-danger">${$('<div>').text(c.ip).html()}</span>`,
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
