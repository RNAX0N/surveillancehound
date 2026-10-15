<?php
/**
 * SurveillanceHound dashboard data API.
 *
 * Mounted at: /api/hound/dashboard/data[/{limit}]
 *
 * Why this exists rather than an iframe: OPNsense serves its UI under
 * `Content-Security-Policy: default-src 'self'` with `X-Frame-Options:
 * SAMEORIGIN`. The daemon's own web server listens on a different port,
 * which is a different origin, so a frame pointing at it is blocked by the
 * browser ("This content is blocked"). Serving the data through the
 * firewall's own API keeps everything same-origin, and lets the page be
 * rendered with stock OPNsense markup so it follows whichever theme the
 * operator has selected instead of shipping its own styling.
 *
 * The daemon's SQLite lives at 0640 hound:hound and the webgui runs as
 * www, so PHP cannot read it directly — configd runs the CLI as root and
 * hands back the JSON.
 */

namespace OPNsense\Hound\Api;

use \OPNsense\Base\ApiControllerBase;
use \OPNsense\Core\Backend;

class DashboardController extends ApiControllerBase
{
    /**
     * Return the dashboard document produced by `hound export`.
     *
     * @param string $limit max alert/flow rows; clamped, and validated as
     *                      an integer because it is interpolated into a
     *                      configd command line.
     * @return array
     */
    public function dataAction($limit = '100')
    {
        $limit = (int)$limit;
        if ($limit < 1) {
            $limit = 1;
        } elseif ($limit > 500) {
            $limit = 500;
        }

        $backend = new Backend();
        $raw = trim($backend->configdpRun('hound dashboard', [(string)$limit]));

        if ($raw === '') {
            // configd returns an empty string for a `script_output` action
            // whose command exited non-zero (it runs them with check=True and
            // throws the output away), and for an action it does not know.
            // Both mean "ask configd, not us" — so name the one command the
            // operator can run to see the real reason.
            return [
                'status' => 'failed',
                'message' => gettext(
                    'No response from the hound backend. Check that the ' .
                    'plugin is fully installed (configd knows the "hound ' .
                    'dashboard" action) and run "configctl hound dashboard ' .
                    '10" from a shell to see what it reports.'
                ),
            ];
        }

        $doc = json_decode($raw, true);
        if (!is_array($doc)) {
            // Surface a truncated copy of what came back — a configd action
            // that failed prints a reason, and swallowing it turns a
            // fixable misconfiguration into a blank panel.
            return [
                'status' => 'failed',
                'message' => gettext('Unexpected response from hound:') . ' ' .
                    substr($raw, 0, 300),
            ];
        }

        // `hound export` reports its own failures inside the document (and
        // exits 0 so configd does not swallow them) — do not overwrite that
        // with 'ok', or a real, explained error renders as an empty panel.
        if (!empty($doc['status']) && $doc['status'] !== 'ok') {
            return $doc;
        }

        $doc['status'] = 'ok';
        return $doc;
    }
}
