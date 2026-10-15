<?php
/**
 * SurveillanceHound service API — start / stop / restart / status / reload.
 *
 * Backs the buttons in the dashboard view. Each action shells out to the
 * configd action defined in service/conf/actions.d/actions_hound.conf,
 * which in turn runs the rc.d hound script as the right user.
 *
 * Mounted at: /api/hound/service/{start,stop,restart,status,reconfigure,reload}
 */

namespace OPNsense\Hound\Api;

use \OPNsense\Base\ApiMutableServiceControllerBase;
use \OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = "\OPNsense\Hound\Hound";
    protected static $internalServiceTemplate = "OPNsense/Hound";
    protected static $internalServiceEnabled = "general.enabled";
    protected static $internalServiceName = "hound";

    /**
     * Re-render /usr/local/etc/hound.toml from the saved model, then
     * restart the daemon so it picks the new config up.
     *
     * This is NOT provided by the base class — it gives start/stop/
     * restart/status/reconfigure and nothing else, so a UI calling
     * /api/hound/service/reload got "Endpoint not found". Worse than the
     * error box: Save itself succeeds, so settings land in config.xml and
     * the operator reasonably believes they are live, while the daemon
     * keeps running the previously rendered file.
     *
     * `reconfigure` is not a drop-in substitute: it reloads an OPNsense
     * *template*, and this plugin renders its config with a Python script
     * invoked through configd rather than through the template system.
     *
     * @return array
     */
    public function reloadAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => gettext('POST required')];
        }
        $backend = new Backend();
        $output = trim($backend->configdRun('hound reload'));
        // The configd action exits non-zero on a render failure, in which
        // case configd hands back an empty string. Say so rather than
        // reporting success over a config that was never written.
        if ($output === '') {
            return [
                'status' => 'failed',
                'message' => gettext(
                    'Could not render the hound configuration. Run ' .
                    '"configctl hound reload" from a shell to see why.'
                ),
            ];
        }
        return ['status' => 'ok', 'response' => $output];
    }
}
