<?php
/**
 * SurveillanceHound service API — start / stop / restart / status / reload.
 *
 * Backs the buttons in the dashboard view. Each action shells out to the
 * configd action defined in service/conf/actions.d/actions_hound.conf,
 * which in turn runs the rc.d hound script as the right user.
 *
 * Mounted at: /api/hound/service/{start,stop,restart,status,reload}
 */

namespace OPNsense\Hound\Api;

use \OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = "\OPNsense\Hound\Hound";
    protected static $internalServiceTemplate = "OPNsense/Hound";
    protected static $internalServiceEnabled = "general.enabled";
    protected static $internalServiceName = "hound";
}
