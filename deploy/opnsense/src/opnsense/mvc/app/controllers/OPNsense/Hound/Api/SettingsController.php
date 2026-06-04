<?php
/**
 * SurveillanceHound settings API — read / write the plugin's config model.
 *
 * The MVC base class (`ApiMutableModelControllerBase`) wires the CRUD ops
 * against `OPNsense\Hound\Hound`, which the framework auto-loads from
 * models/OPNsense/Hound/Hound.xml. Saving the form runs the configd
 * "hound restart" action so the rendered hound.toml is picked up.
 *
 * Mounted at: /api/hound/settings/{get,set}
 */

namespace OPNsense\Hound\Api;

use \OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = "hound";
    protected static $internalModelClass = "\OPNsense\Hound\Hound";
}
