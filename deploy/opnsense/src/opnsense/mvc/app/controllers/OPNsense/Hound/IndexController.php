<?php
/**
 * SurveillanceHound — main Services > SurveillanceHound page controller.
 *
 * Renders the configuration form (Volt template) and exposes the embedded
 * dashboard (served by `hound web` on the configured port) via an iframe.
 *
 * Mounted at: /ui/hound/
 */

namespace OPNsense\Hound;

use \OPNsense\Base\IndexController as BaseController;

class IndexController extends BaseController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm("general");
        $this->view->pick("OPNsense/Hound/index");
    }
}
