<?php
/**
 * SurveillanceHound — model class stub.
 *
 * BaseModel auto-discovers the schema from the sibling Hound.xml file using
 * the conventional naming (`<Namespace>\<Name>\<Name>.php` ↔
 * `<Namespace>/<Name>/<Name>.xml`). The PHP class is just a marker so
 * Phalcon can reflect on it — all field definitions live in the XML.
 *
 * Without this stub, ApiMutableServiceControllerBase::getModel() fails with
 * `ReflectionException: Class "\OPNsense\Hound\Hound" does not exist`.
 */

namespace OPNsense\Hound;

use OPNsense\Base\BaseModel;

class Hound extends BaseModel
{
}
