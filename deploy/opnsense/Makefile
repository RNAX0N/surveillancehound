# SurveillanceHound — OPNsense plugin
#
# Build/install with the standard OPNsense plugin tooling. From this dir:
#
#   make package          # builds os-hound-X.Y.txz
#   pkg install -y ./work/pkg/os-hound-*.txz
#
# Or for in-place dev on an OPNsense system:
#
#   make install          # cp files into /usr/local/
#   configctl webgui restart
#
# The plugin assumes `hound` (the CLI from this repo) is installable from
# pkg or pip. The Makefile here does NOT bundle the hound source — the
# operator is expected to `pkg install python311 && pip install hound` (or
# `pip install -e /usr/local/src/SurveillanceHound`) before enabling the
# service. See README.md.

PLUGIN_NAME=           hound
PLUGIN_VERSION=        0.1
PLUGIN_REVISION=       1
PLUGIN_COMMENT=        IP-camera network monitor
PLUGIN_MAINTAINER=     njack2af@proton.me
PLUGIN_WWW=            https://github.com/RNAX0N/surveillancehound
PLUGIN_DEPENDS=        python311 tcpdump

.include "../../Mk/plugins.mk"
