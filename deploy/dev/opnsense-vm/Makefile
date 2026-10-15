# OPNsense plugin validation rig — one entrypoint per phase.
# Run `make help` for the full list.

SHELL := /usr/bin/env bash
RIG   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: help fetch disk boot stop teardown first-boot ssh plugin-drop validate package-test status console

# Every target honours OPNSENSE_VERSION. Each version gets its own state dir
# and its own host port forwards (see "Instance scoping" in vars.sh), so two
# versions can be up at the same time:
#   make boot                            # 26.1.6 → var/      , ssh 2222
#   OPNSENSE_VERSION=26.7 make boot      # 26.7   → var-26.7/ , ssh 2892
# `make status` prints the ports of the instance you selected.

help:  ## show this help
	@awk 'BEGIN{FS=":.*##"; printf "\nTargets:\n"} /^[a-z][a-zA-Z0-9_-]+:.*##/ {printf "  \033[1m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo "  (prefix any target with OPNSENSE_VERSION=<x.y[.z]> to act on that instance;"
	@echo "   the default is 26.1.6 and keeps var/ + ports 2222/8443/8080)"
	@echo

fetch:        ## download + verify the OPNsense serial image (~550 MB, one-time per version)
	@$(RIG)/scripts/fetch-image.sh

disk:         ## decompress + convert to qcow2, resize to 8 GB (one-time)
	@$(RIG)/scripts/prepare-disk.sh

boot:         ## start the VM in the background
	@$(RIG)/scripts/boot.sh

stop:         ## graceful shutdown via QEMU monitor (falls back to kill)
	@$(RIG)/scripts/stop.sh

teardown:     ## stop + delete this instance's qcow2 (cache/ is preserved)
	@$(RIG)/scripts/stop.sh || true
	@source $(RIG)/vars.sh && rm -f "$$VAR_DIR"/opnsense.qcow2 "$$VAR_DIR"/*.sock "$$VAR_DIR"/qemu.pid \
	  && echo "teardown complete for $$OPNSENSE_VERSION ($$VAR_DIR); cache/ preserved"

first-boot:   ## drive the console to enable SSH + set root pw (one-time per fresh disk)
	@$(RIG)/scripts/first-boot.sh

ssh:          ## interactive shell on the VM
	@$(RIG)/scripts/ssh-wrap.sh ssh

console:      ## attach to the live serial console (Ctrl-] then Ctrl-D to detach)
	@source $(RIG)/vars.sh \
	  && echo "attaching to $$CONSOLE_SOCK — Ctrl-] then Ctrl-D to detach" \
	  && socat - UNIX-CONNECT:"$$CONSOLE_SOCK"

plugin-drop:  ## scp deploy/opnsense/src/ over + pkg install python311
	@$(RIG)/scripts/plugin-drop.sh

validate:     ## run all Phalcon + configd assertions; exits non-zero on failure
	@$(RIG)/scripts/validate.sh

package-test: ## build the os-hound .txz in the VM, pkg add it, assert it works (KEEP=1 to leave installed)
	@$(RIG)/scripts/package-test.sh

status:       ## show this instance's paths, ports, disk and VM state
	@$(RIG)/scripts/status.sh
