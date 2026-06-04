# OPNsense plugin validation rig — one entrypoint per phase.
# Run `make help` for the full list.

SHELL := /usr/bin/env bash
RIG   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: help fetch disk boot stop teardown first-boot ssh plugin-drop validate package-test status console

help:  ## show this help
	@awk 'BEGIN{FS=":.*##"; printf "\nTargets:\n"} /^[a-z][a-zA-Z0-9_-]+:.*##/ {printf "  \033[1m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo

fetch:        ## download + verify the OPNsense nano image (~300 MB, one-time)
	@$(RIG)/scripts/fetch-image.sh

disk:         ## decompress + convert to qcow2, resize to 8 GB (one-time)
	@$(RIG)/scripts/prepare-disk.sh

boot:         ## start the VM in the background
	@$(RIG)/scripts/boot.sh

stop:         ## graceful shutdown via QEMU monitor (falls back to kill)
	@$(RIG)/scripts/stop.sh

teardown:     ## stop + delete the qcow2 (cache/ is preserved)
	@$(RIG)/scripts/stop.sh || true
	@rm -f $(RIG)/var/opnsense.qcow2 $(RIG)/var/*.sock $(RIG)/var/qemu.pid
	@echo "teardown complete; cache/ preserved"

first-boot:   ## drive the console to enable SSH + set root pw (one-time per fresh disk)
	@$(RIG)/scripts/first-boot.sh

ssh:          ## interactive shell on the VM
	@$(RIG)/scripts/ssh-wrap.sh ssh

console:      ## attach to the live serial console (ctrl-o then "q" to detach in socat)
	@echo "attaching to $(RIG)/var/console.sock — Ctrl-] then Ctrl-D to detach"
	@socat - UNIX-CONNECT:$(RIG)/var/console.sock

plugin-drop:  ## scp deploy/opnsense/src/ over + pkg install python311
	@$(RIG)/scripts/plugin-drop.sh

validate:     ## run all Phalcon + configd assertions; exits non-zero on failure
	@$(RIG)/scripts/validate.sh

package-test: ## build the os-hound .txz in the VM, pkg add it, assert it works (KEEP=1 to leave installed)
	@$(RIG)/scripts/package-test.sh

status:       ## show what's running
	@if [ -f $(RIG)/var/qemu.pid ] && kill -0 "$$(cat $(RIG)/var/qemu.pid)" 2>/dev/null; then \
	   echo "VM:       running (pid $$(cat $(RIG)/var/qemu.pid))"; \
	else echo "VM:       stopped"; fi
	@if [ -S $(RIG)/var/console.sock ]; then echo "console:  $(RIG)/var/console.sock"; fi
	@if [ -f $(RIG)/var/opnsense.qcow2 ]; then \
	   echo "disk:     $$(du -h $(RIG)/var/opnsense.qcow2 | cut -f1) at $(RIG)/var/opnsense.qcow2"; \
	else echo "disk:     not built (make disk)"; fi
	@if [ -f $(RIG)/cache/OPNsense-*.img.bz ]; then \
	   echo "image:    $$(du -h $(RIG)/cache/OPNsense-*.img.bz | cut -f1) cached"; \
	else echo "image:    not fetched (make fetch)"; fi
	@if command -v ssh >/dev/null && nc -z 127.0.0.1 2222 2>/dev/null; then \
	   echo "ssh:      open on 127.0.0.1:2222"; \
	else echo "ssh:      not reachable yet"; fi
