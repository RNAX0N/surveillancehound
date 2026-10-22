#!/bin/sh
# P3 auto-revert. Restores the pre-P3 input chain AND both drop-ins,
# then reloads. Fires unless cancelled, so a lockout heals itself.
set -e
cp /etc/nftables.conf.pre-20261022-p3 /etc/nftables.conf
cp /root/gsfw-observe.pre-20261022-p3 /etc/nftables.d/gsfw-observe.nft
cp /root/gsfw-enforce.pre-20261022-p3 /etc/nftables.d/gsfw-enforce.nft
nft -f /etc/nftables.conf
logger -t gsfw "P3 AUTO-REVERTED: input chain and drop-ins restored"
