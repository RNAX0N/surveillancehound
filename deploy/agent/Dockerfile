# SurveillanceHound relay agent.
#
# Runs the full pipeline on a host that can see the camera segment, and
# ships results to a collector. It dispatches no notifications itself —
# the collector is the only thing that notifies.
#
# There is no `pip install` here on purpose. The daemon is stdlib-only and
# must stay that way, so the image copies the source and runs it with
# PYTHONPATH. A build that needed a package index would quietly break the
# constraint this project is built around.

FROM python:3.13-slim

# tcpdump is the only runtime dependency, and it is not a Python one.
# --no-install-recommends keeps the attack surface of a host-networked,
# NET_RAW-capable container down to what it actually needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/*

# Debian puts it here; the daemon resolves it from PATH.
ENV PATH="/usr/sbin:${PATH}"
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY src/ /app/src/

# State lives on a volume so restarting the container does not re-fire
# new_device for every camera. The daemon bootstraps its seen-IP set from
# this database; losing it means an alert storm on next start.
VOLUME ["/var/lib/hound"]

# Run as root INSIDE the container only. The container itself should be
# given CAP_NET_RAW and nothing else (see docker-compose.yml); dropping to
# an unprivileged uid here would additionally require a capability-aware
# tcpdump setup for no gain, since the container is already the boundary.

ENTRYPOINT ["python", "-m", "surveillancehound.cli"]
CMD ["run", "/etc/hound/hound.toml"]
