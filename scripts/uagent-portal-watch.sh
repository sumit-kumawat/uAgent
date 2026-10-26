#!/bin/sh
# Restarts the portal when it stops answering. systemd runs this on a timer.
if ! curl -fsS --max-time 5 http://127.0.0.1/healthz >/dev/null 2>&1; then
  systemctl restart uagent-portal
fi
