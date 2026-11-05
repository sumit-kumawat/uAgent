#!/bin/sh
# Restarts the portal when it stops answering. systemd runs this on a timer.
ENV_FILE=/etc/uagent/portal.env

# A portal an administrator stopped on purpose stays stopped, and an update that is applying or rolling
# back a release restarts the portal itself.
systemctl is-active --quiet uagent-portal || exit 0
if systemctl list-units --type=service --state=active --no-legend 'uagent-update-*' 2>/dev/null | grep -q .; then
  exit 0
fi

setting() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1; }
PORT="$(setting PORTAL_HTTP_PORT)"
BIND="$(setting PORTAL_BIND_ADDRESS)"
case "$BIND" in
  ""|0.0.0.0|::|localhost) HOST=127.0.0.1 ;;
  *:*) HOST="[$BIND]" ;;
  *) HOST="$BIND" ;;
esac

if ! curl -fsS --max-time 5 "http://${HOST}:${PORT:-80}/healthz" >/dev/null 2>&1; then
  systemctl restart uagent-portal
fi
