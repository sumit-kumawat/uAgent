#!/usr/libexec/platform-python -I
# Root helper for administering the Linux server the uAgent portal runs on. The portal calls it through
# sudo (see the sudoers rule written by install-centos.sh); it is also safe to run by hand as root.
#
#   uagent-sysadmin info
#   uagent-sysadmin firewall enable|disable
#   uagent-sysadmin firewall port add|remove <zone> <port>/<proto>
#   uagent-sysadmin firewall service add|remove <zone> <service>
#   uagent-sysadmin firewall confirm|revert
#   uagent-sysadmin service start|stop|restart <unit>
#   uagent-sysadmin power reboot|poweroff|cancel
#   uagent-sysadmin hostname set <name> | hostname restore
#   uagent-sysadmin dns set <connection-uuid> <servers|dhcp> [--search a,b] [--test host] | dns restore <uuid>
#   uagent-sysadmin domain discover <domain>
#   uagent-sysadmin domain join <domain> <user> [--ou <ou>]      (password on standard input)
#   uagent-sysadmin domain leave
#   uagent-sysadmin logs portal|auth|system|firewall|admin [lines]
#
# Every argument is validated against a strict pattern and passed to programs as a separate argument,
# never through a shell. Passwords are read from standard input only and never written or logged.
# Changes that could cut the server off are guarded: firewall changes revert by themselves unless
# confirmed, DNS changes revert if the test name stops resolving, and the SSH and portal ports, the
# network stack and the last local administrator are protected.
# Written for Python 3.6 (platform-python on CentOS Stream 8 / RHEL 8).
import datetime
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time

STATE_DIR = "/var/lib/uagent-sysadmin"
ENV_FILE = "/etc/uagent/portal.env"
REVERT_UNIT = "uagent-firewall-revert"
REVERT_SECONDS = 120
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}

DNS_NAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{0,120}$")
ZONE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,60}$")
PORT = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?/(tcp|udp|sctp|dccp)$")
IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
IPV6 = re.compile(r"^[0-9A-Fa-f:]{2,39}$")
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")
USER = re.compile(r"^[A-Za-z0-9._@\\-]{1,128}$")
OU = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")

# Stopping these cuts off SSH, the network, D-Bus (which every other control uses) or the portal itself.
PROTECTED_UNITS = re.compile(r"^(sshd|NetworkManager|network|dbus|dbus-broker|polkit|systemd-.*|firewalld|auditd|getty@.*|serial-getty@.*|uagent-portal)\.service$")
# The portal may restart itself (the helper runs outside its control group) but not stop.
RESTARTABLE = {"uagent-portal.service", "sshd.service", "NetworkManager.service", "firewalld.service"}


def emit(obj, code=0):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def fail(message, **extra):
    payload = {"ok": False, "error": message}
    payload.update(extra)
    emit(payload, 1)


def run(argv, stdin=None, timeout=60):
    try:
        return subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=timeout, env=CLEAN_ENV)
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", "%s is not installed." % argv[0])
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "%s did not finish within %d seconds." % (argv[0], timeout))


def must(argv, what, stdin=None, timeout=60):
    result = run(argv, stdin, timeout)
    if result.returncode != 0:
        fail("%s failed: %s" % (what, (result.stderr or result.stdout).strip()[:600] or "exit code %d" % result.returncode))
    return result.stdout


def have(program):
    return shutil.which(program, path=CLEAN_ENV["PATH"]) is not None


def audit(message):
    if have("logger"):
        run(["logger", "-t", "uagent-sysadmin", "-p", "authpriv.notice", message])


def save(name, data):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    path = os.path.join(STATE_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(data, handle)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load(name):
    try:
        with open(os.path.join(STATE_DIR, name)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def portal_env():
    values = {}
    try:
        with open(ENV_FILE) as handle:
            for line in handle:
                match = re.match(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$", line)
                if match:
                    values[match.group(1)] = match.group(2).strip("'\"")
    except OSError:
        pass
    return values


def now_utc():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# --- Reading ------------------------------------------------------------------------------------------

def unit_state(name):
    load_state = run(["systemctl", "show", "-p", "LoadState", "--value", name]).stdout.strip()
    if load_state in ("", "not-found"):
        return {"installed": False}
    return {
        "installed": True,
        "active": run(["systemctl", "is-active", name]).stdout.strip(),
        "enabled": run(["systemctl", "is-enabled", name]).stdout.strip()
    }


def parse_zone(text):
    zone = {"services": [], "ports": [], "richRules": [], "interfaces": [], "sources": []}
    key_map = {"services": "services", "ports": "ports", "interfaces": "interfaces", "sources": "sources", "target": "target",
               "masquerade": "masquerade", "protocols": "protocols", "forward-ports": "forwardPorts", "icmp-blocks": "icmpBlocks"}
    in_rich = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            zone["name"] = line.split()[0]
            zone["active"] = "(active)" in line
            continue
        stripped = line.strip()
        if in_rich and line.startswith("\t"):
            zone["richRules"].append(stripped)
            continue
        in_rich = False
        key, _, value = stripped.partition(":")
        if key == "rich rules":
            in_rich = True
            continue
        if key in key_map:
            target = key_map[key]
            zone[target] = value.split() if target in ("services", "ports", "interfaces", "sources", "protocols", "forwardPorts", "icmpBlocks") else value.strip()
    return zone


def firewall_state():
    unit = unit_state("firewalld")
    if not unit.get("installed"):
        return {"installed": False}
    state = {"installed": True, "active": unit["active"], "enabled": unit["enabled"], "running": False, "zones": []}
    if run(["firewall-cmd", "--state"]).stdout.strip() != "running":
        return state
    state["running"] = True
    state["defaultZone"] = run(["firewall-cmd", "--get-default-zone"]).stdout.strip()
    state["panic"] = run(["firewall-cmd", "--query-panic"]).stdout.strip() == "yes"
    state["availableServices"] = run(["firewall-cmd", "--get-services"]).stdout.split()
    active = []
    for line in run(["firewall-cmd", "--get-active-zones"]).stdout.splitlines():
        if line and not line.startswith((" ", "\t")):
            active.append(line.strip())
    names = sorted(set(active + [state["defaultZone"]]))
    for name in names:
        zone = parse_zone(run(["firewall-cmd", "--zone=" + name, "--list-all"]).stdout)
        zone["name"] = name
        zone["default"] = name == state["defaultZone"]
        zone["permanentPorts"] = run(["firewall-cmd", "--permanent", "--zone=" + name, "--list-ports"]).stdout.split()
        zone["permanentServices"] = run(["firewall-cmd", "--permanent", "--zone=" + name, "--list-services"]).stdout.split()
        state["zones"].append(zone)
    state["revertPending"] = revert_pending()
    return state


def revert_pending():
    active = run(["systemctl", "is-active", REVERT_UNIT + ".timer"]).stdout.strip() == "active"
    pending = load("firewall-pending.json")
    return pending if active and pending else None


def accounts():
    shadow = {}
    try:
        with open("/etc/shadow") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 8:
                    shadow[parts[0]] = parts
    except OSError:
        pass
    groups = {}
    try:
        with open("/etc/group") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 4:
                    groups[parts[0]] = [m for m in parts[3].split(",") if m]
    except OSError:
        pass
    admins = set(groups.get("wheel", [])) | {"root"}
    lastlog = read_lastlog()
    known = lastlog is not None
    lastlog = lastlog or {}
    result = []
    with open("/etc/passwd") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(":")
            if len(parts) < 7:
                continue
            name, uid, shell = parts[0], int(parts[2]), parts[6]
            if uid != 0 and uid < 1000:
                continue
            if uid >= 60000:
                continue
            sh = shadow.get(name)
            password = sh[1] if sh else ""
            expires = None
            if sh and sh[7].isdigit():
                expires = (datetime.date(1970, 1, 1) + datetime.timedelta(days=int(sh[7]))).isoformat()
            changed = None
            if sh and sh[2].isdigit() and int(sh[2]) > 0:
                changed = (datetime.date(1970, 1, 1) + datetime.timedelta(days=int(sh[2]))).isoformat()
            login = lastlog.get(uid)
            result.append({
                "user": name, "uid": uid, "shell": shell,
                "interactive": not shell.endswith(("nologin", "false")),
                "locked": password.startswith(("!", "*")),
                "noPassword": password == "",
                "passwordChanged": changed, "expires": expires,
                "admin": name in admins,
                "lastLoginUtc": login[0] if login else None, "lastLoginFrom": login[1] if login else None,
                "lastLoginKnown": known
            })
    return result


# None when lastlog cannot be read, so callers report the last sign-in as unknown rather than never.
def read_lastlog():
    entries = {}
    size = struct.calcsize("=I32s256s")
    try:
        with open("/var/log/lastlog", "rb") as handle:
            data = handle.read(size * 70000)
    except OSError:
        return None
    for uid in range(0, len(data) // size):
        stamp, line, host = struct.unpack_from("=I32s256s", data, uid * size)
        if stamp:
            entries[uid] = (datetime.datetime.utcfromtimestamp(stamp).isoformat() + "Z",
                            (host.split(b"\0")[0] or line.split(b"\0")[0]).decode("utf-8", "replace"))
    return entries


ISO = r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4})"


def iso_utc(text):
    try:
        value = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z")
        return value.astimezone(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    except ValueError:
        return None


def wtmp(argv, limit):
    rows = []
    for line in run(argv + ["-w", "-i", "--time-format", "iso", "-n", str(limit)]).stdout.splitlines():
        # "user line from start - end (duration)", "user line from start   still logged in", and for reboots
        # "reboot system boot <kernel> start   still running".
        match = re.match(r"^(\S+)\s+(.*?)\s+" + ISO + r"(?:\s+-\s+" + ISO + r")?\s*(.*)$", line)
        if not match or (match.group(1) in ("wtmp", "btmp") and match.group(2).startswith("begins")):
            continue
        middle = match.group(2).split()
        rows.append({"user": match.group(1), "line": middle[0] if middle else "", "from": middle[-1] if len(middle) > 1 else "",
                     "startUtc": iso_utc(match.group(3)), "endUtc": iso_utc(match.group(4)) if match.group(4) else None,
                     "state": match.group(5).strip() or ("ended" if match.group(4) else "")})
    return rows


def journal(args, limit):
    rows = []
    out = run(["journalctl", "--no-pager", "-o", "json", "-n", str(limit)] + args, timeout=30).stdout
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, list):
            message = bytes(message).decode("utf-8", "replace")
        stamp = int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1e6
        rows.append({"timeUtc": datetime.datetime.utcfromtimestamp(stamp).isoformat() + "Z",
                     "source": entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "",
                     "priority": int(entry.get("PRIORITY", "6")), "message": str(message or "")[:500]})
    rows.reverse()
    return rows


def realm_state():
    if not have("realm"):
        return {"installed": False}
    realms = []
    current = None
    for line in run(["realm", "list"]).stdout.splitlines():
        if line and not line.startswith(" "):
            current = {"name": line.strip()}
            realms.append(current)
        elif current is not None and ":" in line:
            key, _, value = line.strip().partition(":")
            current[key.strip().replace("-", "_")] = value.strip()
    return {"installed": True, "realms": realms}


def info():
    sshd_ports = []
    if have("sshd"):
        for line in run(["sshd", "-T"]).stdout.splitlines():
            if line.startswith("port "):
                sshd_ports.append(int(line.split()[1]))
    emit({
        "ok": True,
        "helperVersion": 1,
        "firewall": firewall_state(),
        "accounts": accounts(),
        "failedLogins": wtmp(["lastb"], 100),
        "power": wtmp(["last", "-x", "reboot", "shutdown"], 30),
        "authEvents": journal(["--since", "-7d", "-t", "sshd", "-t", "sudo", "-t", "su", "-t", "login", "-t", "systemd-logind"], 300),
        "adminActions": journal(["--since", "-30d", "-t", "sudo", "-t", "uagent-sysadmin"], 150),
        "configChanges": journal(["--since", "-30d", "-t", "systemd-hostnamed", "-t", "firewalld", "-t", "realmd", "-t", "uagent-sysadmin", "-t", "dnf"], 150),
        "problems": journal(["--since", "-24h", "-p", "3"], 120),
        "ssh": dict(unit_state("sshd"), ports=sshd_ports or [22]),
        "xrdp": unit_state("xrdp"),
        "realm": realm_state(),
        "selinux": run(["getenforce"]).stdout.strip() or None,
        "backups": {"hostname": load("hostname.json"), "dns": [name for name in (os.listdir(STATE_DIR) if os.path.isdir(STATE_DIR) else []) if name.startswith("dns-")]}
    })


# --- Firewall -----------------------------------------------------------------------------------------

def protected_ports():
    env = portal_env()
    ports = set()
    for key, default in (("PORTAL_HTTP_PORT", "80"), ("PORTAL_HTTPS_PORT", "443")):
        value = env.get(key, default)
        if value.isdigit() and int(value) > 0:
            ports.add(int(value))
    for line in run(["sshd", "-T"]).stdout.splitlines() if have("sshd") else []:
        if line.startswith("port "):
            ports.add(int(line.split()[1]))
    return ports or {22}


def port_range(spec):
    match = PORT.match(spec)
    if not match:
        fail("The port must look like 8443/tcp or 5000-5100/udp.", field="port")
    low = int(match.group(1))
    high = int(match.group(2) or low)
    if not (1 <= low <= high <= 65535):
        fail("Ports are 1-65535.", field="port")
    return low, high, match.group(3)


def require_running():
    if run(["firewall-cmd", "--state"]).stdout.strip() != "running":
        fail("firewalld is not running. Turn the firewall on first.")


def require_zone(zone):
    if not ZONE.match(zone) or zone not in run(["firewall-cmd", "--get-zones"]).stdout.split():
        fail("Unknown firewall zone %s." % zone, field="zone")


def arm_revert(description):
    if revert_pending():
        fail("Another firewall change is waiting for confirmation. Confirm or revert it first.")
    run(["systemctl", "stop", REVERT_UNIT + ".timer"])
    run(["systemctl", "reset-failed", REVERT_UNIT + ".service", REVERT_UNIT + ".timer"])
    must(["systemd-run", "--unit=" + REVERT_UNIT, "--on-active=%d" % REVERT_SECONDS, "--timer-property=AccuracySec=1s",
          "/usr/bin/firewall-cmd", "--reload"], "Arming the automatic revert")
    save("firewall-pending.json", {"description": description, "armedUtc": now_utc(), "revertSeconds": REVERT_SECONDS})


def firewall(args):
    if not have("firewall-cmd"):
        fail("firewalld is not installed on this server.")
    if not args:
        fail("Name the firewall operation.")
    op = args[0]
    if op == "enable":
        must(["systemctl", "enable", "--now", "firewalld"], "Starting firewalld")
        time.sleep(1)
        zone = run(["firewall-cmd", "--get-default-zone"]).stdout.strip()
        added = []
        for port in sorted(protected_ports()):
            spec = "%d/tcp" % port
            if run(["firewall-cmd", "--zone=" + zone, "--query-port=" + spec]).stdout.strip() != "yes":
                named = {22: "ssh", 80: "http", 443: "https"}.get(port)
                if not (named and run(["firewall-cmd", "--zone=" + zone, "--query-service=" + named]).stdout.strip() == "yes"):
                    run(["firewall-cmd", "--zone=" + zone, "--add-port=" + spec])
                    run(["firewall-cmd", "--permanent", "--zone=" + zone, "--add-port=" + spec])
                    added.append(spec)
        audit("firewall enabled; kept open: %s" % (", ".join(added) or "already open"))
        emit({"ok": True, "message": "The firewall is on (zone %s)." % zone + (" Opened %s so SSH and the portal stay reachable." % ", ".join(added) if added else "")})
    if op == "disable":
        must(["systemctl", "disable", "--now", "firewalld"], "Stopping firewalld")
        run(["systemctl", "stop", REVERT_UNIT + ".timer"])
        audit("firewall disabled")
        emit({"ok": True, "message": "The firewall is off. Every listening port is reachable from the network."})
    if op == "confirm":
        pending = revert_pending()
        if not pending:
            fail("No firewall change is waiting for confirmation; it may already have been reverted.")
        run(["systemctl", "stop", REVERT_UNIT + ".timer"])
        must(["firewall-cmd", "--runtime-to-permanent"], "Saving the firewall configuration")
        os.remove(os.path.join(STATE_DIR, "firewall-pending.json"))
        audit("firewall change confirmed: %s" % pending.get("description"))
        emit({"ok": True, "message": "Kept: %s." % pending.get("description")})
    if op == "revert":
        run(["systemctl", "stop", REVERT_UNIT + ".timer"])
        must(["firewall-cmd", "--reload"], "Reverting the firewall")
        try:
            os.remove(os.path.join(STATE_DIR, "firewall-pending.json"))
        except OSError:
            pass
        audit("firewall runtime changes reverted")
        emit({"ok": True, "message": "The firewall is back to its saved configuration."})
    if op in ("port", "service") and len(args) == 4 and args[1] in ("add", "remove"):
        require_running()
        action, zone, value = args[1], args[2], args[3]
        require_zone(zone)
        if op == "port":
            low, high, proto = port_range(value)
            if action == "remove" and proto == "tcp" and any(low <= p <= high for p in protected_ports()):
                fail("%s carries SSH or the portal. Removing it would cut off administrative access." % value, field="port")
            flag = "--%s-port=%s" % (action, value)
        else:
            if not SERVICE.match(value) or value not in run(["firewall-cmd", "--get-services"]).stdout.split():
                fail("Unknown firewalld service %s." % value, field="service")
            if action == "remove":
                ports = set()
                for spec in run(["firewall-cmd", "--permanent", "--service=" + value, "--get-ports"]).stdout.split():
                    match = PORT.match(spec)
                    if match:
                        ports.update(range(int(match.group(1)), int(match.group(2) or match.group(1)) + 1))
                if ports & protected_ports():
                    fail("The %s service carries SSH or the portal. Removing it would cut off administrative access." % value, field="service")
            flag = "--%s-service=%s" % (action, value)
        description = "%s %s %s in zone %s" % ("Allow" if action == "add" else "Stop allowing", op, value, zone)
        arm_revert(description)
        result = run(["firewall-cmd", "--zone=" + zone, flag])
        if result.returncode != 0:
            run(["systemctl", "stop", REVERT_UNIT + ".timer"])
            run(["firewall-cmd", "--reload"])
            fail("firewall-cmd refused the change: %s" % (result.stderr or result.stdout).strip()[:400])
        audit("firewall runtime change (auto-revert in %ds): %s" % (REVERT_SECONDS, description))
        emit({"ok": True, "pending": True, "revertSeconds": REVERT_SECONDS,
              "message": "%s is active. It is undone in %d seconds unless it is confirmed." % (description, REVERT_SECONDS)})
    fail("Unknown firewall operation.")


# --- Services, power, hostname ------------------------------------------------------------------------

def service(args):
    if len(args) != 2 or args[0] not in ("start", "stop", "restart"):
        fail("Use: service start|stop|restart <unit>.")
    action, name = args
    if not UNIT.match(name):
        fail("That is not a valid unit name.", field="name")
    if not name.endswith(".service"):
        name += ".service"
    if run(["systemctl", "show", "-p", "LoadState", "--value", name]).stdout.strip() != "loaded":
        fail("%s is not installed." % name, field="name")
    if action != "start" and PROTECTED_UNITS.match(name) and not (action == "restart" and name in RESTARTABLE):
        fail("%s keeps the server reachable or managed and cannot be stopped from the portal." % name, field="name")
    result = run(["systemctl", action, name], timeout=120)
    state = run(["systemctl", "is-active", name]).stdout.strip()
    audit("service %s %s -> %s" % (action, name, state))
    if result.returncode != 0:
        fail("systemctl %s %s failed: %s" % (action, name, (result.stderr or "").strip()[:400]), state=state)
    emit({"ok": True, "state": state, "message": "%s is %s." % (name, state)})


def power(args):
    if len(args) != 1 or args[0] not in ("reboot", "poweroff", "cancel"):
        fail("Use: power reboot|poweroff|cancel.")
    if args[0] == "cancel":
        must(["shutdown", "-c", "uAgent portal: cancelled"], "Cancelling")
        audit("scheduled shutdown cancelled")
        emit({"ok": True, "message": "The scheduled restart or shutdown was cancelled."})
    flag = "-r" if args[0] == "reboot" else "-h"
    must(["shutdown", flag, "+1", "uAgent portal: %s requested by an administrator" % args[0]], "Scheduling")
    audit("%s scheduled in 1 minute" % args[0])
    emit({"ok": True, "message": "%s in 1 minute. Cancel it before then if needed." % ("Restarting" if args[0] == "reboot" else "Shutting down")})


def hostname(args):
    if args[:1] == ["restore"]:
        backup = load("hostname.json")
        if not backup:
            fail("No previous host name is recorded.")
        must(["hostnamectl", "set-hostname", backup["previous"]], "Restoring the host name")
        audit("hostname restored to %s" % backup["previous"])
        emit({"ok": True, "message": "The host name is %s again." % backup["previous"]})
    if len(args) != 2 or args[0] != "set":
        fail("Use: hostname set <name> | hostname restore.")
    name = args[1].lower()
    if not DNS_NAME.match(name) or name.replace(".", "").isdigit():
        fail("Use a host name or FQDN of letters, digits and hyphens, such as portal01.corp.example.com.", field="name")
    previous = run(["hostnamectl", "--static"]).stdout.strip() or run(["hostname"]).stdout.strip()
    save("hostname.json", {"previous": previous, "changedTo": name, "utc": now_utc()})
    must(["hostnamectl", "set-hostname", name], "Setting the host name")
    current = run(["hostnamectl", "--static"]).stdout.strip()
    if current != name:
        run(["hostnamectl", "set-hostname", previous])
        fail("The host name did not change (it reads %s); %s was restored." % (current, previous))
    audit("hostname %s -> %s" % (previous, name))
    env = portal_env()
    note = ""
    public = env.get("PUBLIC_HOST", "")
    if public and public != name:
        note = " Browsers and agents still use %s (PUBLIC_HOST); the certificate is unchanged." % public
    resolved = resolves(name)
    if "." in name:
        note += " %s %s in DNS." % (name, "resolves" if resolved else "does not resolve yet; add an A record (or an /etc/hosts entry) so other machines can reach it")
    emit({"ok": True, "previous": previous, "resolves": resolved, "message": "The host name is %s (was %s).%s" % (name, previous, note)})


# --- DNS ----------------------------------------------------------------------------------------------

def connection(uuid):
    if not UUID.match(uuid):
        fail("Choose the network connection.", field="connection")
    for line in run(["nmcli", "-t", "-f", "UUID,DEVICE,NAME", "connection", "show", "--active"]).stdout.splitlines():
        parts = line.split(":", 2)
        if parts[0] == uuid:
            return parts[1], parts[2] if len(parts) > 2 else uuid
    fail("That connection is not active.", field="connection")


def dns_values(uuid):
    keys = ["ipv4.dns", "ipv4.dns-search", "ipv4.ignore-auto-dns"]
    lines = run(["nmcli", "-g", ",".join(keys), "connection", "show", uuid]).stdout.split("\n")
    return {key: (lines[i].strip() if i < len(lines) else "") for i, key in enumerate(keys)}


def dns_apply(uuid, device, values):
    must(["nmcli", "connection", "modify", uuid, "ipv4.dns", values["ipv4.dns"].replace(",", " "),
          "ipv4.dns-search", values["ipv4.dns-search"].replace(",", " "), "ipv4.ignore-auto-dns", values["ipv4.ignore-auto-dns"] or "no"], "Updating the connection")
    # reapply changes DNS without taking the link down, so the session and agents stay connected.
    if run(["nmcli", "device", "reapply", device], timeout=30).returncode != 0:
        must(["nmcli", "connection", "up", uuid], "Activating the connection", timeout=60)


def resolves(name):
    return run(["getent", "ahosts", name], timeout=15).returncode == 0


def dns(args):
    if not have("nmcli"):
        fail("NetworkManager (nmcli) is not available, so DNS cannot be changed from the portal.")
    if args[:1] == ["restore"] and len(args) == 2:
        uuid = args[1]
        device, label = connection(uuid)
        backup = load("dns-%s.json" % uuid)
        if not backup:
            fail("No previous DNS settings are recorded for %s." % label)
        dns_apply(uuid, device, backup["values"])
        audit("dns restored on %s" % label)
        emit({"ok": True, "message": "DNS on %s is back to %s." % (label, backup["values"]["ipv4.dns"] or "automatic (DHCP)")})
    if len(args) < 3 or args[0] != "set":
        fail("Use: dns set <connection-uuid> <servers|dhcp> [--search a,b] [--test host].")
    uuid, servers = args[1], args[2]
    rest = args[3:]
    search = None
    test_host = ""
    while rest:
        if rest[0] == "--search" and len(rest) >= 2:
            search = rest[1]
            rest = rest[2:]
        elif rest[0] == "--test" and len(rest) >= 2:
            test_host = rest[1]
            rest = rest[2:]
        else:
            fail("Unexpected argument %s." % rest[0])
    device, label = connection(uuid)
    dhcp = servers.lower() == "dhcp"
    server_list = [] if dhcp else [s.strip() for s in servers.split(",") if s.strip()]
    if not dhcp and (not 1 <= len(server_list) <= 3 or not all(IPV4.match(s) or (":" in s and IPV6.match(s)) for s in server_list)):
        fail("Enter one to three DNS server addresses separated by commas, or dhcp.", field="servers")
    suffixes = None
    if search is not None:
        suffixes = [s.strip() for s in search.split(",") if s.strip()]
        if len(suffixes) > 6 or not all(DNS_NAME.match(s) for s in suffixes):
            fail("Search domains must be domain names separated by commas.", field="search")
    if test_host and not DNS_NAME.match(test_host):
        fail("The test name must be a DNS name.", field="test")
    previous = dns_values(uuid)
    save("dns-%s.json" % uuid, {"connection": label, "values": previous, "utc": now_utc()})
    values = dict(previous)
    values["ipv4.dns"] = ",".join(server_list)
    values["ipv4.ignore-auto-dns"] = "no" if dhcp else "yes"
    if suffixes is not None:
        values["ipv4.dns-search"] = ",".join(suffixes)
    dns_apply(uuid, device, values)
    time.sleep(2)
    probe = test_host or portal_env().get("PUBLIC_HOST", "")
    if probe and DNS_NAME.match(probe) and not IPV4.match(probe) and not resolves(probe):
        dns_apply(uuid, device, previous)
        audit("dns change on %s reverted: %s did not resolve" % (label, probe))
        fail("%s did not resolve with the new servers, so the previous DNS settings were restored." % probe)
    audit("dns on %s -> %s search %s" % (label, values["ipv4.dns"] or "dhcp", values["ipv4.dns-search"]))
    emit({"ok": True, "message": "DNS on %s is %s%s.%s" % (label, ", ".join(server_list) or "automatic (DHCP)",
                                                          "; search domains " + (", ".join(suffixes) or "none") if suffixes is not None else "",
                                                          " %s still resolves." % probe if probe else "")})


# --- Domain -------------------------------------------------------------------------------------------

def local_admin_available():
    for account in accounts():
        if account["admin"] and not account["locked"] and not account["noPassword"] and account["interactive"]:
            return True
    return False


def domain(args):
    if not have("realm"):
        fail("realmd is not installed. Install it with: dnf install realmd sssd adcli oddjob oddjob-mkhomedir samba-common-tools")
    if len(args) == 2 and args[0] == "discover":
        if not DOMAIN.match(args[1]):
            fail("Enter the domain's DNS name, for example corp.example.com.", field="domain")
        result = run(["realm", "discover", args[1]], timeout=60)
        if result.returncode != 0:
            fail("%s was not found: %s" % (args[1], (result.stderr or result.stdout).strip()[:400] or "check the DNS servers"), field="domain")
        emit({"ok": True, "message": result.stdout.strip()[:3000]})
    if len(args) >= 3 and args[0] == "join":
        name, user = args[1], args[2]
        if not DOMAIN.match(name):
            fail("Enter the domain's DNS name, for example corp.example.com.", field="domain")
        if not USER.match(user):
            fail("Enter the domain account allowed to join computers.", field="user")
        argv = ["realm", "join", "--verbose", "--user=" + user]
        if len(args) == 5 and args[3] == "--ou":
            if not OU.match(args[4]) or "DC=" not in args[4].upper():
                fail("The OU must be a distinguished name such as OU=Servers,DC=corp,DC=example,DC=com.", field="ou")
            argv.append("--computer-ou=" + args[4])
        elif len(args) != 3:
            fail("Unexpected arguments.")
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            fail("The domain password was not given.", field="secret")
        if not local_admin_available():
            fail("No local administrator with a password exists. Create one first so the server stays manageable if the domain is unreachable.")
        result = run(argv + [name], stdin=password + "\n", timeout=180)
        detail = (result.stderr + result.stdout).replace(password, "********").strip()
        password = None
        if result.returncode != 0:
            audit("domain join %s as %s failed" % (name, user))
            fail("Joining %s failed: %s" % (name, detail[-600:]))
        audit("joined domain %s as %s" % (name, user))
        emit({"ok": True, "message": "Joined %s. Domain users can sign in according to the realm's login policy." % name})
    if args == ["leave"]:
        if not local_admin_available():
            fail("No local administrator with a password exists. Leaving would leave no way to sign in.")
        result = run(["realm", "leave"], timeout=120)
        if result.returncode != 0:
            fail("Leaving the domain failed: %s" % (result.stderr or result.stdout).strip()[:400])
        audit("left the domain")
        emit({"ok": True, "message": "The server left the domain. Only local accounts can sign in."})
    fail("Use: domain discover <domain> | domain join <domain> <user> [--ou <ou>] | domain leave.")


def logs(args):
    sources = {
        "portal": ["-u", "uagent-portal"],
        "auth": ["-t", "sshd", "-t", "sudo", "-t", "su", "-t", "login", "-t", "systemd-logind"],
        "system": ["-p", "4"],
        "firewall": ["-u", "firewalld"],
        "admin": ["-t", "uagent-sysadmin", "-t", "sudo"]
    }
    if not args or args[0] not in sources:
        fail("Choose portal, auth, system, firewall or admin.", field="source")
    lines = 1000
    if len(args) > 1:
        if not args[1].isdigit() or not 1 <= int(args[1]) <= 10000:
            fail("Lines must be 1-10000.", field="lines")
        lines = int(args[1])
    out = run(["journalctl", "--no-pager", "-o", "short-iso", "-n", str(lines)] + sources[args[0]], timeout=60)
    emit({"ok": True, "text": out.stdout[-4 * 1024 * 1024:]})


COMMANDS = {"info": info, "firewall": firewall, "service": service, "power": power, "hostname": hostname,
            "dns": dns, "domain": domain, "logs": logs}
READ_ONLY = {"info", "logs"}


def main():
    if os.geteuid() != 0:
        fail("Run this as root.")
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail("Use one of: " + ", ".join(sorted(COMMANDS)))
    command = sys.argv[1]
    # The portal's unit has ProtectSystem=full. Changes run in a transient unit of their own, outside the
    # portal's sandbox and control group, so they can write /etc and survive a restart of the portal.
    if command not in READ_ONLY and os.environ.get("UAGENT_SYSADMIN_SCOPE") != "1" and have("systemd-run") and os.path.isdir("/run/systemd/system"):
        os.execv(shutil.which("systemd-run", path=CLEAN_ENV["PATH"]),
                 ["systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit=uagent-sysadmin-%d" % int(time.time() * 1000),
                  "--setenv=UAGENT_SYSADMIN_SCOPE=1", "--", os.path.realpath(sys.argv[0])] + sys.argv[1:])
    if command in READ_ONLY:
        COMMANDS[command]() if command == "info" else COMMANDS[command](sys.argv[2:])
    else:
        COMMANDS[command](sys.argv[2:])
    fail("No result.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as error:  # Report as JSON so the portal shows the cause rather than a traceback.
        fail("Unexpected error: %s" % error)
