"use strict";

// The server's own IPv4 addresses, in the order agents should be offered them: the configured PUBLIC_IP
// first, then physical interfaces, then container, bridge and VPN interfaces, which agents usually cannot
// reach.
const os = require("os");
const net = require("net");

const VIRTUAL = /^(docker|br-|veth|virbr|vmnet|vboxnet|utun|tun|tap|cni|flannel|cali|kube|podman|lxc|lxd|zt|tailscale|wg|vEthernet)/i;

function lanIpv4Addresses(preferred) {
  const physical = [];
  const virtual = [];
  let ifaces = {};
  try {
    ifaces = os.networkInterfaces();
  } catch (error) {
    ifaces = {};
  }
  for (const name of Object.keys(ifaces)) {
    for (const entry of ifaces[name] || []) {
      const ipv4 = entry.family === 4 || entry.family === "IPv4";
      if (!ipv4 || entry.internal || entry.address.startsWith("169.254.")) {
        continue;
      }
      (VIRTUAL.test(name) ? virtual : physical).push(entry.address);
    }
  }
  const ordered = [];
  const add = (ip) => {
    if (ip && net.isIP(ip) === 4 && !ordered.includes(ip)) {
      ordered.push(ip);
    }
  };
  add(preferred);
  physical.forEach(add);
  virtual.forEach(add);
  return ordered;
}

module.exports = { lanIpv4Addresses };
