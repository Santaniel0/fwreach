# Test fixtures

The snapshots here are synthetic hosts. No file was captured from a real
machine. The rules follow what upstream tools generate, and only the lines
needed for each scenario were copied.

## Upstream sources

| Material | Source | Revision | License |
|---|---|---|---|
| Docker's iptables rules for a published port (`nat` DOCKER/DNAT, `filter` DOCKER, DOCKER-FORWARD, DOCKER-BRIDGE, DOCKER-CT, `raw` PREROUTING direct-access drops) | github.com/moby/moby, `integration/network/bridge/iptablesdoc/generated/usernet-portmap.md` | commit 87fb52f6745d50f03f2d78bd19b3b4498342aae1 | Apache-2.0 |
| Docker's iptables rules for a port published on 127.0.0.1 (used by the loopback hint test) | same repo, `integration/network/bridge/iptablesdoc/generated/usernet-portmap-lo.md` | same commit | Apache-2.0 |
| Docker's native nftables ruleset (`ip docker-bridges` table) | same repo, `integration/network/bridge/nftablesdoc/generated/usernet-portmap.md` | same commit | Apache-2.0 |
| ufw chain layout, `before.rules` and `after.rules` content | git.launchpad.net/ufw, `conf/before.rules`, `conf/after.rules`, `src/ufw-init-functions` | tag 0.36.2 | GPL-3.0 |

Changes made to the upstream material:

- Interface names, subnets, container addresses and ports were changed to
  match each scenario (for example `bridge1`/`192.0.2.0/24` became
  `br-5c1e9a3f0b2d`/`172.18.0.0/16`).
- ufw's rule files are shown the way `iptables-save` prints them after
  ufw loads them: `-m tcp`/`-m udp` added, ICMP types numeric.
- The nftables rules were converted from `nft list ruleset` text to the
  `nft -j list ruleset` JSON schema described in libnftables-json(5).
  This conversion was done by hand. No real `nft -j` output was available
  while these fixtures were written.

## Scenarios

- `snapshots/ubuntu-ufw-docker`: Ubuntu with ufw (default deny incoming,
  `ufw deny 5432/tcp`) and a Compose project publishing Postgres on
  0.0.0.0:5432 through Docker's iptables backend.
- `snapshots/ubuntu-ufw-docker-fixed`: the same host plus exactly the
  DOCKER-USER rule that fwreach suggests for 5432.
- `expect.conf`: the expectations file used with both of them.
