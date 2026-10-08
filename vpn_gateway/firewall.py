from __future__ import annotations

import ipaddress
import shlex

from .settings import Settings
from .system import Runner, SystemCommandError


class Firewall:
    """Own only BRAWL_* chains and brawl_active; never flush the host ruleset.

    Source leases expire in the kernel even when this service is down. IPv6 and
    packets addressed to the VDS itself are always denied on the VPN interface.
    """

    active_set = "brawl_active"
    out_chain = "BRAWL_OUT"
    in_chain = "BRAWL_IN"
    local_chain = "BRAWL_LOCAL"
    nat_chain = "BRAWL_NAT"
    hold_chain = "BRAWL_HOLD"
    ipv6_chain = "BRAWL6_BLOCK"

    def __init__(self, settings: Settings, runner: Runner):
        self.settings = settings
        self.runner = runner

    def command(self, *args: str, ipv6: bool = False, table: str = "filter") -> list[str]:
        return ["ip6tables" if ipv6 else "iptables", "-w", "5", "-t", table, *args]

    def ensure_chain(self, name: str, *, ipv6: bool = False, table: str = "filter") -> None:
        if not self.runner.succeeds(self.command("-S", name, ipv6=ipv6, table=table)):
            self.runner.run(self.command("-N", name, ipv6=ipv6, table=table))

    def ensure_rule(self, chain: str, rule: list[str], *, ipv6: bool = False, table: str = "filter", first: bool = False) -> None:
        if not self.runner.succeeds(self.command("-C", chain, *rule, ipv6=ipv6, table=table)):
            operation = ["-I", chain, "1"] if first else ["-A", chain]
            self.runner.run(self.command(*operation, *rule, ipv6=ipv6, table=table))

    def hook_first(self, chain: str, rule: list[str], *, ipv6: bool = False, table: str = "filter") -> None:
        # Install protection first; deleting the last old hook before insertion
        # leaves a dangerous crash window while restoring corrupted firewall state.
        self.runner.run(self.command("-I", chain, "1", *rule, ipv6=ipv6, table=table))
        actual = [line for line in self.runner.run(self.command("-S", chain, ipv6=ipv6, table=table)).splitlines() if line.startswith("-A ")]
        matching: list[int] = []
        expected = self.semantic_rule(rule)
        for index, line in enumerate(actual, start=1):
            try:
                if self.semantic_rule(shlex.split(line)[2:]) == expected:
                    matching.append(index)
            except SystemCommandError:
                # Unrelated host rules can have arbitrary extension options.
                continue
        if len(matching) > 100:
            raise SystemCommandError("Too many duplicate gateway firewall hooks")
        # Descending deletion retains the new leading rule and all unrelated rules.
        for index in reversed(matching):
            if index != 1:
                self.runner.run(self.command("-D", chain, str(index), ipv6=ipv6, table=table))

    def hold_rules(self) -> list[tuple[str, list[str]]]:
        iface = self.settings.interface
        return [("FORWARD", ["-i", iface, "-j", self.hold_chain]), ("FORWARD", ["-o", iface, "-j", self.hold_chain]), ("INPUT", ["-i", iface, "-j", self.hold_chain])]

    def quarantine(self) -> None:
        self.force_drop_chain(self.hold_chain)
        for chain, rule in self.hold_rules():
            self.hook_first(chain, rule)
        self.install_ipv6_block()

    def install_ipv6_block(self) -> None:
        self.force_drop_chain(self.ipv6_chain, ipv6=True)
        iface = self.settings.interface
        for chain, direction in (("FORWARD", "-i"), ("FORWARD", "-o"), ("INPUT", "-i")):
            self.hook_first(chain, [direction, iface, "-j", self.ipv6_chain], ipv6=True)

    def force_drop_chain(self, name: str, *, ipv6: bool = False) -> None:
        self.ensure_chain(name, ipv6=ipv6)
        rules = [line for line in self.runner.run(self.command("-S", name, ipv6=ipv6)).splitlines() if line.startswith("-A ")]
        if rules:
            # Replace atomically; never flush a live guard or append behind ACCEPT.
            self.runner.run(self.command("-R", name, "1", "-j", "DROP", ipv6=ipv6))
            for index in range(len(rules), 1, -1):
                self.runner.run(self.command("-D", name, str(index), ipv6=ipv6))
        else:
            self.runner.run(self.command("-A", name, "-j", "DROP", ipv6=ipv6))

    def rules(self) -> list[tuple[str, str, list[str]]]:
        s = self.settings
        rules: list[tuple[str, str, list[str]]] = []
        # Reply acceptance is limited to game source IPs and an active lease.
        for cidr in s.game_cidrs:
            rules.append(("filter", self.out_chain, ["-o", s.public_interface, "-s", str(s.client_subnet), "-d", str(cidr), "-m", "set", "--match-set", self.active_set, "src", "-j", "ACCEPT"]))
            rules.append(("filter", self.in_chain, ["-i", s.public_interface, "-s", str(cidr), "-d", str(s.client_subnet), "-m", "set", "--match-set", self.active_set, "dst", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]))
            rules.append(("nat", self.nat_chain, ["-s", str(s.client_subnet), "-d", str(cidr), "-o", s.public_interface, "-m", "set", "--match-set", self.active_set, "src", "-j", "MASQUERADE"]))
        rules.extend(("filter", chain, ["-j", "DROP"]) for chain in (self.out_chain, self.in_chain, self.local_chain))
        return rules

    def hooks(self) -> list[tuple[str, str, list[str]]]:
        iface = self.settings.interface
        return [("filter", "FORWARD", ["-i", iface, "-j", self.out_chain]), ("filter", "FORWARD", ["-o", iface, "-j", self.in_chain]), ("filter", "INPUT", ["-i", iface, "-j", self.local_chain]), ("nat", "POSTROUTING", ["-s", str(self.settings.client_subnet), "-j", self.nat_chain])]

    def install(self) -> None:
        self.quarantine()
        self.runner.run(["ipset", "create", self.active_set, "hash:ip", "family", "inet", "timeout", "86400", "-exist"])
        # A previous process might have died; only persisted valid leases return.
        self.runner.run(["ipset", "flush", self.active_set])
        for table, chain in (("filter", self.out_chain), ("filter", self.in_chain), ("filter", self.local_chain), ("nat", self.nat_chain)):
            self.ensure_chain(chain, table=table)
            self.runner.run(self.command("-F", chain, table=table))
        for table, chain, rule in self.rules():
            self.runner.run(self.command("-A", chain, *rule, table=table))
        for table, chain, rule in self.hooks():
            self.hook_first(chain, rule, table=table)

    def activate(self) -> None:
        for chain, rule in self.hold_rules():
            for _ in range(100):
                if not self.runner.succeeds(self.command("-C", chain, *rule)):
                    break
                self.runner.run(self.command("-D", chain, *rule))
            else:
                raise SystemCommandError("Too many duplicate quarantine rules")

    def verify(self) -> None:
        snapshots = {"filter": self.snapshot("iptables-save", "filter"), "nat": self.snapshot("iptables-save", "nat")}
        # Three snapshots replace hundreds of per-rule subprocesses, keeping
        # Telegram's ten-second precheckout deadline practical for larger lists.
        for table, chain in (("filter", self.out_chain), ("filter", self.in_chain), ("filter", self.local_chain), ("nat", self.nat_chain)):
            actual = snapshots[table].get(chain, [])
            expected = [self.semantic_rule(rule) for rule_table, owner, rule in self.rules() if table == rule_table and owner == chain]
            if actual != expected:
                raise SystemCommandError("Gateway managed chain changed")
        self.verify_hooks(snapshots)
        set_definition = self.runner.run(["ipset", "list", self.active_set, "-terse"])
        if "Type: hash:ip" not in set_definition or "Header: family inet " not in set_definition or " timeout " not in set_definition:
            raise SystemCommandError("Kernel expiry set is unavailable")

    @staticmethod
    def semantic_rule(tokens: list[str]) -> tuple[tuple[str, str], ...]:
        # iptables-save canonicalizes source/interface ordering and ctstate order.
        # All generated options are predicates joined with AND; sorting their
        # representations preserves meaning while rejecting unexpected options.
        pairs: list[tuple[str, str]] = []
        index = 0
        while index < len(tokens):
            option = tokens[index]
            if option not in {"-s", "-d", "-i", "-o", "-m", "-j", "--match-set", "--ctstate"}:
                raise SystemCommandError("Unsupported option in gateway-owned firewall rule")
            count = 2 if option == "--match-set" else 1
            values = tokens[index + 1:index + count + 1]
            if len(values) != count:
                raise SystemCommandError("Malformed gateway firewall rule")
            value = " ".join(values)
            if option in {"-s", "-d"}:
                value = str(ipaddress.ip_network(value, strict=False))
            elif option == "--ctstate":
                value = ",".join(sorted(value.split(",")))
            pairs.append((option, value))
            index += count + 1
        return tuple(sorted(pairs))

    def snapshot(self, binary: str, table: str) -> dict[str, list[tuple[tuple[str, str], ...]]]:
        output = self.runner.run([binary, "-t", table])
        relevant = {self.out_chain, self.in_chain, self.local_chain, self.nat_chain, self.ipv6_chain, "FORWARD", "INPUT", "POSTROUTING"}
        snapshots: dict[str, list[tuple[tuple[str, str], ...]]] = {}
        for line in output.splitlines():
            if not line.startswith("-A "):
                continue
            tokens = shlex.split(line)
            chain = tokens[1]
            if chain not in relevant:
                continue
            # Host chains can contain arbitrary unrelated options. Parse only the
            # leading gateway hooks; retain an opaque marker for other rules.
            if chain in {"FORWARD", "INPUT", "POSTROUTING"} and not any(name in tokens for name in (self.out_chain, self.in_chain, self.local_chain, self.nat_chain, self.ipv6_chain, self.hold_chain)):
                snapshots.setdefault(chain, []).append((("unrelated", line),))
            else:
                snapshots.setdefault(chain, []).append(self.semantic_rule(tokens[2:]))
        return snapshots

    def verify_hooks(self, snapshots: dict[str, dict[str, list[tuple[tuple[str, str], ...]]]]) -> None:
        # The first rules must guard VPN traffic before any unrelated host rule.
        for table, chain in (("filter", "FORWARD"), ("filter", "INPUT"), ("nat", "POSTROUTING")):
            actual = snapshots[table].get(chain, [])
            expected = [self.semantic_rule(rule) for rule_table, owner, rule in reversed(self.hooks()) if table == rule_table and owner == chain]
            if actual[:len(expected)] != expected:
                raise SystemCommandError("Gateway firewall hooks must precede host rules")
        iface = self.settings.interface
        ipv6 = self.snapshot("ip6tables-save", "filter")
        for chain in ("FORWARD", "INPUT"):
            actual = ipv6.get(chain, [])
            directions = ["-o", "-i"] if chain == "FORWARD" else ["-i"]
            expected = [self.semantic_rule([direction, iface, "-j", self.ipv6_chain]) for direction in directions]
            if actual[:len(expected)] != expected:
                raise SystemCommandError("Gateway IPv6 isolation is missing")
        if ipv6.get(self.ipv6_chain, []) != [self.semantic_rule(["-j", "DROP"])]:
            raise SystemCommandError("Gateway IPv6 block chain changed")

    def lease(self, address: str, timeout: int) -> None:
        if not isinstance(timeout, int) or timeout < 1:
            raise ValueError("Kernel lease timeout must be positive")
        if ipaddress.ip_address(address) not in self.settings.client_subnet:
            raise ValueError("Lease address must be inside the client subnet")
        self.runner.run(["ipset", "add", self.active_set, address, "timeout", str(min(timeout, 86400)), "-exist"])

    def revoke(self, address: str) -> None:
        self.runner.run(["ipset", "del", self.active_set, address, "-exist"])
