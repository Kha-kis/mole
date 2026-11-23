"""Pure approved-server ordering and physical endpoint cooldown."""

import math
import re


class ApprovedServerPolicy:
    def __init__(self, names: list, initial: str = '', cooldown: float = 900):
        if (not names or len(names) > 32 or len(set(names)) != len(names) or
                any(not re.fullmatch(r'[A-Z]{2}(?:-[A-Z0-9]+)*#[0-9]+', name) for name in names) or
                (initial and initial not in names) or not math.isfinite(cooldown) or cooldown < 900):
            raise ValueError('Failover requires unique approved server names, a member pin and cooldown >= 900')
        self.names = list(names)
        self.cooldown = cooldown
        self._cursor = self.names.index(initial) if initial else 0
        self._failed = {}
        self._resolved = []

    def candidates(self, servers: list, now: float) -> list:
        self._resolved = list(servers)
        ordered = self.names[self._cursor:] + self.names[:self._cursor]
        result, seen = [], set()
        for name in ordered:
            for server in servers:
                address = server.get('entry_ip')
                if server.get('name') == name and address and address not in seen and self._failed.get(address, -1) <= now:
                    seen.add(address)
                    result.append(server)
        return result

    def failed(self, entry_ip: str, now: float) -> None:
        self._failed[entry_ip] = now + self.cooldown
        for server in self._resolved:
            if server.get('entry_ip') == entry_ip and server.get('name') in self.names:
                self._cursor = (self.names.index(server['name']) + 1) % len(self.names)
                break

    def succeeded(self, entry_ip: str) -> None:
        self._failed.pop(entry_ip, None)
        for server in self._resolved:
            if server.get('entry_ip') == entry_ip and server.get('name') in self.names:
                self._cursor = self.names.index(server['name'])
                break
