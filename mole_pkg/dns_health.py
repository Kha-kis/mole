"""Bounded DNS reply validation for fresh resolver health questions."""

import struct


def _name(packet, offset):
    labels, visited = [], set()
    end = None
    length = 1
    while True:
        if offset < 12 or offset >= len(packet) or offset in visited:
            raise ValueError('invalid DNS name')
        visited.add(offset)
        size = packet[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('incomplete DNS pointer')
            target = ((size & 0x3f) << 8) | packet[offset + 1]
            if target >= offset:
                raise ValueError('forward DNS pointer')
            if end is None:
                end = offset + 2
            offset = target
            continue
        if size & 0xc0 or size > 63:
            raise ValueError('invalid DNS label')
        offset += 1
        if size == 0:
            return tuple(labels), end if end is not None else offset
        if offset + size > len(packet):
            raise ValueError('incomplete DNS label')
        length += size + 1
        if length > 255:
            raise ValueError('oversized DNS name')
        labels.append(packet[offset:offset + size].lower())
        offset += size


def healthy_reply(packet, query):
    try:
        if not 12 <= len(packet) <= 4096 or packet[:2] != query[:2]:
            return False
        flags, questions, answers, authorities, additional = struct.unpack('!HHHHH', packet[2:12])
        rcode = flags & 15
        if (flags & 0x8000 == 0 or flags & 0x7800 or flags & 0x0200 or
                rcode not in (0, 3) or questions != 1 or (rcode == 3 and answers)):
            return False
        expected, qend = _name(query, 12)
        actual, offset = _name(packet, 12)
        if actual != expected or packet[offset:offset + 4] != query[qend:qend + 4]:
            return False
        offset += 4
        addresses, aliases = set(), {}
        negative = False
        # Counts cannot force unbounded loops: every record needs at least 11 bytes.
        if answers + authorities + additional > len(packet) // 11:
            return False
        for section, count in enumerate((answers, authorities, additional)):
            for _ in range(count):
                owner, offset = _name(packet, offset)
                kind, klass, _, size = struct.unpack('!HHIH', packet[offset:offset + 10])
                start = offset + 10
                offset = start + size
                if offset > len(packet):
                    return False
                if klass == 1 and kind in (1, 28) and size != (4 if kind == 1 else 16):
                    return False
                if section == 0 and klass == 1 and kind == 1:
                    addresses.add(owner)
                if kind == 5:
                    target, end = _name(packet, start)
                    if end != offset:
                        return False
                    if section == 0 and klass == 1:
                        if owner in aliases and aliases[owner] != target:
                            return False
                        aliases[owner] = target
                if section == 1 and klass == 1 and kind == 6:
                    _, soa = _name(packet, start)
                    _, soa = _name(packet, soa)
                    if soa + 20 != offset:
                        return False
                    negative = negative or not owner or expected[-len(owner):] == owner
        reachable, current = set(), expected
        while current not in reachable:
            reachable.add(current)
            if current not in aliases:
                break
            if current in addresses:
                return False
            current = aliases[current]
        else:
            return False
        # Empty local blocklist NXDOMAIN replies contain no upstream SOA proof.
        return offset == len(packet) and (bool(addresses & reachable) or (answers == 0 and negative))
    except (ValueError, struct.error, IndexError):
        return False
