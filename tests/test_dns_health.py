import asyncio
import socket
import struct
import unittest
from unittest.mock import patch

from mole_pkg.config import Config
from mole_pkg.services.dns import DNSProtocol, DOTServer
from mole_pkg.validation_worker import probe_dns


def answer(query, *, negative=False):
    if negative:
        soa = b'\x02ns\x07example\x03com\0\x04host\x07example\x03com\0' + struct.pack('!IIIII', 1, 60, 60, 60, 60)
        return (query[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 1, 0) + query[12:] +
                b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 60, len(soa)) + soa)
    return (query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:] +
            b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x01\x01\x01\x01')


class ProbeReplies(unittest.TestCase):
    def test_unrelated_records_cannot_establish_health(self):
        for negative in (False, True):
            def unrelated(query):
                data = answer(query, negative=negative)
                return data[:len(query)] + b'\x05other\x03org\0' + data[len(query)+2:]
            with self.subTest(negative=negative):
                self.assertFalse(self.run_probe(unrelated)[0])

    def test_cname_data_is_validated_and_positive_owner_follows_the_chain(self):
        alias = b'\x05alias\x07example\x03com\0'
        def response(query, target):
            cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(target)) + target
            address = alias + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x01\x01\x01\x01'
            return query[:2] + struct.pack('!HHHHH', 0x8180, 1, 2, 0, 0) + query[12:] + cname + address
        self.assertTrue(self.run_probe(lambda q: response(q, alias))[0])
        for malformed in (b'\xff', b'\xc0\xff', alias + b'x'):
            with self.subTest(malformed=malformed):
                self.assertFalse(self.run_probe(lambda q: response(q, malformed))[0])

    def run_probe(self, response):
        queries = []

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def settimeout(self, value):
                self.timeout = value

            def connect(self, address):
                pass

            def send(self, query):
                queries.append(query)

            def recv(self, size):
                return response(queries[-1])

        with patch('mole_pkg.validation_worker.socket.socket', side_effect=lambda *a: Connection()):
            result = probe_dns(dict(servers=['127.0.0.1']))
        return result['dns_ready'], queries

    def test_each_question_has_a_fresh_name_not_only_a_fresh_id(self):
        _, first = self.run_probe(answer)
        _, second = self.run_probe(answer)
        self.assertNotEqual(first[0][12:], second[0][12:])
        self.assertTrue(first[0].endswith(b'\x07example\x03com\0\0\1\0\1'))

    def test_positive_and_authoritative_negative_responses_are_healthy(self):
        self.assertTrue(self.run_probe(answer)[0])
        self.assertTrue(self.run_probe(lambda q: answer(q, negative=True))[0])

    def test_invalid_replies_do_not_claim_health(self):
        cases = {
            'wrong_id': lambda q: b'xx' + answer(q)[2:],
            'wrong_question': lambda q: answer(q)[:13] + b'z' + answer(q)[14:],
            'truncated': lambda q: answer(q)[:2] + b'\x83' + answer(q)[3:],
            'servfail': lambda q: answer(q)[:3] + b'\x82' + answer(q)[4:],
            'header_only': lambda q: answer(q)[:12],
            'cut_record': lambda q: answer(q)[:-1],
            'trailing_bytes': lambda q: answer(q) + b'x',
            'empty_blocklist': lambda q: q[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + q[12:],
            'bad_soa': lambda q: answer(q, negative=True)[:-1],
            'pointer_cycle': lambda q: answer(q)[:len(q)] + b'\xc0' + bytes([len(q)]) + answer(q)[len(q)+2:],
        }
        for name, response in cases.items():
            with self.subTest(name=name):
                self.assertFalse(self.run_probe(response)[0])


class FreshResolverProbe(unittest.IsolatedAsyncioTestCase):
    async def test_warm_cache_cannot_hide_unresponsive_upstream(self):
        config = Config('/nonexistent')
        server = DOTServer(config, 'isolated-loopback')
        upstream_queries = []

        async def forward(query, xid):
            upstream_queries.append(query)
            return answer(query) if len(upstream_queries) == 1 else None

        server._forward = forward
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: DNSProtocol(server), local_addr=('127.0.0.1', 0))
        port = transport.get_extra_info('sockname')[1]
        try:
            loop = asyncio.get_running_loop()
            with patch.object(asyncio, 'to_thread', None, create=True):
                self.assertTrue((await loop.run_in_executor(None, probe_dns, dict(servers=['127.0.0.1'], port=port)))['dns_ready'])
                self.assertFalse((await loop.run_in_executor(None, probe_dns, dict(servers=['127.0.0.1'], port=port)))['dns_ready'])
            self.assertEqual(len(upstream_queries), 2)
        finally:
            transport.close()
            await server.stop()
