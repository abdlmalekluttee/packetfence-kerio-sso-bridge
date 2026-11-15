import copy
import unittest

from bridge.packetfence import PacketFence, SourceError
from tests.helpers import Clock


ROW = {'ip':'192.0.2.10', 'mac':'020000000001', 'user':'alice@example', 'updated':1000}


class Source(PacketFence):
    """Replace only the HTTPS exchange; exercise real queries, parsing and cache."""
    def __init__(self, clock):
        super().__init__({'host':'pf.invalid','username':'observer','password':'test',
                          'timezone':'UTC'}, clock=clock)
        self.calls = []
        self.bindings = [{'ip':'192.0.2.10','mac':'02:00:00:00:00:01',
                          'start_time':'1970-01-01 00:01:00','end_time':'0000-00-00 00:00:00'}]
        self.nodes = [{'mac':'02:00:00:00:00:01','pid':r'EXAMPLE\alice','status':'reg'}]
        self.failure = None
        self.extra = {}

    def _exchange(self, path, payload, token):
        self.calls.append((path, copy.deepcopy(payload)))
        if self.failure:
            raise self.failure
        if path == '/login':
            return {'token':'opaque'}
        values = self.bindings if path == '/ip4logs/search' else self.nodes
        return {'items':copy.deepcopy(values),'status':200, **self.extra}


def canonical(name):
    return name.replace('EXAMPLE\\', '').replace('@example', '').casefold()


class PacketFenceTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.pf = Source(self.clock)

    def test_full_identity_and_alias_confirm_current_binding(self):
        self.assertEqual(self.pf.check(ROW, canonical), 'current')
        self.assertEqual([p for p,_ in self.pf.calls], ['/login','/ip4logs/search','/nodes/search'])
        for _ in range(100):
            self.assertEqual(self.pf.check(ROW, canonical), 'current')
        self.assertEqual(len(self.pf.calls), 3)
        self.assertEqual(self.pf.calls[1][1]['query']['values'][0],
                         {'field':'ip','op':'equals','value':'192.0.2.10'})

    def test_ended_binding_is_stale_but_future_expiry_is_current(self):
        self.pf.bindings[0]['end_time'] = '1970-01-01 00:15:00'
        self.assertEqual(self.pf.check(ROW, canonical), 'stale')
        self.clock.advance(61)
        self.pf.bindings[0]['end_time'] = '1970-01-01 01:00:00'
        self.assertEqual(self.pf.check(ROW, canonical), 'current')

    def test_newer_mac_or_user_cannot_validate_old_identity(self):
        for field,value in [('mac','020000000099'),('user','bob@example')]:
            with self.subTest(field=field):
                self.assertEqual(self.pf.check({**ROW,field:value}, canonical), 'stale')

    def test_missing_ambiguous_and_malformed_data_are_unknown(self):
        variants = [([],self.pf.nodes), (self.pf.bindings*2,self.pf.nodes),
                    (self.pf.bindings,[]), (self.pf.bindings,self.pf.nodes*2),
                    ([{**self.pf.bindings[0],'end_time':'broken'}],self.pf.nodes)]
        for bindings,nodes in variants:
            with self.subTest(bindings=bindings,nodes=nodes):
                pf = Source(self.clock); pf.bindings=bindings;pf.nodes=nodes
                self.assertEqual(pf.check(ROW,canonical),'unknown')

    def test_truncated_results_and_api_outage_never_mean_stale(self):
        self.pf.extra={'nextCursor':100}
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')
        count=len(self.pf.calls)
        for _ in range(50):self.pf.check(ROW,canonical)
        self.assertEqual(len(self.pf.calls),count)
        self.clock.advance(61);self.pf.extra={};self.pf.failure=SourceError('unavailable')
        self.assertEqual(self.pf.check(ROW,canonical),'unknown')
        self.assertTrue(self.pf.error)

    def test_batch_reads_once_for_many_leases_and_expires(self):
        rows=[{**ROW,'ip':f'192.0.2.{i}'} for i in range(1,100)]
        self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),3)
        self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),3)
        self.clock.advance(61);self.pf.refresh(rows)
        self.assertEqual(len(self.pf.calls),5)

    def test_non_ipv4_or_missing_mac_is_unknown_without_network(self):
        for row in [{**ROW,'ip':'2001:db8::10'}, {**ROW,'mac':''}]:
            self.assertEqual(self.pf.check(row,canonical),'unknown')
        self.assertEqual(self.pf.calls,[])

    def test_bad_config_rejected(self):
        for change in [{'host':'https://pf.invalid/path'}, {'certificate_sha256':'bad'},
                       {'port':True}, {'username':''}, {'timezone':'invalid/timezone'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                PacketFence({'host':'pf.invalid','username':'observer','password':'test',**change})
