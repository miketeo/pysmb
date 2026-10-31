import importlib
import unittest


connection_module = importlib.import_module('smb.SMBConnection')


class PacketDeadlineTests(unittest.TestCase):

    def setUp(self):
        self.now = 100.0
        self.waits = []
        self.events = []
        self.conn = connection_module.SMBConnection('', '', 'client', 'server')
        self.conn.sock = self
        self.original_time = connection_module.time.time
        self.original_select = connection_module.select.select
        connection_module.time.time = lambda: self.now
        connection_module.select.select = self.select
        self.conn.feedData = lambda data: self.delivered.append(data)
        self.delivered = []
        self.addCleanup(self.restore)

    def restore(self):
        self.conn.sock = None
        connection_module.time.time = self.original_time
        connection_module.select.select = self.original_select

    def fileno(self):
        return 42

    def recv(self, size):
        return self.chunk

    def select(self, readers, writers, errors, timeout):
        self.waits.append(timeout)
        delay, self.chunk = self.events.pop(0)
        if delay > timeout:
            self.now += timeout
            return [], [], []
        self.now += delay
        return [42], [], []

    def test_fragmented_header_uses_remaining_budget(self):
        self.events = [(0.12, '\x00'), (0.12, '\x00\x00\x00')]
        self.assertRaises(connection_module.SMBTimeout,
                          self.conn._pollForNetBIOSPacket, 0.2)
        self.assertAlmostEqual(self.waits[1], 0.08, places=3)
        self.assertEqual(self.delivered, [])

    def test_header_and_body_share_deadline(self):
        self.events = [(0.12, '\x00\x00\x00\x01'), (0.12, 'x')]
        self.assertRaises(connection_module.SMBTimeout,
                          self.conn._pollForNetBIOSPacket, 0.2)
        self.assertAlmostEqual(self.waits[1], 0.08, places=3)
        self.assertEqual(self.delivered, [])

    def test_complete_fragmented_packet_before_deadline(self):
        self.events = [(0.05, '\x00'), (0.05, '\x00\x00\x01'), (0.05, 'x')]
        self.conn._pollForNetBIOSPacket(0.2)
        self.assertEqual(self.delivered, ['\x00\x00\x00\x01x'])

    def test_expired_deadline_does_not_wait(self):
        self.assertRaises(connection_module.SMBTimeout,
                          self.conn._pollForNetBIOSPacket, 0)
        self.assertEqual(self.waits, [])
