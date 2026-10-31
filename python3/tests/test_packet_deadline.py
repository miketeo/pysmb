import errno
import importlib
import unittest


connection_module = importlib.import_module('smb.SMBConnection')


class PacketDeadlineTests(unittest.TestCase):

    def setUp(self):
        self.now = 100.0
        self.waits = []
        self.events = []
        self.received = []
        self.conn = connection_module.SMBConnection('', '', 'client', 'server')
        self.conn.sock = self
        self.original_time = connection_module.time.time
        self.original_select = connection_module.select.select
        self.original_poll = getattr(connection_module.select, 'poll', None)
        connection_module.time.time = lambda: self.now
        connection_module.select.select = self.select
        connection_module.select.poll = lambda: self
        self.addCleanup(self.restore)

    def restore(self):
        self.conn.sock = None
        connection_module.time.time = self.original_time
        connection_module.select.select = self.original_select
        if self.original_poll is None:
            del connection_module.select.poll
        else:
            connection_module.select.poll = self.original_poll

    def fileno(self):
        return 42

    def register(self, *args):
        pass

    def recv(self, size):
        self.received.append(size)
        return self.chunk

    def wait(self, timeout):
        self.waits.append(timeout)
        delay, self.chunk = self.events.pop(0)
        if delay > timeout:
            self.now += timeout
            return []
        self.now += delay
        if isinstance(self.chunk, Exception):
            raise self.chunk
        return [42]

    def poll(self, milliseconds):
        return self.wait(milliseconds / 1000.0)

    def select(self, readers, writers, errors, timeout):
        return self.wait(timeout), [], []

    def reset(self, events):
        self.now = 100.0
        self.events = list(events)
        self.waits = []
        self.received = []

    def test_fragmented_read_uses_remaining_budget(self):
        for poller in (self, None):
            self.reset([(0.12, b'a'), (0.12, b'bcd')])
            self.assertRaises(connection_module.SMBTimeout,
                              self.conn._poll_for_data,
                              100.2, 4, b'', 0.2, poller)
            self.assertAlmostEqual(self.waits[1], 0.08, places=3)
            self.assertEqual(self.received, [4])

    def test_header_and_body_share_deadline(self):
        self.reset([(0.12, b'\x00\x00\x00\x01'), (0.12, b'x')])
        self.conn.feedData = lambda data: self.fail('expired packet delivered')
        self.assertRaises(connection_module.SMBTimeout,
                          self.conn._pollForNetBIOSPacket, 0.2)
        self.assertAlmostEqual(self.waits[1], 0.08, places=3)

    def test_interrupt_recomputes_remaining_budget(self):
        for poller in (self, None):
            self.reset([(0.12, connection_module.select.error(errno.EINTR, 'interrupted')),
                        (0.12, b'abcd')])
            self.assertRaises(connection_module.SMBTimeout,
                              self.conn._poll_for_data,
                              100.2, 4, b'', 0.2, poller)
            self.assertAlmostEqual(self.waits[1], 0.08, places=3)

    def test_complete_fragmented_packet_before_deadline(self):
        for poller in (self, None):
            self.reset([(0.05, b'a'), (0.05, b'bcd')])
            self.assertEqual(self.conn._poll_for_data(100.2, 4, b'', 0.2, poller),
                             (b'abcd', 0))

    def test_expired_deadline_does_not_wait(self):
        for poller in (self, None):
            self.reset([(0, b'abcd')])
            self.assertRaises(connection_module.SMBTimeout,
                              self.conn._poll_for_data,
                              100.0, 4, b'', 0.2, poller)
            self.assertEqual(self.waits, [])

    def test_poll_rounds_submillisecond_budget_up(self):
        self.reset([(0.0001, b'abcd')])
        self.assertEqual(self.conn._poll_for_data(100.0005, 4, b'', 0.2, self),
                         (b'abcd', 0))
        self.assertEqual(self.waits, [0.001])

    def test_readiness_after_deadline_does_not_read(self):
        for poller in (self, None):
            self.reset([])
            self.chunk = b'abcd'
            def late_wait(timeout):
                self.now = 100.21
                return [42]
            original_wait = self.wait
            self.wait = late_wait
            try:
                self.assertRaises(connection_module.SMBTimeout,
                                  self.conn._poll_for_data,
                                  100.2, 4, b'', 0.2, poller)
                self.assertEqual(self.received, [])
            finally:
                self.wait = original_wait

    def test_connection_closed_and_other_errors_propagate(self):
        for poller in (self, None):
            self.reset([(0.01, b'')])
            self.assertRaises(connection_module.NotConnectedError,
                              self.conn._poll_for_data,
                              100.2, 4, b'', 0.2, poller)
            self.reset([(0.01, connection_module.select.error(errno.EBADF, 'bad fd'))])
            self.assertRaises(connection_module.select.error,
                              self.conn._poll_for_data,
                              100.2, 4, b'', 0.2, poller)
