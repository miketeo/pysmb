"""SMB1 directory-search protocol fixtures; no remote server is required."""
import struct
import unittest

from smb.base import SMB
from smb.smb_constants import ATTR_DIRECTORY, ATTR_NORMAL, SMB_COM_TRANSACTION2
from smb.smb_structs import ComTransaction2Response, SMBMessage


class SearchConnection(SMB):
    def __init__(self):
        SMB.__init__(self, '', '', 'client', 'server')
        self.has_authenticated = True
        self.connected_trees['share'] = 7
        self.max_buffer_size = 65535
        self.sent = []
        self.completed = []
        self._sendSMBMessage = self.send

    def send(self, message):
        message.mid = len(self.sent) + 1
        # Exercise request encoding as well as inspecting its parameters.
        message.encode()
        self.sent.append(message)

    def fail(self, error):
        raise error

    def start(self, search=ATTR_DIRECTORY):
        self._listPath_SMB1('share', '/', self.completed.append,
                            self.fail, search, '*')

    def reply(self, data, first=False, end=False, total=None):
        request = self.sent[-1]
        pending = self.pending_requests.pop(request.mid)
        message = SMBMessage()
        message.mid, message.tid = request.mid, request.tid
        message.command = SMB_COM_TRANSACTION2
        message.payload = ComTransaction2Response()
        message.payload.params_bytes = (struct.pack('<HHHHH', 23, 1, end, 0, 0)
                                        if first else struct.pack('<HHHH', 1, end, 0, 0))
        message.payload.data_bytes = data
        message.payload.total_data_count = len(data) if total is None else total
        pending.callback(message, **pending.kwargs)

    def resume(self):
        request = self.sent[-1].payload
        assert request.setup_bytes == struct.pack('<H', 2)
        sid, count, level, key, flags = struct.unpack('<HHHIH', request.params_bytes[:12])
        assert (sid, count, level, flags) == (23, 100, 0x104, 6)
        return key, request.params_bytes[12:].decode('utf-16le').rstrip('\0')


def entries(*items):
    chunks = []
    for pos, (key, name, attrs) in enumerate(items):
        filename = name.encode('utf-16le')
        length = struct.calcsize('<IIQQQQQQIIIBB24s') + len(filename)
        next_offset = (length + 7) & ~7 if pos < len(items) - 1 else 0
        chunk = struct.pack('<IIQQQQQQIIIBB24s', next_offset, key,
                            0, 0, 0, 0, 0, 0, attrs, len(filename), 0, 0, 0, b'') + filename
        chunks.append(chunk.ljust(next_offset, b'\0') if next_offset else chunk)
    return b''.join(chunks)


class SMB1SearchResumeTests(unittest.TestCase):
    def test_first_and_later_pages_echo_server_keys(self):
        conn = SearchConnection()
        conn.start()
        conn.reply(entries((0xF1234567, 'first', ATTR_DIRECTORY)), first=True)
        self.assertEqual(conn.resume(), (0xF1234567, 'first'))
        conn.reply(entries((73, 'second', ATTR_DIRECTORY)))
        self.assertEqual(conn.resume(), (73, 'second'))
        conn.reply(entries((99, 'last', ATTR_DIRECTORY)), end=True)
        self.assertEqual([f.filename for f in conn.completed[0]], ['first', 'second', 'last'])
        self.assertEqual(len(conn.sent), 3)

    def test_resume_after_filtered_trailing_entries(self):
        conn = SearchConnection()
        conn.start()
        conn.reply(entries((10, 'directory', ATTR_DIRECTORY),
                           (20, 'filtered.txt', ATTR_NORMAL)), first=True)
        self.assertEqual(conn.resume(), (20, 'filtered.txt'))
        conn.reply(entries((30, 'next-directory', ATTR_DIRECTORY),
                           (40, 'another.txt', ATTR_NORMAL)))
        self.assertEqual(conn.resume(), (40, 'another.txt'))
        conn.reply(b'', end=True)
        self.assertEqual([f.filename for f in conn.completed[0]], ['directory', 'next-directory'])

    def test_whole_filtered_first_and_later_pages(self):
        conn = SearchConnection()
        conn.start()
        conn.reply(entries((1, 'filtered.txt', ATTR_NORMAL)), first=True)
        self.assertEqual(conn.resume(), (1, 'filtered.txt'))
        conn.reply(entries((2, 'also-filtered.txt', ATTR_NORMAL)))
        self.assertEqual(conn.resume(), (2, 'also-filtered.txt'))
        conn.reply(entries((3, 'directory', ATTR_DIRECTORY)), end=True)
        self.assertEqual([f.filename for f in conn.completed[0]], ['directory'])

    def test_fragmented_entries_resume_only_after_complete_transaction(self):
        conn = SearchConnection()
        conn.start()
        for first, key, name in [(True, 52, u'caf\u00e9.txt'), (False, 81, 'other.txt')]:
            data = entries((key, name, ATTR_NORMAL))
            before = len(conn.sent)
            split = len(data) - 3  # Split inside the UTF-16 filename.
            conn.reply(data[:split], first=first, total=len(data))
            self.assertEqual(len(conn.sent), before)
            conn.reply(data[split:], total=len(data))
            self.assertEqual(conn.resume(), (key, name))
        conn.reply(b'', end=True)
        self.assertEqual(conn.completed, [[]])

    def test_single_final_page_needs_no_resume(self):
        conn = SearchConnection()
        conn.start()
        conn.reply(entries((1, 'filtered.txt', ATTR_NORMAL)), first=True, end=True)
        self.assertEqual(conn.completed, [[]])
        self.assertEqual(len(conn.sent), 1)
