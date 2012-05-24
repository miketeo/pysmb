
import os, sys, struct, types, logging, binascii, time
from StringIO import StringIO
from smb_structs import ProtocolError
from smb2_constants import *
from utils import convertFILETIMEtoEpoch


class SMB2Message:

    HEADER_STRUCT_FORMAT = "<4sHHIHHI"  # This refers to the common header part that is shared by both sync and async SMB2 header
    HEADER_STRUCT_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)

    ASYNC_HEADER_STRUCT_FORMAT = "<IQQQ16s"
    ASYNC_HEADER_STRUCT_SIZE = struct.calcsize(ASYNC_HEADER_STRUCT_FORMAT)

    SYNC_HEADER_STRUCT_FORMAT = "<IQIIQ16s"
    SYNC_HEADER_STRUCT_SIZE = struct.calcsize(SYNC_HEADER_STRUCT_FORMAT)

    HEADER_SIZE = 64

    log = logging.getLogger('SMB.SMB2Message')
    protocol = 2

    def __init__(self, payload = None):
        self.reset()
        if payload:
            self.payload = payload
            self.payload.initMessage(self)

    def __str__(self):
        b = StringIO()
        b.write('Command: 0x%02X (%s) %s' % ( self.command, SMB2_COMMAND_NAMES.get(self.command, '<unknown>'), os.linesep ))
        b.write('Status: 0x%08X %s' % ( self.status, os.linesep ))
        b.write('Flags: 0x%02X %s' % ( self.flags, os.linesep ))
        b.write('PID: %d %s' % ( self.pid, os.linesep ))
        b.write('MID: %d %s' % ( self.mid, os.linesep ))
        b.write('TID: %d %s' % ( self.tid, os.linesep ))
        b.write('Data: %d bytes %s%s %s' % ( len(self.data), os.linesep, binascii.hexlify(self.data), os.linesep ))
        return b.getvalue()

    def reset(self):
        self.raw_data = ''
        self.command = 0
        self.status = 0
        self.flags = 0

        self.next_command_offset = 0
        self.mid = 0
        self.session_id = 0
        self.signature = ''
        self.payload = None
        self.data = ''

        # For async SMB2 message
        self.async_id = 0

        # For sync SMB2 message
        self.pid = 0
        self.tid = 0

        # Not used in this class. Maintained for compatibility with SMBMessage class
        self.flags2 = 0
        self.uid = 0
        self.security = 0L
        self.parameters_data = ''

    def encode(self):
        """
        Encode this SMB2 message into a series of bytes suitable to be embedded with a NetBIOS session message.
        AssertionError will be raised if this SMB message has not been initialized with a Payload instance

        @return: a string containing the encoded SMB2 message
        """
        assert self.payload

        self.pid = os.getpid()
        self.payload.prepare(self)

        headers_data = struct.pack(self.HEADER_STRUCT_FORMAT,
                                   '\xFESMB', self.HEADER_SIZE, 0, self.status, self.command, 0, self.flags) + \
                       struct.pack(self.SYNC_HEADER_STRUCT_FORMAT, self.next_command_offset, self.mid, self.pid, self.tid, self.session_id, '\0'*16)
        return headers_data + self.data

    def decode(self, buf):
        """
        Decodes the SMB message in buf.
        All fields of the SMB2Message object will be reset to default values before decoding.
        On errors, do not assume that the fields will be reinstated back to what they are before
        this method is invoked.

        References
        ==========
        - [MS-SMB2]: 2.2.1

        @param buf: data containing one complete SMB2 message
        @type buf: string
        @return: a positive integer indicating the number of bytes used in buf to decode this SMB message
        @raise ProtocolError: raised when decoding fails
        """
        buf_len = len(buf)
        if buf_len < 64:  # All SMB2 headers must be at least 64 bytes. [MS-SMB2]: 2.2.1.1, 2.2.1.2
            raise ProtocolError('Not enough data to decode SMB2 header', buf)

        self.reset()

        protocol, struct_size, self.credit_charge, self.status, \
            self.command, self.credit_re, self.flags = struct.unpack(self.HEADER_STRUCT_FORMAT, buf[:self.HEADER_STRUCT_SIZE])

        if protocol != '\xFESMB':
            raise ProtocolError('Invalid 4-byte SMB2 protocol field', buf)

        if struct_size != self.HEADER_SIZE:
            raise ProtocolError('Invalid SMB2 header structure size')

        if self.isAsync:
            if buf_len < self.HEADER_STRUCT_SIZE+self.ASYNC_HEADER_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB2 header', buf)

            self.next_command_offset, self.mid, self.async_id, self.session_id, \
                self.signature = struct.unpack(self.ASYNC_HEADER_STRUCT_FORMAT,
                                               buf[self.HEADER_STRUCT_SIZE:self.HEADER_STRUCT_SIZE+self.ASYNC_HEADER_STRUCT_SIZE])
        else:
            if buf_len < self.HEADER_STRUCT_SIZE+self.SYNC_HEADER_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB2 header', buf)

            self.next_command_offset, self.mid, self.pid, self.tid, self.session_id, \
                self.signature = struct.unpack(self.SYNC_HEADER_STRUCT_FORMAT,
                                               buf[self.HEADER_STRUCT_SIZE:self.HEADER_STRUCT_SIZE+self.SYNC_HEADER_STRUCT_SIZE])

        if self.next_command_offset > 0:
            self.raw_data = buf[:self.next_command_offset]
            self.data = buf[self.HEADER_SIZE:self.next_command_offset]
        else:
            self.raw_data = buf
            self.data = buf[self.HEADER_SIZE:]

        self._decodeCommand()
        if self.payload:
            self.payload.decode(self)

        return len(self.raw_data)

    def _decodeCommand(self):
        if self.command == SMB2_COM_SESSION_SETUP:
            self.payload = SMB2SessionSetupResponse()
        elif self.command == SMB2_COM_NEGOTIATE:
            self.payload = SMB2NegotiateResponse()

    @property
    def isAsync(self):
        return bool(self.flags & SMB2_FLAGS_ASYNC_COMMAND)

    @property
    def isReply(self):
        return bool(self.flags & SMB2_FLAGS_SERVER_TO_REDIR)


class Structure:

    def initMessage(self, message):
        pass

    def prepare(self, message):
        raise NotImplementedError

    def decode(self, message):
        raise NotImplementedError


class SMB2NegotiateResponse(Structure):
    """
    Contains information on the SMB2_NEGOTIATE response from server

    After calling the decode method, each instance will contain the following attributes,
    - security_mode (integer)
    - dialect_revision (integer)
    - server_guid (string)
    - max_transact_size (integer)
    - max_read_size (integer)
    - max_write_size (integer)
    - system_time (long)
    - server_start_time (long)
    - security_blob (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.4
    """

    STRUCTURE_FORMAT = "<HHHH16sIIIIQQHHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_NEGOTIATE

        struct_size, self.security_mode, self.dialect_revision, _, self.server_guid, self.capabilities, \
        self.max_transact_size, self.max_read_size, self.max_write_size, self.system_time, self.server_start_time, \
        security_buf_offset, security_buf_len, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

        self.server_start_time = convertFILETIMEtoEpoch(self.server_start_time)
        self.system_time = convertFILETIMEtoEpoch(self.system_time)
        self.security_blob = message.raw_data[security_buf_offset:security_buf_offset+security_buf_len]


class SMB2SessionSetupRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.5
    """

    STRUCTURE_FORMAT = "<HBBIIHHQ"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, security_blob):
        self.security_blob = security_blob

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_SESSION_SETUP

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   25,   # Structure size. Must be 25 as mandated by [MS-SMB2] 2.2.5
                                   0,    # VcNumber
                                   0x01, # Security mode
                                   0x00, # Capabilities
                                   0,    # Channel
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,
                                   len(self.security_blob),
                                   0) + self.security_blob


class SMB2SessionSetupResponse(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.6
    """

    STRUCTURE_FORMAT = "<HHHH"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_SESSION_SETUP

        struct_size, self.session_flags, security_blob_offset, security_blob_len \
            = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

        self.security_blob = message.raw_data[security_blob_offset:security_blob_offset+security_blob_len]
