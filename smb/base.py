
import logging, binascii, time
from smb_constants import *
from smb_structs import *
from nmb.base import NMBSession
from utils import convertFILETIMEtoEpoch
import ntlm, securityblob

class NotReadyError(Exception):
    """Raised when SMB connection is not ready (i.e. not authenticated or authentication failed)"""
    pass

class NotConnectedError(Exception):
    """Raised when underlying SMB connection has been disconnected or not connected yet"""
    pass

class SMBTimeout(Exception):
    """Raised when a timeout has occurred while waiting for a response or for a SMB/CIFS operation to complete."""
    pass


class SMB(NMBSession):
    """
    This class represents a "connection" to the remote SMB/CIFS server.
    It is not meant to be used directly in an application as it does not have any network transport implementations.

    For application use, please refer to
      - L{SMBProtocol.SMBProtocolFactory<smb.SMBProtocol>} if you are using Twisted framework

    In [MS-CIFS], this class will contain attributes of Client, Client.Connection and Client.Session abstract data models.

    References:
    ===========
      - [MS-CIFS]: 3.2.1
    """

    log = logging.getLogger('SMB.SMB')

    def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True):
        NMBSession.__init__(self, my_name, remote_name)
        self.username = username
        self.password = password
        self.domain = domain
        self.use_ntlm_v2 = use_ntlm_v2 #: Similar to LMAuthenticationPolicy and NTAuthenticationPolicy as described in [MS-CIFS] 3.2.1.1
        self.smb_message = SMBMessage()
        self.pending_requests = { }  #: MID mapped to _PendingRequest instance
        self.connected_trees = { }   #: Share name mapped to TID
        self.next_rpc_call_id = 0    #: Next RPC callID value. Not used directly in SMB message. Usually encapsulated in sub-commands under SMB_COM_TRANSACTION or SMB_COM_TRANSACTION2 messages

        self.has_negotiated = False
        self.has_authenticated = False
        self.mid = 0
        self.uid = 0

        # Most of the following attributes will be initialized upon receipt of SMB_COM_NEGOTIATE message from server (via self._updateServerInfo method)
        self.use_plaintext_authentication = False  #: Similar to PlaintextAuthenticationPolicy in in [MS-CIFS] 3.2.1.1
        self.max_raw_size = 0
        self.max_buffer_size = 0   #: Similar to MaxBufferSize as described in [MS-CIFS] 3.2.1.1
        self.max_mpx_count = 0     #: Similar to MaxMpxCount as described in [MS-CIFS] 3.2.1.1
        self.capabilities = 0

        self.log.info('Authetication with remote machine "%s" for user "%s" will be using NTLM %s authentication (%s extended security)',
                      self.remote_name, self.username,
                      (self.use_ntlm_v2 and 'v2') or 'v1',
                      (SUPPORT_EXTENDED_SECURITY and 'with') or 'without')


    #
    # NMBSession Methods
    #

    def onNMBSessionOK(self):
        self._sendSMBMessage(SMBMessage(ComNegotiateRequest()))

    def onNMBSessionFailed(self):
        pass

    def onNMBSessionMessage(self, flags, data):
        i = self.smb_message.decode(data)
        if i > 0:
            self.log.debug('Received SMB message "%s" (command:0x%2X flags:0x%02X flags2:0x%04X TID:%d UID:%d)',
                           SMB_COMMAND_NAMES.get(self.smb_message.command, '<unknown>'),
                           self.smb_message.command, self.smb_message.flags, self.smb_message.flags2, self.smb_message.tid, self.smb_message.uid)
            if self._updateState(self.smb_message):
                self.smb_message = SMBMessage()

    #
    # Public Methods for Overriding in Subclasses
    #

    def onAuthOK(self):
        pass

    def onAuthFailed(self):
        pass

    #
    # Protected Methods
    #

    def _sendSMBMessage(self, smb_message):
        if smb_message.mid == 0:
            smb_message.mid = self._getNextMID()
        smb_message.uid = self.uid
        smb_message.raw_data = smb_message.encode()
        self.sendNMBMessage(smb_message.raw_data)

    def _getNextMID(self):
        self.mid += 1
        if self.mid >= 0xFFFF: # MID cannot be 0xFFFF. [MS-CIFS]: 2.2.1.6.2
            # We don't use MID of 0 as MID can be reused for SMB_COM_TRANSACTION2_SECONDARY messages
            # where if mid=0, _sendSMBMessage will re-assign new MID values again
            self.mid = 1
        return self.mid

    def _getNextRPCCallID(self):
        self.next_rpc_call_id += 1
        return self.next_rpc_call_id

    def _updateState(self, message):
        if message.isReply:
            if message.command == SMB_COM_NEGOTIATE:
                self.has_negotiated = True
                self.log.info('SMB dialect negotiation successful (ExtendedSecurity:%s)', message.hasExtendedSecurity)
                self._updateServerInfo(message.payload)
                self._handleNegotiateResponse(message)
            elif message.command == SMB_COM_SESSION_SETUP_ANDX:
                if message.hasExtendedSecurity:
                    if not message.status.hasError:
                        try:
                            result = securityblob.decodeAuthResponseSecurityBlob(message.payload.security_blob)
                            if result == securityblob.RESULT_ACCEPT_COMPLETED:
                                self.has_authenticated = True
                                self.log.info('Authentication (with extended security) successful!')
                                self.onAuthOK()
                            else:
                                raise ProtocolError('SMB_COM_SESSION_SETUP_ANDX status is 0 but security blob negResult value is %d' % result, message.raw_data, message)
                        except securityblob.BadSecurityBlobError, ex:
                            raise ProtocolError(str(ex), message.raw_data, message)
                    elif message.status.internal_value == 0xc0000016:  # STATUS_MORE_PROCESSING_REQUIRED
                        try:
                            result, ntlm_token = securityblob.decodeChallengeSecurityBlob(message.payload.security_blob)
                            if result == securityblob.RESULT_ACCEPT_INCOMPLETE:
                                self._handleSessionChallenge(message, ntlm_token)
                        except ( securityblob.BadSecurityBlobError, securityblob.UnsupportedSecurityProvider ), ex:
                            raise ProtocolError(str(ex), message.raw_data, message)
                    elif message.status.internal_value == 0xc000006d:  # STATUS_LOGON_FAILURE
                        self.has_authenticated = False
                        self.log.info('Authentication (with extended security) failed. Please check username and password. You may need to enable/disable NTLMv2 authentication.')
                        self.onAuthFailed()
                    else:
                        raise ProtocolError('Unknown status value (0x%08X) in SMB_COM_SESSION_SETUP_ANDX (with extended security)' % message.status.internal_value,
                                            message.raw_data, message)
                else:
                    if message.status.internal_value == 0:
                        self.has_authenticated = True
                        self.log.info('Authentication (without extended security) successful!')
                        self.onAuthOK()
                    else:
                        self.has_authenticated = False
                        self.log.info('Authentication (without extended security) failed. Please check username and password')
                        self.onAuthFailed()
            elif message.command == SMB_COM_TREE_CONNECT_ANDX:
                try:
                    req = self.pending_requests[message.mid]
                except KeyError:
                    pass
                else:
                    if not message.status.hasError:
                        self.connected_trees[req.kwargs['path']] = message.tid

            req = self.pending_requests.pop(message.mid, None)
            if req:
                req.callback(message, **req.kwargs)
                return True


    def _updateServerInfo(self, payload):
        self.capabilities = payload.capabilities
        self.max_raw_size = payload.max_raw_size
        self.max_buffer_size = payload.max_buffer_size
        self.max_mpx_count = payload.max_mpx_count
        self.use_plaintext_authentication = not bool(payload.security_mode & NEGOTIATE_ENCRYPT_PASSWORDS)

        if self.use_plaintext_authentication:
            self.log.warning('Remote server only supports plaintext authentication. Your password can be stolen easily over the network.')

        if payload.security_mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRE:
            raise UnsupportedFeature('Remote server requires secure SMB message signing but current version pysmb does not support this yet.')


    def _handleSessionChallenge(self, message, ntlm_token):
        assert message.hasExtendedSecurity

        if message.uid and not self.uid:
            self.log.debug('SMB uid is now %d', message.uid)
            self.uid = message.uid

        server_challenge, server_flags, server_info = ntlm.decodeChallengeMessage(ntlm_token)
        if self.use_ntlm_v2:
            self.log.info('Performing NTLMv2 authentication (with extended security) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV2(self.password,
                                                                                                         self.username,
                                                                                                         server_challenge,
                                                                                                         server_info,
                                                                                                         self.domain)

        else:
            self.log.info('Performing NTLMv1 authentication (with extended security) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV1(self.password, server_challenge, True)

        ntlm_data = ntlm.generateAuthenticateMessage(server_flags,
                                                     nt_challenge_response,
                                                     lm_challenge_response,
                                                     session_key,
                                                     self.username)

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug('NT challenge response is "%s" (%d bytes)', binascii.hexlify(nt_challenge_response), len(nt_challenge_response))
            self.log.debug('LM challenge response is "%s" (%d bytes)', binascii.hexlify(lm_challenge_response), len(lm_challenge_response))

        blob = securityblob.generateAuthSecurityBlob(ntlm_data)
        self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__WithSecurityExtension(0, blob)))


    def _handleNegotiateResponse(self, message):
        if message.uid and not self.uid:
            self.log.debug('SMB uid is now %d', message.uid)
            self.uid = message.uid

        if message.hasExtendedSecurity:
            ntlm_data = ntlm.generateNegotiateMessage()
            blob = securityblob.generateNegotiateSecurityBlob(ntlm_data)
            self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__WithSecurityExtension(message.payload.session_key, blob)))
        else:
            nt_password, _, _ = ntlm.generateChallengeResponseV1(self.password, message.payload.challenge, False)
            self.log.info('Performing NTLMv1 authentication (without extended security) with challenge "%s" and hashed password of "%s"',
                          binascii.hexlify(message.payload.challenge),
                          binascii.hexlify(nt_password))
            self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__NoSecurityExtension(message.payload.session_key,
                                                                                           self.username,
                                                                                           nt_password,
                                                                                           True,
                                                                                           message.payload.domain)))

    def _listShares(self, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = 'IPC$'
        messages_history = [ ]

        def connectSrvSvc(tid):
            m = SMBMessage(ComNTCreateAndxRequest('\\srvsvc',
                                                  flags = NT_CREATE_REQUEST_EXTENDED_RESPONSE,
                                                  access_mask = READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_READ_DATA,
                                                  share_access = FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  create_disp = FILE_OPEN,
                                                  create_options = FILE_OPEN_NO_RECALL | FILE_NON_DIRECTORY_FILE,
                                                  impersonation = SEC_IMPERSONATE,
                                                  security_flags = 0))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectSrvSvcCB, errback)
            messages_history.append(m)

        def connectSrvSvcCB(create_message, **kwargs):
            messages_history.append(create_message)
            if not create_message.status.hasError:
                call_id = self._getNextRPCCallID()
                # See [MS-CIFS]: 2.2.5.6.1 for more information on TRANS_TRANSACT_NMPIPE (0x0026) parameters
                setup_bytes = struct.pack('<HH', 0x0026, create_message.payload.fid)
                # The data_bytes are binding call to Server Service RPC using DCE v1.1 RPC over SMB. See [MS-SRVS] and [C706]
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 0b 03 10 00 00 00 48 00 00 00""".replace(' ', '')) + \
                    struct.pack('<I', call_id) + \
                    binascii.unhexlify("""
b8 10 b8 10 00 00 00 00 01 00 00 00 00 00 01 00
c8 4f 32 4b 70 16 d3 01 12 78 5a 47 bf 6e e1 88
03 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00
2b 10 48 60 02 00 00 00""".replace(' ', '').replace('\n', ''))
                m = SMBMessage(ComTransactionRequest(max_params_count = 0,
                                                     max_data_count = 4280,
                                                     max_setup_count = 0,
                                                     data_bytes = data_bytes,
                                                     setup_bytes = setup_bytes))
                m.tid = create_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcBindCB, errback, fid = create_message.payload.fid)
                messages_history.append(m)
            else:
                errback(OperationFailure('Failed to list shares: Unable to locate Server Service RPC endpoint', messages_history))

        def rpcBindCB(trans_message, **kwargs):
            messages_history.append(trans_message)
            if not trans_message.status.hasError:
                call_id = self._getNextRPCCallID()

                padding = ''
                server_len = len(self.remote_name) + 1
                server_bytes_len = server_len * 2
                if server_len % 2 != 0:
                    padding = '\0\0'
                    server_bytes_len += 2

                # See [MS-CIFS]: 2.2.5.6.1 for more information on TRANS_TRANSACT_NMPIPE (0x0026) parameters
                setup_bytes = struct.pack('<HH', 0x0026, kwargs['fid'])
                # The data bytes are the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 00 03 10 00 00 00""".replace(' ', '')) + \
                    struct.pack('<HHI', 72+server_bytes_len, 0, call_id) + \
                    binascii.unhexlify("""4c 00 00 00 00 00 0f 00 00 00 02 00""".replace(' ', '')) + \
                    struct.pack('<III', server_len, 0, server_len) + \
                    (self.remote_name + '\0').encode('UTF-16LE') + padding + \
                    binascii.unhexlify("""
01 00 00 00 01 00 00 00 04 00 02 00 00 00 00 00
00 00 00 00 ff ff ff ff 08 00 02 00 00 00 00 00
""".replace(' ', '').replace('\n', ''))
                m = SMBMessage(ComTransactionRequest(max_params_count = 0,
                                                     max_data_count = 4280,
                                                     max_setup_count = 0,
                                                     data_bytes = data_bytes,
                                                     setup_bytes = setup_bytes))
                m.tid = trans_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(trans_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to bind to Server Service RPC endpoint', messages_history))

        def listShareResultsCB(result_message, **kwargs):
            messages_history.append(result_message)
            if not result_message.status.hasError:
                # The payload.data_bytes will contain the results of the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                data_bytes = result_message.payload.data_bytes
                shares_count = struct.unpack('<I', data_bytes[36:40])[0]

                results = [ ]     # A list of SharedDevice instances
                offset = 36 + 12  # You need to study the byte stream to understand the meaning of these constants
                for i in range(0, shares_count):
                    results.append(SharedDevice(struct.unpack('<I', data_bytes[offset+4:offset+8])[0], None, None))
                    offset += 12

                for i in range(0, shares_count):
                    max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                    offset += 12
                    results[i].name = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                    if length % 2 != 0:
                        offset += (length * 2 + 2)
                    else:
                        offset += (length * 2)

                    max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                    offset += 12
                    results[i].comments = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                    if length % 2 != 0:
                        offset += (length * 2 + 2)
                    else:
                        offset += (length * 2)

                closeFid(result_message.tid, kwargs['fid'])
                callback(results)
            else:
                closeFid(result_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(path):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    connectSrvSvc(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list shares: Unable to connect to IPC$', messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), path ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = path)
            messages_history.append(m)
        else:
            connectSrvSvc(self.connected_trees[path])

    def _listPath(self, service_name, path, callback, errback, search, pattern, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if not path.endswith('\\'):
            path += '\\'
        messages_history = [ ]
        results = [ ]

        def sendFindFirst(tid):
            setup_bytes = struct.pack('<H', 0x0001)  # TRANS2_FIND_FIRST2 sub-command. See [MS-CIFS]: 2.2.6.2.1
            params_bytes = \
                struct.pack('<HHHHI',
                            search, # SearchAttributes
                            100,    # SearchCount
                            0x0006, # Flags: SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
                            0x0104, # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                            0x0000) # SearchStorageType
            params_bytes += (path + pattern).encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                                  max_data_count = 16644,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findFirstCB, errback)
            messages_history.append(m)

        def decodeFindStruct(data_bytes):
            # SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure. See [MS-CIFS]: 2.2.8.1.7 and [MS-SMB]: 2.2.8.1.1
            info_format = '<IIQQQQQQIIIBB24s'
            info_size = struct.calcsize(info_format)

            data_length = len(data_bytes)
            offset = 0
            while offset < data_length:
                if offset + info_size > data_length:
                    return data_bytes[offset:]

                next_offset, _, \
                create_time, last_access_time, last_write_time, last_attr_change_time, \
                file_size, alloc_size, file_attributes, filename_length, ea_size, \
                short_name_length, _, short_name = struct.unpack(info_format, data_bytes[offset:offset+info_size])

                offset2 = offset + info_size
                if offset2 + filename_length > data_length:
                    return data_bytes[offset:]

                filename = data_bytes[offset2:offset2+filename_length].decode('UTF-16LE')
                short_name = short_name.decode('UTF-16LE')
                results.append(SharedFile(create_time, last_access_time, last_write_time, last_attr_change_time,
                                          file_size, alloc_size, file_attributes, short_name, filename))

                if next_offset:
                    offset += next_offset
                else:
                    break
            return ''

        def findFirstCB(find_message, **kwargs):
            messages_history.append(find_message)
            if not find_message.status.hasError:
                if not kwargs.has_key('total_count'):
                    # TRANS2_FIND_FIRST2 response. [MS-CIFS]: 2.2.6.2.2
                    sid, search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHHH', find_message.payload.params_bytes[:10])
                    kwargs.update({ 'sid': sid, 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
                else:
                    sid, end_of_search, last_name_offset = kwargs['sid'], kwargs['end_of_search'], kwargs['last_name_offset']

                send_next = True
                if find_message.payload.data_bytes:
                    d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                    if not kwargs.has_key('data_count'):
                        if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                            kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                            'total_count': find_message.payload.total_data_count,
                                            'data_buf': d,
                                            })
                            send_next = False
                    else:
                        kwargs['data_count'] += len(find_message.payload.data_bytes)
                        kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                        kwargs['data_buf'] = d
                        if kwargs['data_count'] != kwargs['total_count']:
                            send_next = False

                if not send_next:
                    self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findFirstCB, errback, **kwargs)
                elif end_of_search:
                    callback(results)
                else:
                    sendFindNext(find_message.tid, sid, last_name_offset)
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

        def sendFindNext(tid, sid, resume_key):
            setup_bytes = struct.pack('<H', 0x0002)  # TRANS2_FIND_NEXT2 sub-command. See [MS-CIFS]: 2.2.6.3.1
            params_bytes = \
                struct.pack('<HHHIH',
                            sid,        # SID
                            100,        # SearchCount
                            0x0104,     # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                            resume_key, # ResumeKey
                            0x000a)     # Flags: SMB_FIND_RETURN_RESUME_KEYS | SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
            params_bytes += pattern.encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                                  max_data_count = 16644,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findNextCB, errback, sid = sid)
            messages_history.append(m)

        def findNextCB(find_message, **kwargs):
            messages_history.append(find_message)
            if not find_message.status.hasError:
                if not kwargs.has_key('total_count'):
                    # TRANS2_FIND_NEXT2 response. [MS-CIFS]: 2.2.6.3.2
                    search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHH', find_message.payload.params_bytes[:8])
                    kwargs.update({ 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
                else:
                    end_of_search, last_name_offset = kwargs['end_of_search'], kwargs['last_name_offset']

                send_next = True
                if find_message.payload.data_bytes:
                    d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                    if not kwargs.has_key('data_count'):
                        if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                            kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                            'total_count': find_message.payload.total_data_count,
                                            'data_buf': d,
                                            })
                            send_next = False
                    else:
                        kwargs['data_count'] += len(find_message.payload.data_bytes)
                        kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                        kwargs['data_buf'] = d
                        if kwargs['data_count'] != kwargs['total_count']:
                            send_next = False

                if not send_next:
                    self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findNextCB, errback, **kwargs)
                elif end_of_search:
                    callback(results)
                else:
                    sendFindNext(find_message.tid, kwargs['sid'], last_name_offset)
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendFindFirst(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendFindFirst(self.connected_trees[service_name])

    def _retrieveFile(self, service_name, path, file_obj, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0040,  # Sharing mode: Deny nothing to others
                                              open_mode = 0x0001,    # Failed if file does not exist
                                              search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                sendRead(open_message.tid, open_message.payload.fid, 0L, open_message.payload.file_attributes)
            else:
                errback(OperationFailure('Failed to retrieve %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendRead(tid, fid, offset, file_attributes):
            read_count = self.max_raw_size - 2
            m = SMBMessage(ComReadAndxRequest(fid = fid,
                                              offset = offset,
                                              max_return_bytes_count = read_count,
                                              min_return_bytes_count = min(0xFFFF, read_count)))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback, fid = fid, offset = offset, file_attributes = file_attributes)

        def readCB(read_message, **kwargs):
            # To avoid crazy memory usage when retrieving large files, we do not save every read_message in messages_history.
            if not read_message.status.hasError:
                file_obj.write(read_message.payload.data)
                if read_message.payload.data_length < (self.max_raw_size - 2):
                    closeFid(read_message.tid, kwargs['fid'])
                    callback(( file_obj, kwargs['file_attributes'], kwargs['offset']+read_message.payload.data_length ))  # Note that this is a tuple of 3-elements
                else:
                    sendRead(read_message.tid, kwargs['fid'], kwargs['offset']+read_message.payload.data_length, kwargs['file_attributes'])
            else:
                messages_history.append(read_message)
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to retrieve %s on %s: Read failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to retrieve %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

    def _storeFile(self, service_name, path, file_obj, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0041,  # Sharing mode: Deny nothing to others + Open for writing
                                              open_mode = 0x0010,    # Create file if file does not exist
                                              search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                sendWrite(open_message.tid, open_message.payload.fid, 0L)
            else:
                errback(OperationFailure('Failed to store %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendWrite(tid, fid, offset):
            write_count = min(self.max_raw_size, 0xFFFF)
            data_bytes = file_obj.read(write_count)
            if data_bytes:
                m = SMBMessage(ComWriteAndxRequest(fid = fid, offset = offset, data_bytes = data_bytes))
                m.tid = tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, writeCB, errback, fid = fid, offset = offset+len(data_bytes))
            else:
                closeFid(tid, fid)
                callback(( file_obj, offset ))  # Note that this is a tuple of 2-elements

        def writeCB(write_message, **kwargs):
            # To avoid crazy memory usage when saving large files, we do not save every write_message in messages_history.
            if not write_message.status.hasError:
                sendWrite(write_message.tid, kwargs['fid'], kwargs['offset'])
            else:
                messages_history.append(write_message)
                closeFid(write_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to store %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

    def _deleteFiles(self, service_name, path_file_pattern, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path_file_pattern.replace('/', '\\')
        messages_history = [ ]

        def sendDelete(tid):
            m = SMBMessage(ComDeleteRequest(filename_pattern = path,
                                            search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if not delete_message.status.hasError:
                callback(path_file_pattern)
            else:
                errback(OperationFailure('Failed to store %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendDelete(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendDelete(self.connected_trees[service_name])

    def _createDirectory(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendCreate(tid):
            m = SMBMessage(ComCreateDirectoryRequest(path))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if not create_message.status.hasError:
                callback(path)
            else:
                errback(OperationFailure('Failed to create directory %s on %s: Create failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to create directory %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _deleteDirectory(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendDelete(tid):
            m = SMBMessage(ComDeleteDirectoryRequest(path))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if not delete_message.status.hasError:
                callback(path)
            else:
                errback(OperationFailure('Failed to delete directory %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendDelete(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendDelete(self.connected_trees[service_name])

    def _rename(self, service_name, old_path, new_path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        new_path = new_path.replace('/', '\\')
        old_path = old_path.replace('/', '\\')
        messages_history = [ ]

        def sendRename(tid):
            m = SMBMessage(ComRenameRequest(old_path = old_path,
                                            new_path = new_path,
                                            search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, renameCB, errback)
            messages_history.append(m)

        def renameCB(rename_message, **kwargs):
            messages_history.append(rename_message)
            if not rename_message.status.hasError:
                callback(( old_path, new_path ))  # Note that this is a tuple of 2-elements
            else:
                errback(OperationFailure('Failed to rename %s on %s: Rename failed' % ( old_path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    sendRename(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to rename %s on %s: Unable to connect to shared device' % ( old_path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendRename(self.connected_trees[service_name])

    def _echo(self, data, callback, errback, timeout = 30):
        messages_history = [ ]

        def echoCB(echo_message, **kwargs):
            messages_history.append(echo_message)
            if not echo_message.status.hasError:
                callback(echo_message.payload.data)
            else:
                errback(OperationFailure('Echo failed', messages_history))

        m = SMBMessage(ComEchoRequest(echo_data = data))
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, echoCB, errback)
        messages_history.append(m)


class SharedDevice:
    """
    Contains information about a single shared device on the remote server.
    """

    # The following constants are taken from [MS-SRVS]: 2.2.2.4
    # They are used to identify the type of shared resource from the results from the NetrShareEnum in Server Service RPC
    DISK_TREE   = 0x00
    PRINT_QUEUE = 0x01
    COMM_DEVICE = 0x02
    IPC         = 0x03

    def __init__(self, type, name, comments):
        self._type = type
        self.name = name         #: An unicode string containing the name of the shared device
        self.comments = comments #: An unicode string containing the user description of the shared device

    @property
    def type(self):
        """
        Returns one of the following integral constants.
         - SharedDevice.DISK_TREE
         - SharedDevice.PRINT_QUEUE
         - SharedDevice.COMM_DEVICE
         - SharedDevice.IPC
        """
        return self._type & 0xFFFF

    @property
    def isSpecial(self):
        """
        Returns True if this shared device is a special share reserved for interprocess communication (IPC$)
        or remote administration of the server (ADMIN$). Can also refer to administrative shares such as
        C$, D$, E$, and so forth
        """
        return bool(self._type & 0x80000000)

    @property
    def isTemporary(self):
        """
        Returns True if this is a temporary share that is not persisted for creation each time the file server initializes.
        """
        return bool(self._type & 0x40000000)

    def __unicode__(self):
        return u'Shared device: %s (type:0x%02x comments:%s)' % (self.name, self.type, self.comments )


class SharedFile:
    """
    Contain information about a file/folder entry that is shared on the shared device.

    As an application developer, you should not need to instantiate a *SharedFile* instance directly in your application.
    These *SharedFile* instances are usually returned via a call to *listPath* method in :doc:`smb.SMBProtocol.SMBProtocolFactory<smb_SMBProtocolFactory>`.

    If you encounter *SharedFile* instance where its short_name attribute is empty but the filename attribute contains a short name which does not correspond
    to any files/folders on your remote shared device, it could be that the original filename on the file/folder entry on the shared device contains
    one of these prohibited characters: "\/[]:+|<>=;?,* (see [MS-CIFS]: 2.2.1.1.1 for more details).
    """

    def __init__(self, create_time, last_access_time, last_write_time, last_attr_change_time, file_size, alloc_size, file_attributes, short_name, filename):
        self.create_time = create_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of creation of this file resource on the remote server
        self.last_access_time = last_access_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last access of this file resource on the remote server
        self.last_write_time = last_write_time    #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last modification of this file resource on the remote server
        self.last_attr_change_time = last_attr_change_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last attribute change of this file resource on the remote server
        self.file_size = file_size   #: File size in number of bytes
        self.alloc_size = alloc_size #: Total number of bytes allocated to store this file
        self.file_attributes = file_attributes #: A SMB_EXT_FILE_ATTR integer value. See [MS-CIFS]: 2.2.1.2.3
        self.short_name = short_name #: Unicode string containing the short name of this file (usually in 8.3 notation)
        self.filename = filename     #: Unicode string containing the long filename of this file. Each OS has a limit to the length of this file name. On Windows, it is 256 characters.

    @property
    def isDirectory(self):
        """A convenience property to return True if this file resource is a directory on the remote server"""
        return bool(self.file_attributes & ATTR_DIRECTORY)

    def __unicode__(self):
        return u'Shared file: %s (FileSize:%d bytes, isDirectory:%s)' % ( self.filename, self.file_size, self.isDirectory )


class _PendingRequest:

    def __init__(self, mid, expiry_time, callback, errback, **kwargs):
        self.mid = mid
        self.expiry_time = expiry_time
        self.callback = callback
        self.errback = errback
        self.kwargs = kwargs
