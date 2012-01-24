
import os, logging, select, socket, types, struct
from smb_constants import *
from smb_structs import *
from base import SMB, NotConnectedError, NotReadyError, SMBTimeout


class SMBConnection(SMB):

    log = logging.getLogger('SMB.SMBConnection')

    def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True):
        """
        Create a new SMBConnection instance.

        *username* and *password* are the user credentials required to authenticate the underlying SMB connection with the remote server.
        File operations can only be proceeded after the connection has been authenticated successfully.

        Note that you need to call *connect* method to actually establish the SMB connection to the remote server and perform authentication.

        :param string my_name: The local NetBIOS machine name that will identify where this connection is originating from.
                               You can freely choose a name as long as it contains a maximum of 15 alphanumeric characters and does not contain spaces and any of ``\/:*?";|+``
        :param string remote_name: The NetBIOS machine name of the remote server.
                                   On windows, you can find out the machine name by right-clicking on the "My Computer" and selecting "Properties".
                                   This parameter must be the same as what has been configured on the remote server, or else the connection will be rejected.
        :param string domain: The network domain. On windows, it is known as the workgroup. Usually, it is safe to leave this parameter as an empty string.
        :param boolean use_ntlm_v2: Indicates whether pysmb should be NTLMv1 or NTLMv2 authentication algorithm for authentication.
                                    The choice of NTLMv1 and NTLMv2 is configured on the remote server, and there is no mechanism to auto-detect which algorithm has been configured.
                                    Hence, we can only "guess" or try both algorithms.
                                    On Sambda, Windows Vista and Windows 7, NTLMv2 is enabled by default. On Windows XP, we can use NTLMv1 before NTLMv2.
        """
        SMB.__init__(self, username, password, my_name, remote_name, domain, use_ntlm_v2)
        self.sock = None
        self.auth_result = None
        self.is_busy = False

    #
    # SMB (and its superclass) Methods
    #

    def onAuthOK(self):
        self.auth_result = True

    def onAuthFailed(self):
        self.auth_result = False

    def write(self, data):
        assert self.sock
        data_len = len(data)
        assert self.sock.send(data) == data_len

    #
    # Public Methods
    #

    def connect(self, ip, port = 139, sock_family = socket.AF_INET, timeout = 60):
        """
        Establish the SMB connection to the remote SMB/CIFS server.

        You must call this method before attempting any of the file operations with the remote server.
        This method will block until the SMB connection has attempted at least one authentication.

        :return: A boolean value indicating the result of the authentication atttempt: True if authentication is successful; False, if otherwise.
        """
        if self.sock:
            self.sock.close()

        self.auth_result = None
        self.sock = socket.socket(sock_family)
        self.sock.connect_ex(( ip, port ))

        self.is_busy = True
        try:
            self.requestNMBSession()
            while self.auth_result is None:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return self.auth_result

    def close(self):
        """
        Terminate the SMB connection (if it has been started) and release any sources held by the underlying socket.
        """
        if self.sock:
            self.sock.close()
            self.sock = None

    def listShares(self, timeout = 30):
        """
        Retrieve a list of shared resources on remote server.

        :return: A list of :doc:`smb.base.SharedDevice<smb_SharedDevice>` instances describing the shared resource
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(entries):
            self.is_busy = False
            results.extend(entries)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._listShares(cb, eb, timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results

    def listPath(self, service_name, path,
                 search = SMB_FILE_ATTRIBUTE_READONLY | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_DIRECTORY | SMB_FILE_ATTRIBUTE_ARCHIVE,
                 pattern = '*', timeout = 30):
        """
        Retrieve a directory listing of files/folders at *path*

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: path relative to the *service_name* where we are interested to learn about its files/sub-folders.
        :param integer search: integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py).
                               The default *search* value will query for all read-only, hidden, system, archive files and directories.
        :param string/unicode pattern: the filter to apply to the results before returning to the client.
        :return: A list of :doc:`smb.base.SharedFile<smb_SharedFile>` instances.
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(entries):
            self.is_busy = False
            results.extend(entries)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._listPath(service_name, path, cb, eb, search = search, pattern = pattern, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results

    def retrieveFile(self, service_name, path, file_obj, timeout = 30):
        """
        Retrieve the contents of the file at *path* on the *service_name* and write these contents to the provided *file_obj*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be called in the returned *Deferred* errback.
        :param file_obj: A file-like object that has a *write* method. Data will be written continuously to *file_obj* until EOF is received from the remote service.
        :return: A 2-element tuple of ( file attributes of the file on server, number of bytes retrieved ).
                 The file attributes is an integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py)
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r[1:])

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._retrieveFile(service_name, path, file_obj, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def storeFile(self, service_name, path, file_obj, timeout = 30):
        """
        Store the contents of the *file_obj* at *path* on the *service_name*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file at *path* does not exist, it will be created. Otherwise, it will be overwritten.
                                    If the *path* refers to a folder or the file cannot be opened for writing, an :doc:`OperationFailure<smb_exceptions>` will be called in the returned *Deferred* errback.
        :param file_obj: A file-like object that has a *read* method. Data will read continuously from *file_obj* until EOF.
        :return: Number of bytes uploaded
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r[1])

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._storeFile(service_name, path, file_obj, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def deleteFiles(self, service_name, path_file_pattern, timeout = 30):
        """
        Delete one or more regular files. It supports the use of wildcards in file names, allowing for deletion of multiple files in a single request.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path_file_pattern: The pathname of the file(s) to be deleted, relative to the service_name.
                                                 Wildcards may be used in th filename component of the path.
                                                 If your path/filename contains non-English characters, you must pass in an unicode string.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._deleteFiles(service_name, path_file_pattern, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def createDirectory(self, service_name, path, timeout = 30):
        """
        Creates a new directory *path* on the *service_name*.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the new folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._createDirectory(service_name, path, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def deleteDirectory(self, service_name, path, timeout = 30):
        """
        Delete the empty folder at *path* on *service_name*

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the to-be-deleted folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._deleteDirectory(service_name, path, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def rename(self, service_name, old_path, new_path, timeout = 30):
        """
        Rename a file or folder at *old_path* to *new_path* shared at *service_name*. Note that this method cannot be used to rename file/folder across different shared folders

        *old_path* and *new_path* are string/unicode referring to the old and new path of the renamed resources (relative to) the shared folder.
        If the path contains non-English characters, an unicode string must be used to pass in the path.

        :param string/unicode service_name: Contains the name of the shared folder.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._rename(service_name, old_path, new_path, cb, eb)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def echo(self, data, timeout = 10):
        """
        Send an echo command containing *data* to the remote SMB/CIFS server. The remote SMB/CIFS will reply with the same *data*.

        :param string data: Data to send to the remote server.
        :return: The *data* parameter
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._echo(data, cb, eb)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    #
    # Protected Methods
    #

    def _pollForNetBIOSPacket(self, timeout):
        read_len = 4
        data = ''

        while read_len > 0:
            try:
                ready, _, _ = select.select([ self.sock.fileno() ], [ ], [ ], timeout)
                if not ready:
                    raise SMBTimeout

                d = self.sock.recv(read_len)
                data = data + d
                read_len -= len(d)
            except select.error, ex:
                if type(ex) is types.TupleType:
                    if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                        raise ex
                else:
                    raise ex

        type, flags, length = struct.unpack('>BBH', data)
        if flags & 0x01:
            length = length | 0x10000

        read_len = length
        while read_len > 0:
            try:
                ready, _, _ = select.select([ self.sock.fileno() ], [ ], [ ], timeout)
                if not ready:
                    raise SMBTimeout

                d = self.sock.recv(read_len)
                data = data + d
                read_len -= len(d)
            except select.error, ex:
                if type(ex) is types.TupleType:
                    if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                        raise ex
                else:
                    raise ex

        self.feedData(data)
