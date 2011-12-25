# -*- coding: utf-8 -*-

import os, tempfile
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from util import getConnectionInfo

try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()


class RetrieveFileFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.temp_fh = tempfile.NamedTemporaryFile(prefix = 'pysmbtest-')
        self.service = ''
        self.path = ''
        self.digest = ''
        self.filesize = 0

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def fileRetrieved(self, write_result):
        file_obj, file_attributes, file_size = write_result
        assert file_obj == self.temp_fh

        md = MD5()
        filesize = 0
        self.temp_fh.seek(0)
        while True:
            s = self.temp_fh.read(8192)
            if not s:
                break
            md.update(s)
            filesize += len(s)

        assert self.filesize == filesize
        assert md.hexdigest() == self.digest

        self.temp_fh.close()
        self.d.callback(True)
        self.instance.transport.loseConnection()

    def onAuthOK(self):
        assert self.service
        assert self.path

        d = self.retrieveFile(self.service, self.path, self.temp_fh, timeout = 15)
        d.addCallback(self.fileRetrieved)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=30.0)
def test_retr_multiplereads():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    info = getConnectionInfo()
    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/rfc1001.txt'
    factory.digest = '5367c2bbf97f521059c78eab65309ad3'
    factory.filesize = 158437
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_longfilename():
    # Test file retrieval that has a long English filename
    info = getConnectionInfo()
    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/Implementing CIFS - SMB.html'
    factory.digest = '671c5700d279fcbbf958c1bba3c2639e'
    factory.filesize = 421269
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_unicodefilename():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    info = getConnectionInfo()
    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '8a44c1e80d55e91c92350955cdf83442'
    factory.filesize = 256000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
