# -*- coding: utf-8 -*-

import os, tempfile
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
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
        self.offset = 0
        self.max_length = -1
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

        d = self.retrieveFileFromOffset(self.service, self.path, self.temp_fh, self.offset, self.max_length, timeout = 15)
        d.addCallback(self.fileRetrieved)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=30.0)
def test_retr_multiplereads_SMB1():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/rfc1001.txt'
    factory.digest = '5367c2bbf97f521059c78eab65309ad3'
    factory.filesize = 158437
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_multiplereads_SMB2():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/rfc1001.txt'
    factory.digest = '5367c2bbf97f521059c78eab65309ad3'
    factory.filesize = 158437
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_longfilename_SMB1():
    # Test file retrieval that has a long English filename
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/Implementing CIFS - SMB.html'
    factory.digest = '671c5700d279fcbbf958c1bba3c2639e'
    factory.filesize = 421269
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_longfilename_SMB2():
    # Test file retrieval that has a long English filename
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = '/Implementing CIFS - SMB.html'
    factory.digest = '671c5700d279fcbbf958c1bba3c2639e'
    factory.filesize = 421269
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_unicodefilename_SMB1():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '8a44c1e80d55e91c92350955cdf83442'
    factory.filesize = 256000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_unicodefilename_SMB2():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '8a44c1e80d55e91c92350955cdf83442'
    factory.filesize = 256000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_SMB1():
    # Test file retrieval from offset to EOF
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = 'a141bd8024571ce7cb5c67f2b0d8ea0b'
    factory.filesize = 156000
    factory.offset = 100000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_SMB2():
    # Test file retrieval from offset to EOF
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = 'a141bd8024571ce7cb5c67f2b0d8ea0b'
    factory.filesize = 156000
    factory.offset = 100000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_biglimit_SMB1():
    # Test file retrieval from offset with a big max_length
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '83b7afd7c92cdece3975338b5ca0b1c5'
    factory.filesize = 100000
    factory.offset = 100000
    factory.max_length = 100000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_biglimit_SMB2():
    # Test file retrieval from offset with a big max_length
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '83b7afd7c92cdece3975338b5ca0b1c5'
    factory.filesize = 100000
    factory.offset = 100000
    factory.max_length = 100000
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_smalllimit_SMB1():
    # Test file retrieval from offset with a small max_length
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '746f60a96b39b712a7b6e17ddde19986'
    factory.filesize = 10
    factory.offset = 100000
    factory.max_length = 10
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_smalllimit_SMB2():
    # Test file retrieval from offset with a small max_length
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = '746f60a96b39b712a7b6e17ddde19986'
    factory.filesize = 10
    factory.offset = 100000
    factory.max_length = 10
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_zerolimit_SMB1():
    # Test file retrieval from offset to EOF with max_length=0
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = 'd41d8cd98f00b204e9800998ecf8427e'
    factory.filesize = 0
    factory.offset = 100000
    factory.max_length = 0
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_retr_offset_and_zerolimit_SMB2():
    # Test file retrieval from offset to EOF with max_length=0
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True
    
    factory = RetrieveFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.path = u'/测试文件夹/垃圾文件.dat'
    factory.digest = 'd41d8cd98f00b204e9800998ecf8427e'
    factory.filesize = 0
    factory.offset = 100000
    factory.max_length = 0
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
