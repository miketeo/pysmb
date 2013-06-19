# -*- coding: utf-8 -*-

import os, time, random
from StringIO import StringIO
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

class StoreFilesFactory(SMBProtocolFactory):
    """
    A super test factory that tests store file, list files, retrieve file and delete file functionlities in sequence.
    """

    TEST_FILENAME = os.path.join(os.path.dirname(__file__), os.pardir, 'SupportFiles', 'binary.dat')
    TEST_FILESIZE = 256000
    TEST_DIGEST = 'bb6303f76e29f354b6fdf6ef58587e48'

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.service_name = ''
        self.filename = ''

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def storeComplete(self, result):
        file_obj, filesize = result
        file_obj.close()
        assert filesize == self.TEST_FILESIZE

        d = self.listPath(self.service_name, os.path.dirname(self.filename.replace('/', os.sep)))
        d.addCallback(self.listComplete)
        d.addErrback(self.d.errback)

    def listComplete(self, entries):
        filenames = map(lambda e: e.filename, entries)
        assert os.path.basename(self.filename.replace('/', os.sep)) in filenames

        for entry in entries:
            if os.path.basename(self.filename.replace('/', os.sep)) == entry.filename:
                # The following asserts will fail if the remote machine's time is not in sync with the test machine's time
                assert abs(entry.create_time - time.time()) < 3
                assert abs(entry.last_access_time - time.time()) < 3
                assert abs(entry.last_write_time - time.time()) < 3
                assert abs(entry.last_attr_change_time - time.time()) < 3
                break

        d = self.retrieveFile(self.service_name, self.filename, StringIO())
        d.addCallback(self.retrieveComplete)
        d.addErrback(self.d.errback)

    def retrieveComplete(self, result):
        file_obj, file_attributes, file_size = result

        md = MD5()
        md.update(file_obj.getvalue())
        file_obj.close()

        assert file_size == self.TEST_FILESIZE
        assert md.hexdigest() == self.TEST_DIGEST

        d = self.deleteFiles(self.service_name, self.filename)
        d.addCallback(self.deleteComplete)
        d.addErrback(self.d.errback)

    def deleteComplete(self, result):
        d = self.listPath(self.service_name, os.path.dirname(self.filename.replace('/', os.sep)))
        d.addCallback(self.list2Complete)
        d.addErrback(self.d.errback)

    def list2Complete(self, entries):
        filenames = map(lambda e: e.filename, entries)
        assert os.path.basename(self.filename.replace('/', os.sep)) not in filenames
        self.d.callback(True)
        self.instance.transport.loseConnection()

    def onAuthOK(self):
        d = self.storeFile(self.service_name, self.filename, open(self.TEST_FILENAME, 'rb'))
        d.addCallback(self.storeComplete)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=30.0)
def test_store_long_filename_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = StoreFilesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.filename = os.sep + 'StoreTest %d-%d.dat' % ( time.time(), random.randint(0, 10000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_store_long_filename_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = StoreFilesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.filename = os.sep + 'StoreTest %d-%d.dat' % ( time.time(), random.randint(0, 10000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_store_unicode_filename_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = StoreFilesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.filename = os.sep + u'上载测试 %d-%d.dat' % ( time.time(), random.randint(0, 10000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_store_unicode_filename_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = StoreFilesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.filename = os.sep + u'上载测试 %d-%d.dat' % ( time.time(), random.randint(0, 10000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
