# -*- coding: utf-8 -*-

import os, random, time
from StringIO import StringIO
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class RenameFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.service = ''
        self.new_path = ''
        self.old_path = ''

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def pathCreated(self, result):
        d = self.listPath(self.service, os.path.dirname(self.old_path.replace('/', os.sep)))
        d.addCallback(self.listComplete)
        d.addErrback(self.d.errback)

    def listComplete(self, entries):
        filenames = map(lambda e: e.filename, entries)
        assert os.path.basename(self.old_path.replace('/', os.sep)) in filenames
        assert os.path.basename(self.new_path.replace('/', os.sep)) not in filenames

        d = self.rename(self.service, self.old_path, self.new_path)
        d.addCallback(self.renameComplete)
        d.addErrback(self.d.errback)

    def renameComplete(self, result):
        d = self.listPath(self.service, os.path.dirname(self.new_path.replace('/', os.sep)))
        d.addCallback(self.list2Complete)
        d.addErrback(self.d.errback)

    def list2Complete(self, entries):
        filenames = map(lambda e: e.filename, entries)
        assert os.path.basename(self.new_path.replace('/', os.sep)) in filenames
        assert os.path.basename(self.old_path.replace('/', os.sep)) not in filenames
        self.cleanup()

    def onAuthFailed(self):
        self.d.errback('Auth failed')


class RenameFileFactory(RenameFactory):

    def onAuthOK(self):
        d = self.storeFile(self.service, self.old_path, StringIO('Rename file test'))
        d.addCallback(self.pathCreated)
        d.addErrback(self.d.errback)

    def cleanup(self):
        d = self.deleteFiles(self.service, self.new_path)
        d.chainDeferred(self.d)


class RenameDirectoryFactory(RenameFactory):

    def onAuthOK(self):
        d = self.createDirectory(self.service, self.old_path)
        d.addCallback(self.pathCreated)
        d.addErrback(self.d.errback)

    def cleanup(self):
        d = self.deleteDirectory(self.service, self.new_path)
        d.chainDeferred(self.d)


@deferred(timeout=30.0)
def test_rename_english_file_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RenameFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_english_file_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RenameFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_unicode_file_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RenameFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_unicode_file_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RenameFileFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_english_directory_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RenameDirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = '/RenameTest %d-%d' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = '/RenameTest %d-%d' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_english_directory_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RenameDirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = '/RenameTest %d-%d' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = '/RenameTest %d-%d' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_unicode_directory_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = RenameDirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=30.0)
def test_rename_unicode_directory_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = RenameDirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service = 'smbtest'
    factory.old_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    factory.new_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
