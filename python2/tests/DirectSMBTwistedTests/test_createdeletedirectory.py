# -*- coding: utf-8 -*-

import os, random, time
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class DirectoryFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.service_name = ''
        self.path = ''

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def createDone(self, result):
        d = self.listPath(self.service_name, os.path.dirname(self.path.replace('/', os.sep)))
        d.addCallback(self.listComplete)
        d.addErrback(self.d.errback)

    def listComplete(self, entries):
        names = map(lambda e: e.filename, entries)
        assert os.path.basename(self.path.replace('/', os.sep)) in names

        d = self.deleteDirectory(self.service_name, self.path)
        d.addCallback(self.deleteDone)
        d.addErrback(self.d.errback)

    def deleteDone(self, result):
        d = self.listPath(self.service_name, os.path.dirname(self.path.replace('/', os.sep)))
        d.addCallback(self.list2Complete)
        d.addErrback(self.d.errback)

    def list2Complete(self, entries):
        names = map(lambda e: e.filename, entries)
        assert os.path.basename(self.path.replace('/', os.sep)) not in names
        self.d.callback(True)

    def onAuthOK(self):
        d = self.createDirectory(self.service_name, self.path)
        d.addCallback(self.createDone)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=15.0)
def test_english_directory_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = DirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = os.sep + 'TestDir %d-%d' % ( time.time(), random.randint(0, 1000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_english_directory_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = DirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = os.sep + 'TestDir %d-%d' % ( time.time(), random.randint(0, 1000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_unicode_directory_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = DirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = os.sep + u'文件夹创建 %d-%d' % ( time.time(), random.randint(0, 1000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_unicode_directory_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = DirectoryFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = os.sep + u'文件夹创建 %d-%d' % ( time.time(), random.randint(0, 1000) )
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
