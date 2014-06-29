
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class GetAttributesFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.path = ''
        self.is_directory = False

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def onAuthOK(self):
        def cb(info):
            assert info.isDirectory == self.is_directory
            self.d.callback(True)

        d = self.getAttributes('smbtest', self.path, timeout = 15)
        d.addCallback(cb)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=15.0)
def test_getAttributes_SMB1_test1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = '/Test Folder with Long Name/'
    factory.is_directory = True
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_getAttributes_SMB1_test2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = '/rfc1001.txt'
    factory.is_directory = False
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_getAttributes_SMB1_test3():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = u'/\u6d4b\u8bd5\u6587\u4ef6\u5939'
    factory.is_directory = True
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_getAttributes_SMB2_test1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = '/Test Folder with Long Name/'
    factory.is_directory = True
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_getAttributes_SMB2_test2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = '/rfc1001.txt'
    factory.is_directory = False
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_getAttributes_SMB2_test3():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = GetAttributesFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.path = u'/\u6d4b\u8bd5\u6587\u4ef6\u5939'
    factory.is_directory = True
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
