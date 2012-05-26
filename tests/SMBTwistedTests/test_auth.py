
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class AuthFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def onAuthOK(self):
        self.d.callback(True)

    def onAuthFailed(self):
        self.d.callback(False)


@deferred(timeout=5.0)
def test_NTLMv1_auth_SMB1():
    def result(auth_passed):
        assert auth_passed

    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    factory = AuthFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = False)
    factory.d.addCallback(result)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d


@deferred(timeout=5.0)
def test_NTLMv2_auth_SMB1():
    def result(auth_passed):
        assert auth_passed

    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    factory = AuthFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.d.addCallback(result)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d


@deferred(timeout=5.0)
def test_NTLMv1_auth_SMB2():
    def result(auth_passed):
        assert auth_passed

    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    factory = AuthFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = False)
    factory.d.addCallback(result)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d


@deferred(timeout=5.0)
def test_NTLMv2_auth_SMB2():
    def result(auth_passed):
        assert auth_passed

    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    factory = AuthFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.d.addCallback(result)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
