
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class ListSnapshotsFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.service_name = None
        self.path = None

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def onAuthOK(self):
        def cb(results):
            assert len(results) > 0
            self.d.callback(True)
            self.instance.transport.loseConnection()

        d = self.listSnapshots(self.service_name, self.path, timeout = 15)
        d.addCallback(cb)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=15.0)
def test_listshares_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = ListSnapshotsFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = '/rfc1001.txt'
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_listshares_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = ListSnapshotsFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    factory.service_name = 'smbtest'
    factory.path = '/rfc1001.txt'
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
