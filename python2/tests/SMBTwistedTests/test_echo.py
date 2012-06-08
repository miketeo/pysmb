
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from util import getConnectionInfo


class EchoFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)
        self.echo_data = 'This is an echo test'

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def onAuthOK(self):
        def cb(data):
            assert data == self.echo_data
            self.d.callback(True)

        d = self.echo(self.echo_data)
        d.addCallback(cb)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=15.0)
def test_echo():
    info = getConnectionInfo()
    factory = EchoFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
