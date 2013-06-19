
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from smb.SMBProtocol import SMBProtocolFactory
from smb import smb_structs
from util import getConnectionInfo


class ListPathFactory(SMBProtocolFactory):

    def __init__(self, *args, **kwargs):
        SMBProtocolFactory.__init__(self, *args, **kwargs)
        self.d = defer.Deferred()
        self.d.addBoth(self.testDone)

    def testDone(self, r):
        if self.instance:
            self.instance.transport.loseConnection()
        return r

    def onAuthOK(self):
        def cb(results):
            filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
            assert ( u'\u6d4b\u8bd5\u6587\u4ef6\u5939', True ) in filenames  # Test non-English folder names
            assert ( u'Test Folder with Long Name', True ) in filenames      # Test long English folder names
            assert ( u'TestDir1', True ) in filenames                        # Test short English folder names
            assert ( u'Implementing CIFS - SMB.html', False ) in filenames   # Test long English file names
            assert ( u'rfc1001.txt', False ) in filenames                    # Test short English file names

            self.d.callback(True)

        d = self.listPath('smbtest', '/', timeout = 15)
        d.addCallback(cb)
        d.addErrback(self.d.errback)

    def onAuthFailed(self):
        self.d.errback('Auth failed')


@deferred(timeout=15.0)
def test_listPath_SMB1():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = False

    factory = ListPathFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d

@deferred(timeout=15.0)
def test_listPath_SMB2():
    info = getConnectionInfo()
    smb_structs.SUPPORT_SMB2 = True

    factory = ListPathFactory(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    reactor.connectTCP(info['server_ip'], info['server_port'], factory)
    return factory.d
