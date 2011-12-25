
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from nmb.NetBIOSProtocol import NBNSProtocol
from nose.tools import with_setup


@deferred(timeout=15.0)
def test_broadcast():
    def cb(results):
        assert results

    def cleanup(r):
        p.transport.stopListening()

    p = NBNSProtocol()
    d = p.queryName('MICHAEL-I5PC', timeout = 10)
    d.addCallback(cb)
    d.addBoth(cleanup)

    return d
