
from nmb.NetBIOS import NetBIOS
from nose.tools import with_setup

conn = None

def teardown_func():
    global conn
    conn.close()

@with_setup(teardown = teardown_func)
def test_broadcast():
    global conn
    conn = NetBIOS()
    assert conn.queryName('MICHAEL-I5PC', timeout = 10)

