
from nmb.NetBIOS import NetBIOS
from nose2.tools.decorators import with_teardown

conn = None

def teardown_func():
    global conn
    conn.close()

@with_teardown(teardown_func)
def test_broadcast():
    global conn
    conn = NetBIOS()
    assert conn.queryName('MICHAEL-I5PC', timeout = 10)

