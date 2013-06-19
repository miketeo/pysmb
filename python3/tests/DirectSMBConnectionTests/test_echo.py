
import random
from smb.SMBConnection import SMBConnection
from .util import getConnectionInfo
from nose.tools import with_setup

conn = None

def setup_func():
    global conn
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def teardown_func():
    global conn
    conn.close()

@with_setup(setup_func, teardown_func)
def test_echo():
    global conn

    data = bytearray('%d' % random.randint(1000, 9999), 'ascii')
    assert conn.echo(data) == data
