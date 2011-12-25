
from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
from nose.tools import with_setup

conn = None

def teardown_func():
    global conn
    conn.close()

@with_setup(teardown = teardown_func)
def test_NTLMv1_auth():
    global conn
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = False)
    assert conn.connect(info['server_ip'], info['server_port'])

@with_setup(teardown = teardown_func)
def test_NTLMv2_auth():
    global conn
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])
