
from nose2.tools.decorators import with_setup, with_teardown
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from .util import getConnectionInfo

conn = None

def setup_func_SMB1():
    global conn
    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True, is_direct_tcp = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def setup_func_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True, is_direct_tcp = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def teardown_func():
    global conn
    conn.close()

@with_setup(setup_func_SMB1)
@with_teardown(teardown_func)
def test_listshares_SMB1():
    global conn
    results = conn.listShares()
    assert 'smbtest' in [r.name.lower() for r in results]

@with_setup(setup_func_SMB2)
@with_teardown(teardown_func)
def test_listshares_SMB2():
    global conn
    results = conn.listShares()
    assert 'smbtest' in [r.name.lower() for r in results]
