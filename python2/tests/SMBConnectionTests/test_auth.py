
from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

conn, conn2, conn3 = None, None, None

def teardown_func():
    global conn, conn2, conn3
    if conn:
        conn.close()
    if conn2:
        conn2.close()
    if conn3:
        conn3.close();

@with_setup(teardown = teardown_func)
def test_NTLMv1_auth_SMB1():
    global conn
    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], domain = info['domain'], use_ntlm_v2 = False)
    assert conn.connect(info['server_ip'], info['server_port'])

    conn2 = SMBConnection(info['user'], 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = False)
    assert not conn2.connect(info['server_ip'], info['server_port'])

    conn3 = SMBConnection('INVALIDUSER', 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = False)
    assert not conn3.connect(info['server_ip'], info['server_port'])

@with_setup(teardown = teardown_func)
def test_NTLMv2_auth_SMB1():
    global conn
    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], domain = info['domain'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

    conn2 = SMBConnection(info['user'], 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert not conn2.connect(info['server_ip'], info['server_port'])

    conn3 = SMBConnection('INVALIDUSER', 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert not conn3.connect(info['server_ip'], info['server_port'])

@with_setup(teardown = teardown_func)
def test_NTLMv1_auth_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], domain = info['domain'], use_ntlm_v2 = False)
    assert conn.connect(info['server_ip'], info['server_port'])

    conn2 = SMBConnection(info['user'], 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = False)
    assert not conn2.connect(info['server_ip'], info['server_port'])

    conn3 = SMBConnection('INVALIDUSER', 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = False)
    assert not conn3.connect(info['server_ip'], info['server_port'])

@with_setup(teardown = teardown_func)
def test_NTLMv2_auth_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], domain = info['domain'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

    conn2 = SMBConnection(info['user'], 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert not conn2.connect(info['server_ip'], info['server_port'])

    conn3 = SMBConnection('INVALIDUSER', 'wrongPass', info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert not conn3.connect(info['server_ip'], info['server_port'])
