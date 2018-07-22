
from smb.SMBConnection import SMBConnection
from smb.smb2_constants import SMB2_DIALECT_2
from .util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

conn = None

def setup_func_SMB1():
    global conn
    smb_structs.SUPPORT_SMB2 = smb_structs.SUPPORT_SMB2x = False

    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def setup_func_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True
    smb_structs.SUPPORT_SMB2x = False

    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def setup_func_SMB2x():
    global conn
    smb_structs.SUPPORT_SMB2 = smb_structs.SUPPORT_SMB2x = True

    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def teardown_func():
    global conn
    conn.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_listsnapshots_SMB1():
    global conn
    results = conn.listSnapshots('smbtest', '/rfc1001.txt')
    assert len(results) > 0

@with_setup(setup_func_SMB2, teardown_func)
def test_listsnapshots_SMB2():
    global conn
    assert conn.smb2_dialect == SMB2_DIALECT_2
    results = conn.listSnapshots('smbtest', '/rfc1001.txt')
    assert len(results) > 0

@with_setup(setup_func_SMB2x, teardown_func)
def test_listsnapshots_SMB2x():
    global conn
    assert conn.smb2_dialect != SMB2_DIALECT_2
    results = conn.listSnapshots('smbtest', '/rfc1001.txt')
    assert len(results) > 0
