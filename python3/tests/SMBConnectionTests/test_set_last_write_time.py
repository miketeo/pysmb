# -*- coding: utf-8 -*-

from nose2.tools.decorators import with_setup, with_teardown
from smb.SMBConnection import SMBConnection
from smb.smb_constants import *
from smb import smb_structs
from .util import getConnectionInfo

conn = None

def setup_func_SMB1():
    global conn
    smb_structs.SUPPORT_SMB2 = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def setup_func_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])

def teardown_func():
    global conn
    conn.close()


# FIXME: Disabled because setLastWriteTime is not implemented for SMB1
# @with_setup(setup_func_SMB1)
# @with_teardown(teardown_func)
# def test_setLastWriteTime_SMB1():
#     global conn
#     conn.setLastWriteTime('smbtest', 'rfc1001.txt', 1777000000)
#     result = conn.getAttributes('smbtest', 'rfc1001.txt')
#     assert result.last_write_time == 1777000000

@with_setup(setup_func_SMB2)
@with_teardown(teardown_func)
def test_setLastWriteTime_SMB2():
    global conn
    # Time: 2026-04-24 03:06:40 GMT
    conn.setLastWriteTime('smbtest', 'rfc1001.txt', 1777000000)
    result = conn.getAttributes('smbtest', 'rfc1001.txt')
    assert result.last_write_time == 1777000000
