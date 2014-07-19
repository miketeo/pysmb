# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

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
    
@with_setup(setup_func_SMB2, teardown_func)
def test_getAttributes_SMB2():
    global conn
    info = conn.getAttributes('smbtest', '/Test Folder with Long Name/')
    assert info.isDirectory
    
    info = conn.getAttributes('smbtest', '/rfc1001.txt')
    assert not info.isDirectory
    assert info.file_size == 158437
    assert info.alloc_size == 159744
    
    info = conn.getAttributes('smbtest', u'/\u6d4b\u8bd5\u6587\u4ef6\u5939')
    assert info.isDirectory
    
@with_setup(setup_func_SMB1, teardown_func)
def test_getAttributes_SMB1():
    global conn
    info = conn.getAttributes('smbtest', '/Test Folder with Long Name/')
    assert info.isDirectory
    
    info = conn.getAttributes('smbtest', '/rfc1001.txt')
    assert not info.isDirectory
    assert info.file_size == 158437
    assert info.alloc_size == 159744
    
    info = conn.getAttributes('smbtest', u'/\u6d4b\u8bd5\u6587\u4ef6\u5939')
    assert info.isDirectory
    
    