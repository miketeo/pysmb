# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from .util import getConnectionInfo
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

@with_setup(setup_func_SMB1, teardown_func)
def test_listPath_SMB1():
    global conn
    results = conn.listPath('smbtest', '/')
    filenames = [( r.filename, r.isDirectory ) for r in results]
    assert ( '\u6d4b\u8bd5\u6587\u4ef6\u5939', True ) in filenames  # Test non-English folder names
    assert ( 'Test Folder with Long Name', True ) in filenames      # Test long English folder names
    assert ( 'TestDir1', True ) in filenames                        # Test short English folder names
    assert ( 'Implementing CIFS - SMB.html', False ) in filenames   # Test long English file names
    assert ( 'rfc1001.txt', False ) in filenames                    # Test short English file names

@with_setup(setup_func_SMB1, teardown_func)
def test_listSubPath_SMB1():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name/')
    filenames = [( r.filename, r.isDirectory ) for r in results]
    assert ( 'Test File.txt', False ) in filenames
    assert ( 'Test Folder', True ) in filenames
    assert ( '子文件夹', True ) in filenames

@with_setup(setup_func_SMB2, teardown_func)
def test_listPath_SMB2():
    global conn
    results = conn.listPath('smbtest', '/')
    filenames = [( r.filename, r.isDirectory ) for r in results]
    assert ( '\u6d4b\u8bd5\u6587\u4ef6\u5939', True ) in filenames  # Test non-English folder names
    assert ( 'Test Folder with Long Name', True ) in filenames      # Test long English folder names
    assert ( 'TestDir1', True ) in filenames                        # Test short English folder names
    assert ( 'Implementing CIFS - SMB.html', False ) in filenames   # Test long English file names
    assert ( 'rfc1001.txt', False ) in filenames                    # Test short English file names

@with_setup(setup_func_SMB2, teardown_func)
def test_listSubPath_SMB2():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name/')
    filenames = [( r.filename, r.isDirectory ) for r in results]
    assert ( 'Test File.txt', False ) in filenames
    assert ( 'Test Folder', True ) in filenames
    assert ( '子文件夹', True ) in filenames
