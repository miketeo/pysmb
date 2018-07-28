# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from smb.smb_constants import *
from .util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

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

@with_setup(setup_func_SMB1, teardown_func)
def test_listPathWithManyFiles_SMB1():
    global conn
    results = conn.listPath('smbtest', '/RFC Archive/')
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames))==999

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

@with_setup(setup_func_SMB2, teardown_func)
def test_listPathWithManyFiles_SMB2():
    global conn
    results = conn.listPath('smbtest', '/RFC Archive/')
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames))==999

@with_setup(setup_func_SMB1, teardown_func)
def test_listPathFilterForDirectory_SMB1():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', search = SMB_FILE_ATTRIBUTE_DIRECTORY)
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames)) > 0
    for f, isDirectory in filenames:
        assert isDirectory

@with_setup(setup_func_SMB2, teardown_func)
def test_listPathFilterForDirectory_SMB2():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', search = SMB_FILE_ATTRIBUTE_DIRECTORY)
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames)) > 0
    for f, isDirectory in filenames:
        assert isDirectory

@with_setup(setup_func_SMB1, teardown_func)
def test_listPathFilterForFiles_SMB1():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', search = SMB_FILE_ATTRIBUTE_READONLY | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_ARCHIVE | SMB_FILE_ATTRIBUTE_INCL_NORMAL)
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames)) > 0
    for f, isDirectory in filenames:
        assert not isDirectory

@with_setup(setup_func_SMB2, teardown_func)
def test_listPathFilterForFiles_SMB2():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', search = SMB_FILE_ATTRIBUTE_READONLY | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_ARCHIVE | SMB_FILE_ATTRIBUTE_INCL_NORMAL)
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert len(list(filenames)) > 0
    for f, isDirectory in filenames:
        assert not isDirectory


@with_setup(setup_func_SMB1, teardown_func)
def test_listPathFilterPattern_SMB1():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', pattern = 'Test*')
    filenames = list(map(lambda r: ( r.filename, r.isDirectory ), results))
    assert len(filenames) == 2
    assert ( u'Test File.txt', False ) in filenames
    assert ( u'Test Folder', True ) in filenames
    assert ( u'子文件夹', True ) not in filenames

@with_setup(setup_func_SMB2, teardown_func)
def test_listPathFilterPattern_SMB2():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', pattern = 'Test*')
    filenames = list(map(lambda r: ( r.filename, r.isDirectory ), results))
    assert len(filenames) == 2
    assert ( u'Test File.txt', False ) in filenames
    assert ( u'Test Folder', True ) in filenames
    assert ( u'子文件夹', True ) not in filenames

@with_setup(setup_func_SMB1, teardown_func)
def test_listPathFilterUnicodePattern_SMB1():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', pattern = u'*件夹')
    filenames = list(map(lambda r: ( r.filename, r.isDirectory ), results))
    assert len(filenames) == 1
    assert ( u'Test File.txt', False ) not in filenames
    assert ( u'Test Folder', True ) not in filenames
    assert ( u'子文件夹', True ) in filenames

@with_setup(setup_func_SMB2, teardown_func)
def test_listPathFilterUnicodePattern_SMB2():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name', pattern = u'*件夹')
    filenames = list(map(lambda r: ( r.filename, r.isDirectory ), results))
    assert len(filenames) == 1
    assert ( u'Test File.txt', False ) not in filenames
    assert ( u'Test Folder', True ) not in filenames
    assert ( u'子文件夹', True ) in filenames
