# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
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
def test_listPath():
    global conn
    results = conn.listPath('smbtest', '/')
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    assert ( u'\u6d4b\u8bd5\u6587\u4ef6\u5939', True ) in filenames  # Test non-English folder names
    assert ( u'Test Folder with Long Name', True ) in filenames      # Test long English folder names
    assert ( u'TestDir1', True ) in filenames                        # Test short English folder names
    assert ( u'Implementing CIFS - SMB.html', False ) in filenames   # Test long English file names
    assert ( u'rfc1001.txt', False ) in filenames                    # Test short English file names

@with_setup(setup_func, teardown_func)
def test_listSubPath():
    global conn
    results = conn.listPath('smbtest', '/Test Folder with Long Name/')
    filenames = map(lambda r: ( r.filename, r.isDirectory ), results)
    print filenames
    assert ( u'Test File.txt', False ) in filenames
    assert ( u'Test Folder', True ) in filenames
    assert ( u'子文件夹', True ) in filenames

