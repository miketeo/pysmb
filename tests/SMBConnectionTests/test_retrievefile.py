# -*- coding: utf-8 -*-

import os, tempfile
from StringIO import StringIO
from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
from nose.tools import with_setup

try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()

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
def test_retr_multiplereads():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert filesize == 158437

    temp_fh.close()

@with_setup(setup_func, teardown_func)
def test_retr_longfilename():
    # Test file retrieval that has a long English filename
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/Implementing CIFS - SMB.html', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '671c5700d279fcbbf958c1bba3c2639e'
    assert filesize == 421269

    temp_fh.close()


@with_setup(setup_func, teardown_func)
def test_retr_unicodefilename():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '8a44c1e80d55e91c92350955cdf83442'
    assert filesize == 256000

    temp_fh.close()
