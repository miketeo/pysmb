# -*- coding: utf-8 -*-

import os, tempfile
from StringIO import StringIO
from smb.SMBConnection import SMBConnection
from util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()

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
def test_retr_multiplereads_SMB1():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert filesize == 158437

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_multiplereads_SMB2():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert filesize == 158437

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_longfilename_SMB1():
    # Test file retrieval that has a long English filename
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/Implementing CIFS - SMB.html', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '671c5700d279fcbbf958c1bba3c2639e'
    assert filesize == 421269

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_longfilename_SMB2():
    # Test file retrieval that has a long English filename
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/Implementing CIFS - SMB.html', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '671c5700d279fcbbf958c1bba3c2639e'
    assert filesize == 421269

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_unicodefilename_SMB1():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '8a44c1e80d55e91c92350955cdf83442'
    assert filesize == 256000

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_unicodefilename_SMB2():
    # Test file retrieval that has a long non-English filename inside a folder with a non-English name
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '8a44c1e80d55e91c92350955cdf83442'
    assert filesize == 256000

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_offset_SMB1():
    # Test file retrieval from offset to EOF
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == 'a141bd8024571ce7cb5c67f2b0d8ea0b'
    assert filesize == 156000

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_offset_SMB2():
    # Test file retrieval from offset to EOF
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == 'a141bd8024571ce7cb5c67f2b0d8ea0b'
    assert filesize == 156000

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_offset_and_biglimit_SMB1():
    # Test file retrieval from offset with a big max_length
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 100000)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '83b7afd7c92cdece3975338b5ca0b1c5'
    assert filesize == 100000

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_offset_and_biglimit_SMB2():
    # Test file retrieval from offset with a big max_length
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 100000)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '83b7afd7c92cdece3975338b5ca0b1c5'
    assert filesize == 100000

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_offset_and_smalllimit_SMB1():
    # Test file retrieval from offset with a small max_length
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 10)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '746f60a96b39b712a7b6e17ddde19986'
    assert filesize == 10

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_offset_and_smalllimit_SMB2():
    # Test file retrieval from offset with a small max_length
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 10)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '746f60a96b39b712a7b6e17ddde19986'
    assert filesize == 10

    temp_fh.close()

@with_setup(setup_func_SMB1, teardown_func)
def test_retr_offset_and_zerolimit_SMB1():
    # Test file retrieval from offset to EOF with max_length=0
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 0)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == 'd41d8cd98f00b204e9800998ecf8427e'
    assert filesize == 0

    temp_fh.close()

@with_setup(setup_func_SMB2, teardown_func)
def test_retr_offset_and_zerolimit_SMB2():
    # Test file retrieval from offset to EOF with max_length=0
    global conn
    temp_fh = StringIO()
    file_attributes, filesize = conn.retrieveFileFromOffset('smbtest', u'/测试文件夹/垃圾文件.dat', temp_fh, offset = 100000, max_length = 0)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == 'd41d8cd98f00b204e9800998ecf8427e'
    assert filesize == 0

    temp_fh.close()
