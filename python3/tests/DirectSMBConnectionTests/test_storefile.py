# -*- coding: utf-8 -*-

import os, tempfile, random, time
from io import BytesIO
from smb.SMBConnection import SMBConnection
from .util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()

conn = None

TEST_FILENAME = os.path.join(os.path.dirname(__file__), os.pardir, 'SupportFiles', 'binary.dat')
TEST_FILESIZE = 256000
TEST_DIGEST = 'bb6303f76e29f354b6fdf6ef58587e48'

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
def test_store_long_filename_SMB1():
    filename = os.sep + 'StoreTest %d-%d.dat' % ( time.time(), random.randint(0, 10000) )

    filesize = conn.storeFile('smbtest', filename, open(TEST_FILENAME, 'rb'))
    assert filesize == TEST_FILESIZE

    entries = conn.listPath('smbtest', os.path.dirname(filename.replace('/', os.sep)))
    filenames = [e.filename for e in entries]
    assert os.path.basename(filename.replace('/', os.sep)) in filenames

    buf = BytesIO()
    file_attributes, file_size = conn.retrieveFile('smbtest', filename, buf)
    assert file_size == TEST_FILESIZE

    md = MD5()
    md.update(buf.getvalue())
    assert md.hexdigest() == TEST_DIGEST
    buf.close()

    conn.deleteFiles('smbtest', filename)


@with_setup(setup_func_SMB2, teardown_func)
def test_store_long_filename_SMB2():
    filename = os.sep + 'StoreTest %d-%d.dat' % ( time.time(), random.randint(0, 10000) )

    filesize = conn.storeFile('smbtest', filename, open(TEST_FILENAME, 'rb'))
    assert filesize == TEST_FILESIZE

    entries = conn.listPath('smbtest', os.path.dirname(filename.replace('/', os.sep)))
    filenames = [e.filename for e in entries]
    assert os.path.basename(filename.replace('/', os.sep)) in filenames

    buf = BytesIO()
    file_attributes, file_size = conn.retrieveFile('smbtest', filename, buf)
    assert file_size == TEST_FILESIZE

    md = MD5()
    md.update(buf.getvalue())
    assert md.hexdigest() == TEST_DIGEST
    buf.close()

    conn.deleteFiles('smbtest', filename)


@with_setup(setup_func_SMB1, teardown_func)
def test_store_unicode_filename_SMB1():
    filename = os.sep + '上载测试 %d-%d.dat' % ( time.time(), random.randint(0, 10000) )

    filesize = conn.storeFile('smbtest', filename, open(TEST_FILENAME, 'rb'))
    assert filesize == TEST_FILESIZE

    entries = conn.listPath('smbtest', os.path.dirname(filename.replace('/', os.sep)))
    filenames = [e.filename for e in entries]
    assert os.path.basename(filename.replace('/', os.sep)) in filenames

    buf = BytesIO()
    file_attributes, file_size = conn.retrieveFile('smbtest', filename, buf)
    assert file_size == TEST_FILESIZE

    md = MD5()
    md.update(buf.getvalue())
    assert md.hexdigest() == TEST_DIGEST
    buf.close()

    conn.deleteFiles('smbtest', filename)


@with_setup(setup_func_SMB2, teardown_func)
def test_store_unicode_filename_SMB2():
    filename = os.sep + '上载测试 %d-%d.dat' % ( time.time(), random.randint(0, 10000) )

    filesize = conn.storeFile('smbtest', filename, open(TEST_FILENAME, 'rb'))
    assert filesize == TEST_FILESIZE

    entries = conn.listPath('smbtest', os.path.dirname(filename.replace('/', os.sep)))
    filenames = [e.filename for e in entries]
    assert os.path.basename(filename.replace('/', os.sep)) in filenames

    buf = BytesIO()
    file_attributes, file_size = conn.retrieveFile('smbtest', filename, buf)
    assert file_size == TEST_FILESIZE

    md = MD5()
    md.update(buf.getvalue())
    assert md.hexdigest() == TEST_DIGEST
    buf.close()

    conn.deleteFiles('smbtest', filename)
