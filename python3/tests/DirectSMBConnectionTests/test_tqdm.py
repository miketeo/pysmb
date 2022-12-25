# -*- coding: utf-8 -*-

import os, time, random
from io import BytesIO
from nose2.tools.decorators import with_setup, with_teardown
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from .util import getConnectionInfo

try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()


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


@with_setup(setup_func_SMB1)
@with_teardown(teardown_func)
def test_retr_tqdm_SMB1():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    global conn
    temp_fh = BytesIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', temp_fh, show_progress=True)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert filesize == 158437

    temp_fh.close()

@with_setup(setup_func_SMB2)
@with_teardown(teardown_func)
def test_retr_tqdm_SMB2():
    # Test file retrieval using multiple ReadAndx calls (assuming each call will not reach more than 65534 bytes)
    global conn
    temp_fh = BytesIO()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', temp_fh, show_progress=True)

    md = MD5()
    md.update(temp_fh.getvalue())
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert filesize == 158437

    temp_fh.close()

TEST_FILENAME = os.path.join(os.path.dirname(__file__), os.pardir, 'SupportFiles', 'binary.dat')
TEST_FILESIZE = 256000
TEST_DIGEST = 'bb6303f76e29f354b6fdf6ef58587e48'

@with_setup(setup_func_SMB1)
@with_teardown(teardown_func)
def test_store_tqdm_SMB1():
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

@with_setup(setup_func_SMB2)
@with_teardown(teardown_func)
def test_store_tqdm_SMB2():
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

