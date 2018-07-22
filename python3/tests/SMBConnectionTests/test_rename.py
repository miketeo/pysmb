# -*- coding: utf-8 -*-

import os, time, random
from io import BytesIO
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
def test_rename_english_file_SMB1():
    global conn

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB2, teardown_func)
def test_rename_english_file_SMB2():
    global conn
    assert conn.smb2_dialect == SMB2_DIALECT_2

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB2x, teardown_func)
def test_rename_english_file_SMB2x():
    global conn
    assert conn.smb2_dialect != SMB2_DIALECT_2

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB1, teardown_func)
def test_rename_unicode_file_SMB1():
    global conn

    old_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB2, teardown_func)
def test_rename_unicode_file_SMB2():
    global conn
    assert conn.smb2_dialect == SMB2_DIALECT_2

    old_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB2x, teardown_func)
def test_rename_unicode_file_SMB2x():
    global conn
    assert conn.smb2_dialect != SMB2_DIALECT_2

    old_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.storeFile('smbtest', old_path, BytesIO(b'Rename file test'))

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteFiles('smbtest', new_path)

@with_setup(setup_func_SMB1, teardown_func)
def test_rename_english_directory_SMB1():
    global conn

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)

@with_setup(setup_func_SMB2, teardown_func)
def test_rename_english_directory_SMB2():
    global conn
    assert conn.smb2_dialect == SMB2_DIALECT_2

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)

@with_setup(setup_func_SMB2x, teardown_func)
def test_rename_english_directory_SMB2x():
    global conn
    assert conn.smb2_dialect != SMB2_DIALECT_2

    old_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )
    new_path = '/RenameTest %d-%d.txt' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)

@with_setup(setup_func_SMB1, teardown_func)
def test_rename_unicode_directory_SMB1():
    global conn

    old_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)

@with_setup(setup_func_SMB2, teardown_func)
def test_rename_unicode_directory_SMB2():
    global conn
    assert conn.smb2_dialect == SMB2_DIALECT_2

    old_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)

@with_setup(setup_func_SMB2x, teardown_func)
def test_rename_unicode_directory_SMB2x():
    global conn
    assert conn.smb2_dialect != SMB2_DIALECT_2

    old_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )
    new_path = u'/改名测试 %d-%d' % ( time.time(), random.randint(1000, 9999) )

    conn.createDirectory('smbtest', old_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) not in filenames

    conn.rename('smbtest', old_path, new_path)

    entries = conn.listPath('smbtest', os.path.dirname(old_path.replace('/', os.sep)))
    filenames = list(map(lambda e: e.filename, entries))
    assert os.path.basename(old_path.replace('/', os.sep)) not in filenames
    assert os.path.basename(new_path.replace('/', os.sep)) in filenames

    conn.deleteDirectory('smbtest', new_path)
