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
def test_security_SMB2():
    global conn
    # TODO: Need a way to setup the environment on the remote server and perform some verification on the returned results.
    attributes = conn.getSecurity('smbtest', '/rfc1001.txt')
