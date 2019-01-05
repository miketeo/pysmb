# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from .util import getConnectionInfo

def test_context():
    info = getConnectionInfo()
    with SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True) as conn:
        assert conn.connect(info['server_ip'], info['server_port'])

    assert conn.sock is None
