# -*- coding: utf-8 -*-

from io import BytesIO
from typing import Optional

from nose2.tools.decorators import with_setup, with_teardown
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from .util import getConnectionInfo


conn: Optional[SMBConnection] = None
TEST_FILE_NAME = 'StoreTest.txt'
TEST_SERVICE_NAME = 'smbtest'


def setup_func_SMB2():
    global conn
    smb_structs.SUPPORT_SMB2 = True

    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True, is_direct_tcp=True)
    assert conn.connect(info['server_ip'], info['server_port'])


def teardown_func():
    global conn
    conn.close()


@with_setup(setup_func_SMB2)
@with_teardown(teardown_func)
def test_messages_in_exception_SMB2():
    info = getConnectionInfo()

    with open(f'''\\\\{info['server_ip']}\\{TEST_SERVICE_NAME}\\{TEST_FILE_NAME}''', 'w'):
        try:
            conn.storeFile(TEST_SERVICE_NAME, TEST_FILE_NAME, BytesIO(b'Test data'))
        except Exception as ex:
            conn.retrieveFile(TEST_SERVICE_NAME, TEST_FILE_NAME, BytesIO())
            last_smb_message = ex.args[1][-1]
            if last_smb_message.status != 0xC0000043:
                raise ex
