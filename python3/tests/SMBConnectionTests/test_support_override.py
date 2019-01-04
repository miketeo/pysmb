# -*- coding: utf-8 -*-

from smb.SMBConnection import SMBConnection
from smb.smb_constants import *
from smb.smb2_constants import SMB2_DIALECT_2, SMB2_DIALECT_21
from .util import getConnectionInfo
from nose.tools import with_setup
from smb import smb_structs

def test_smb1():
    smb_structs.SUPPORT_SMB2 = smb_structs.SUPPORT_SMB2x = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True)
    assert conn.connect(info['server_ip'], info['server_port'])
    assert not conn.isUsingSMB2
    conn.close()

def test_smb2():
    smb_structs.SUPPORT_SMB2 = smb_structs.SUPPORT_SMB2x = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True, smb_support_mask = SMBConnection.SMB_SUPPORT_SMB2)
    assert conn.connect(info['server_ip'], info['server_port'])
    assert conn.smb2_dialect == SMB2_DIALECT_2
    conn.close()

def test_smb2x():
    smb_structs.SUPPORT_SMB2 = smb_structs.SUPPORT_SMB2x = False
    info = getConnectionInfo()
    conn = SMBConnection(info['user'], info['password'], info['client_name'], info['server_name'], use_ntlm_v2 = True, smb_support_mask = SMBConnection.SMB_SUPPORT_SMB2 | SMBConnection.SMB_SUPPORT_SMB2x)
    assert conn.connect(info['server_ip'], info['server_port'])
    assert conn.smb2_dialect == SMB2_DIALECT_21
    conn.close()
