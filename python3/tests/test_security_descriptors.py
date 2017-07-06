import binascii

from smb import security_descriptors as sd
from smb import smb_constants as sc


def test_sid_string_representation():
    sid = sd.SID(1, 5, [2, 3, 4])
    assert str(sid) == "S-1-5-2-3-4"
    sid = sd.SID(1, 2**32 + 3, [])
    assert str(sid) == "S-1-0x100000003"
    sid = sd.SID(1, 2**32, [3, 2, 1])
    assert str(sid) == "S-1-0x100000000-3-2-1"


def test_sid_binary_parsing():
    raw_sid = binascii.unhexlify(b"""
        01 05 00 00 00 00 00 05  15 00 00 00 de 53 c1 2a
        2a 4f da ca c1 79 a6 32  b1 04 00 00
    """.translate(None, b' \n'))
    assert str(sd.SID.from_bytes(raw_sid)) == "S-1-5-21-717312990-3403304746-849770945-1201"
    raw_sid += b"garbage"
    assert str(sd.SID.from_bytes(raw_sid)) == "S-1-5-21-717312990-3403304746-849770945-1201"
    sid, tail = sd.SID.from_bytes(raw_sid, return_tail=True)
    assert str(sid) == "S-1-5-21-717312990-3403304746-849770945-1201"
    assert tail == b"garbage"


def test_ace_binary_parsing():
    raw_ace = binascii.unhexlify(b"""
        00 10 24 00 ff 01 1f 00  01 05 00 00 00 00 00 05
        15 00 00 00 de 53 c1 2a  2a 4f da ca c1 79 a6 32
        6e 04 00 00
    """.translate(None, b' \n'))
    ace = sd.ACE.from_bytes(raw_ace)
    assert str(ace.sid) == "S-1-5-21-717312990-3403304746-849770945-1134"
    assert ace.type == sd.ACE_TYPE_ACCESS_ALLOWED
    assert ace.flags == sd.ACE_FLAG_INHERITED
    assert ace.mask == (sc.SYNCHRONIZE | sc.WRITE_OWNER | sc.WRITE_DAC
                        | sc.READ_CONTROL | sc.DELETE | sc.FILE_READ_DATA
                        | sc.FILE_WRITE_DATA | sc.FILE_APPEND_DATA
                        | sc.FILE_READ_EA | sc.FILE_WRITE_EA | sc.FILE_EXECUTE
                        | sc.FILE_DELETE_CHILD | sc.FILE_READ_ATTRIBUTES
                        | sc.FILE_WRITE_ATTRIBUTES)
    assert not ace.additional_data

    raw_ace = binascii.unhexlify(b"""
        00 13 18 00 a9 00 12 00  01 02 00 00 00 00 00 05
        20 00 00 00 21 02 00 00
    """.translate(None, b' \n'))
    ace = sd.ACE.from_bytes(raw_ace)
    assert str(ace.sid) == "S-1-5-32-545"
    assert ace.type == sd.ACE_TYPE_ACCESS_ALLOWED
    assert ace.flags == (sd.ACE_FLAG_INHERITED | sd.ACE_FLAG_CONTAINER_INHERIT
                         | sd.ACE_FLAG_OBJECT_INHERIT)
    assert ace.mask == (sc.SYNCHRONIZE | sc.READ_CONTROL | sc.FILE_READ_DATA
                        | sc.FILE_READ_EA | sc.FILE_EXECUTE
                        | sc.FILE_READ_ATTRIBUTES)
    assert not ace.additional_data

    raw_ace = binascii.unhexlify(b"""
        01 03 24 00 a9 00 02 00  01 05 00 00 00 00 00 05
        15 00 00 00 de 53 c1 2a  2a 4f da ca c1 79 a6 32
        6c 04 00 00
    """.translate(None, b' \n'))
    ace = sd.ACE.from_bytes(raw_ace)
    assert str(ace.sid) == "S-1-5-21-717312990-3403304746-849770945-1132"
    assert ace.type == sd.ACE_TYPE_ACCESS_DENIED
    assert ace.flags == (sd.ACE_FLAG_CONTAINER_INHERIT
                         | sd.ACE_FLAG_OBJECT_INHERIT)
    assert ace.mask == (sc.READ_CONTROL | sc.FILE_READ_DATA | sc.FILE_READ_EA
                        | sc.FILE_EXECUTE | sc.FILE_READ_ATTRIBUTES)
    assert not ace.additional_data


def test_acl_binary_parsing():
    raw_acl = binascii.unhexlify(b"""
        02 00 70 00 04 00 00 00  00 10 18 00 89 00 10 00
        01 02 00 00 00 00 00 05  20 00 00 00 21 02 00 00
        00 10 14 00 ff 01 1f 00  01 01 00 00 00 00 00 05
        12 00 00 00 00 10 18 00  ff 01 1f 00 01 02 00 00
        00 00 00 05 20 00 00 00  20 02 00 00 00 10 24 00
        ff 01 1f 00 01 05 00 00  00 00 00 05 15 00 00 00
        de 53 c1 2a 2a 4f da ca  c1 79 a6 32 b1 04 00 00
    """.translate(None, b' \n'))
    acl = sd.ACL.from_bytes(raw_acl)
    assert acl.revision == 2
    assert len(acl.aces) == 4

    ace = acl.aces[0]
    assert ace.type == sd.ACE_TYPE_ACCESS_ALLOWED
    assert str(ace.sid) == "S-1-5-32-545"
    assert ace.flags == sd.ACE_FLAG_INHERITED
    assert ace.mask == (sc.SYNCHRONIZE | sc.FILE_READ_DATA | sc.FILE_READ_EA
                        | sc.FILE_READ_ATTRIBUTES)

    ace = acl.aces[3]
    assert ace.type == sd.ACE_TYPE_ACCESS_ALLOWED
    assert str(ace.sid) == "S-1-5-21-717312990-3403304746-849770945-1201"
    assert ace.flags == sd.ACE_FLAG_INHERITED
    assert ace.mask == (sc.SYNCHRONIZE | sc.WRITE_OWNER | sc.WRITE_DAC
                        | sc.READ_CONTROL | sc.DELETE | sc.FILE_READ_DATA
                        | sc.FILE_WRITE_DATA | sc.FILE_APPEND_DATA
                        | sc.FILE_READ_EA | sc.FILE_WRITE_EA | sc.FILE_EXECUTE
                        | sc.FILE_DELETE_CHILD | sc.FILE_READ_ATTRIBUTES
                        | sc.FILE_WRITE_ATTRIBUTES)


def test_descriptor_binary_parsing():
    raw_descriptor = binascii.unhexlify(b"""
        01 00 04 84 14 00 00 00  30 00 00 00 00 00 00 00
        4c 00 00 00 01 05 00 00  00 00 00 05 15 00 00 00
        de 53 c1 2a 2a 4f da ca  c1 79 a6 32 b1 04 00 00
        01 05 00 00 00 00 00 05  15 00 00 00 de 53 c1 2a
        2a 4f da ca c1 79 a6 32  01 02 00 00 02 00 70 00
        04 00 00 00 00 10 18 00  89 00 10 00 01 02 00 00
        00 00 00 05 20 00 00 00  21 02 00 00 00 10 14 00
        ff 01 1f 00 01 01 00 00  00 00 00 05 12 00 00 00
        00 10 18 00 ff 01 1f 00  01 02 00 00 00 00 00 05
        20 00 00 00 20 02 00 00  00 10 24 00 ff 01 1f 00
        01 05 00 00 00 00 00 05  15 00 00 00 de 53 c1 2a
        2a 4f da ca c1 79 a6 32  b1 04 00 00
    """.translate(None, b' \n'))
    descriptor = sd.SecurityDescriptor.from_bytes(raw_descriptor)
    assert descriptor.flags == (sd.SECURITY_DESCRIPTOR_SELF_RELATIVE
                                | sd.SECURITY_DESCRIPTOR_DACL_PRESENT
                                | sd.SECURITY_DESCRIPTOR_DACL_AUTO_INHERITED)
    assert descriptor.dacl is not None
    assert descriptor.sacl is None
    assert str(descriptor.owner) == "S-1-5-21-717312990-3403304746-849770945-1201"
    assert str(descriptor.group) == "S-1-5-21-717312990-3403304746-849770945-513"

    acl = descriptor.dacl
    assert acl.revision == 2
    assert len(acl.aces) == 4
    assert str(acl.aces[0].sid) == sd.SID_BUILTIN_USERS
    assert str(acl.aces[1].sid) == sd.SID_LOCAL_SYSTEM
    assert str(acl.aces[2].sid) == sd.SID_BUILTIN_ADMINISTRATORS
    assert str(acl.aces[3].sid) == "S-1-5-21-717312990-3403304746-849770945-1201"
