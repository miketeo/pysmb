"""
This module implements security descriptors, and the partial structures
used in them, as specified in [MS-DTYP].
"""
# TODO: document class APIs

import struct


# Security descriptor control flags
# [MS-DTYP]: 2.4.6
SECURITY_DESCRIPTOR_OWNER_DEFAULTED = 0x0001
SECURITY_DESCRIPTOR_GROUP_DEFAULTED = 0x0002
SECURITY_DESCRIPTOR_DACL_PRESENT = 0x0004
SECURITY_DESCRIPTOR_DACL_DEFAULTED = 0x0008
SECURITY_DESCRIPTOR_SACL_PRESENT = 0x0010
SECURITY_DESCRIPTOR_SACL_DEFAULTED = 0x0020
SECURITY_DESCRIPTOR_SERVER_SECURITY = 0x0040
SECURITY_DESCRIPTOR_DACL_TRUSTED = 0x0080
SECURITY_DESCRIPTOR_DACL_COMPUTED_INHERITANCE_REQUIRED = 0x0100
SECURITY_DESCRIPTOR_SACL_COMPUTED_INHERITANCE_REQUIRED = 0x0200
SECURITY_DESCRIPTOR_DACL_AUTO_INHERITED = 0x0400
SECURITY_DESCRIPTOR_SACL_AUTO_INHERITED = 0x0800
SECURITY_DESCRIPTOR_DACL_PROTECTED = 0x1000
SECURITY_DESCRIPTOR_SACL_PROTECTED = 0x2000
SECURITY_DESCRIPTOR_RM_CONTROL_VALID = 0x4000
SECURITY_DESCRIPTOR_SELF_RELATIVE = 0x8000

# ACE types
# [MS-DTYP]: 2.4.4.1
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
ACE_TYPE_SYSTEM_AUDIT = 0x02
ACE_TYPE_SYSTEM_ALARM = 0x03
ACE_TYPE_ACCESS_ALLOWED_COMPOUND = 0x04
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_TYPE_ACCESS_DENIED_OBJECT = 0x06
ACE_TYPE_SYSTEM_AUDIT_OBJECT = 0x07
ACE_TYPE_SYSTEM_ALARM_OBJECT = 0x08
ACE_TYPE_ACCESS_ALLOWED_CALLBACK = 0x09
ACE_TYPE_ACCESS_DENIED_CALLBACK = 0x0A
ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT = 0x0B
ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT = 0x0C
ACE_TYPE_SYSTEM_AUDIT_CALLBACK = 0x0D
ACE_TYPE_SYSTEM_ALARM_CALLBACK = 0x0E
ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT = 0x0F
ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT = 0x10
ACE_TYPE_SYSTEM_MANDATORY_LABEL = 0x11
ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE = 0x12
ACE_TYPE_SYSTEM_SCOPED_POLICY_ID = 0x13

# ACE flags
# [MS-DTYP]: 2.4.4.1
ACE_FLAG_OBJECT_INHERIT = 0x01
ACE_FLAG_CONTAINER_INHERIT = 0x02
ACE_FLAG_NO_PROPAGATE_INHERIT = 0x04
ACE_FLAG_INHERIT_ONLY = 0x08
ACE_FLAG_INHERITED = 0x10
ACE_FLAG_SUCCESSFUL_ACCESS = 0x40
ACE_FLAG_FAILED_ACCESS = 0x80


class SID(object):
    # TODO: docstring
    def __init__(self, revision, identifier_authority, subauthorities):
        self.revision = revision
        self.identifier_authority = identifier_authority
        self.subauthorities = subauthorities

    def __str__(self):
        auths = [self.revision, self.identifier_authority] + self.subauthorities
        return 'S-' + '-'.join(str(subauth) for subauth in auths)

    def __repr__(self):
        return 'SID(%r)' % (str(self),)

    @classmethod
    def from_bytes(cls, data, return_tail=False):
        revision, subauth_count = struct.unpack('<BB', data[:2])
        identifier_authority = struct.unpack('>Q', '\x00\x00' + data[2:8])[0]
        subauth_data = data[8:]
        subauthorities = [struct.unpack('<L', subauth_data[4 * i : 4 * (i+1)])[0]
                          for i in range(subauth_count)]
        sid = cls(revision, identifier_authority, subauthorities)
        if return_tail:
            return sid, subauth_data[4 * subauth_count :]
        return sid


class ACE(object):
    # TODO: docstring
    HEADER_FORMAT = '<BBH'

    def __init__(self, type_, flags, mask, sid, additional_data):
        self.type = type_
        self.flags = flags
        self.mask = mask
        self.sid = sid
        self.additional_data = additional_data

    def __repr__(self):
        return "ACE(type=%#04x, flags=%#04x, mask=%#010x, sid=%s)" % (
            self.type, self.flags, self.mask, self.sid,
        )

    @property
    def isInheritOnly(self):
        """Convenience property which indicates if this ACE is inherit
        only, meaning that it doesn't apply to the object itself."""
        return bool(self.flags & ACE_FLAG_INHERIT_ONLY)

    @classmethod
    def from_bytes(cls, data):
        header_size = struct.calcsize(cls.HEADER_FORMAT)
        header = data[:header_size]
        type_, flags, size = struct.unpack(cls.HEADER_FORMAT, header)

        assert len(data) >= size

        body = data[header_size:size]
        additional_data = {}

        # In all ACE types, the mask immediately follows the header.
        mask = struct.unpack('<I', body[:4])[0]
        body = body[4:]

        # All OBJECT-type ACEs contain additional flags, and two GUIDs as
        # the following fields.
        if type_ in (ACE_TYPE_ACCESS_ALLOWED_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_OBJECT,
                     ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
            additional_data['flags'] = struct.unpack('<I', body[:4])[0]
            additional_data['object_type'] = body[4:20]
            additional_data['inherited_object_type'] = body[20:36]
            body = body[36:]

        # Then the SID in all types.
        sid, body = SID.from_bytes(body, return_tail=True)

        # CALLBACK-type ACEs (and for some obscure reason,
        # SYSTEM_AUDIT_OBJECT) have a final tail of application data.
        if type_ in (ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK,
                     ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
            additional_data['application_data'] = body

        # SYSTEM_RESOURCE_ATTRIBUTE ACEs have a tail of attribute data.
        if type_ == ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
            additional_data['attribute_data'] = body

        return cls(type_, flags, mask, sid, additional_data)


class ACL(object):
    # TODO: docstring
    HEADER_FORMAT = '<BBHHH'

    def __init__(self, revision, aces):
        self.revision = revision
        self.aces = aces

    def __repr__(self):
        return "ACL(%r)" % (self.aces,)

    @classmethod
    def from_bytes(cls, data):
        revision = None
        aces = []

        header_size = struct.calcsize(cls.HEADER_FORMAT)
        header, remaining = data[:header_size], data[header_size:]
        revision, sbz1, size, count, sbz2 = struct.unpack(cls.HEADER_FORMAT, header)

        assert len(data) >= size

        for i in range(count):
            ace_size = struct.unpack('<H', remaining[2:4])[0]
            ace_data, remaining = remaining[:ace_size], remaining[ace_size:]
            aces.append(ACE.from_bytes(ace_data))

        return cls(revision, aces)


class SecurityDescriptor(object):
    """
    Represents a security descriptor, with the following attributes:
    - flags
    - owner
    - group
    - dacl
    - sacl

    References:
    ===========
    - [MS-DTYP]: 2.4.6
    """

    HEADER_FORMAT = '<BBHIIII'

    def __init__(self, flags, owner, group, dacl, sacl):
        self.flags = flags
        self.owner = owner
        self.group = group
        self.dacl = dacl
        self.sacl = sacl

    @classmethod
    def from_bytes(cls, data):
        owner = None
        group = None
        dacl = None
        sacl = None

        header = data[:struct.calcsize(cls.HEADER_FORMAT)]
        (revision, sbz1, flags, owner_offset, group_offset, sacl_offset,
         dacl_offset) = struct.unpack(cls.HEADER_FORMAT, header)

        assert revision == 1
        assert flags & SECURITY_DESCRIPTOR_SELF_RELATIVE
        for offset in (owner_offset, group_offset, sacl_offset, dacl_offset):
            assert 0 <= offset < len(data)

        if owner_offset:
            owner = SID.from_bytes(data[owner_offset:])
        if group_offset:
            group = SID.from_bytes(data[group_offset:])
        if dacl_offset:
            dacl = ACL.from_bytes(data[dacl_offset:])
        if sacl_offset:
            sacl = ACL.from_bytes(data[sacl_offset:])

        return cls(flags, owner, group, dacl, sacl)
