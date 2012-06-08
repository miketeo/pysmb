
import binascii
from smb import securityblob


def test_NTLMSSP_NEGOTIATE_encoding():
    ntlm_data = binascii.unhexlify(b'4e544c4d5353500001000000978208e200000000000000000000000000000000060072170000000f')  # The NTLM negotiate message
    blob = securityblob.generateNegotiateSecurityBlob(ntlm_data)

    TARGET = binascii.unhexlify(b"""
60 48 06 06 2b 06 01 05 05 02 a0 3e 30 3c a0 0e
30 0c 06 0a 2b 06 01 04 01 82 37 02 02 0a a2 2a
04 28 4e 54 4c 4d 53 53 50 00 01 00 00 00 97 82
08 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 06 00 72 17 00 00 00 0f
""".replace(b' ', b'').replace(b'\n', b''))

    assert blob == TARGET


def test_NTLMSSP_CHALLENGE_decoding():
    blob = binascii.unhexlify(b"""
a1 81 be 30 81 bb a0 03 0a 01 01 a1 0c 06 0a 2b
06 01 04 01 82 37 02 02 0a a2 81 a5 04 81 a2 4e
54 4c 4d 53 53 50 00 02 00 00 00 0a 00 0a 00 38
00 00 00 15 82 8a e2 32 81 ce 29 7f de 3f 80 00
00 00 00 00 00 00 00 60 00 60 00 42 00 00 00 06
01 00 00 00 00 00 0f 43 00 45 00 54 00 55 00 53
00 02 00 0a 00 43 00 45 00 54 00 55 00 53 00 01
00 0a 00 43 00 45 00 54 00 55 00 53 00 04 00 16
00 6c 00 6f 00 63 00 61 00 6c 00 64 00 6f 00 6d
00 61 00 69 00 6e 00 03 00 22 00 63 00 65 00 74
00 75 00 73 00 2e 00 6c 00 6f 00 63 00 61 00 6c
00 64 00 6f 00 6d 00 61 00 69 00 6e 00 00 00 00
00""".replace(b' ', b'').replace(b'\n', b''))

    RESPONSE_TOKENS = binascii.unhexlify(b"""
4e 54 4c 4d 53 53 50 00 02 00 00 00 0a 00 0a 00
38 00 00 00 15 82 8a e2 32 81 ce 29 7f de 3f 80
00 00 00 00 00 00 00 00 60 00 60 00 42 00 00 00
06 01 00 00 00 00 00 0f 43 00 45 00 54 00 55 00
53 00 02 00 0a 00 43 00 45 00 54 00 55 00 53 00
01 00 0a 00 43 00 45 00 54 00 55 00 53 00 04 00
16 00 6c 00 6f 00 63 00 61 00 6c 00 64 00 6f 00
6d 00 61 00 69 00 6e 00 03 00 22 00 63 00 65 00
74 00 75 00 73 00 2e 00 6c 00 6f 00 63 00 61 00
6c 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 00 00
00 00
""".replace(b' ', b'').replace(b'\n', b''))

    result, response_tokens = securityblob.decodeChallengeSecurityBlob(blob)

    assert result == securityblob.RESULT_ACCEPT_INCOMPLETE
    assert response_tokens == RESPONSE_TOKENS


def test_NTLMSSP_AUTH_encoding():
    ntlm_data = binascii.unhexlify(b"""
4e 54 4c 4d 53 53 50 00 03 00 00 00 01 00 01 00
70 00 00 00 00 00 00 00 71 00 00 00 00 00 00 00
58 00 00 00 00 00 00 00 58 00 00 00 18 00 18 00
58 00 00 00 10 00 10 00 71 00 00 00 15 8a 88 e2
06 00 72 17 00 00 00 0f 06 49 3b c4 f6 2a 2b be
61 a6 81 e7 cc 58 37 b4 4d 00 49 00 43 00 48 00
41 00 45 00 4c 00 2d 00 49 00 35 00 50 00 43 00
00 a7 0d b4 74 c3 d8 14 c9 df 3d 80 6d 87 94 42
bc
""".replace(b' ', b'').replace(b'\n', b''))

    TARGET = binascii.unhexlify(b"""
a1 81 8a 30 81 87 a2 81 84 04 81 81 4e 54 4c 4d
53 53 50 00 03 00 00 00 01 00 01 00 70 00 00 00
00 00 00 00 71 00 00 00 00 00 00 00 58 00 00 00
00 00 00 00 58 00 00 00 18 00 18 00 58 00 00 00
10 00 10 00 71 00 00 00 15 8a 88 e2 06 00 72 17
00 00 00 0f 06 49 3b c4 f6 2a 2b be 61 a6 81 e7
cc 58 37 b4 4d 00 49 00 43 00 48 00 41 00 45 00
4c 00 2d 00 49 00 35 00 50 00 43 00 00 a7 0d b4
74 c3 d8 14 c9 df 3d 80 6d 87 94 42 bc
""".replace(b' ', b'').replace(b'\n', b''))

    blob = securityblob.generateAuthSecurityBlob(ntlm_data)

    assert blob == TARGET


def test_auth_response_decoding():
    blob = binascii.unhexlify(b"a1 07 30 05 a0 03 0a 01 00".replace(b' ', b''))

    result = securityblob.decodeAuthResponseSecurityBlob(blob)
    assert result == securityblob.RESULT_ACCEPT_COMPLETED
