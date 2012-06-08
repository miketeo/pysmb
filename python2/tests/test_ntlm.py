
import binascii
from smb import ntlm

def test_NTLMv1_without_extended_security():
    password = 'Password'
    server_challenge = '\x01\x23\x45\x67\x89\xab\xcd\xef'

    nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV1(password,
                                                                                                 server_challenge,
                                                                                                 has_extended_security = False,
                                                                                                 client_challenge = '\xAA'*8)

    assert binascii.hexlify(nt_challenge_response).lower() == '67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94'.replace(' ', '')  # [MS-NLMP]: 4.2.2.2.1
    assert binascii.hexlify(lm_challenge_response).lower() == '98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13'.replace(' ', '')  # [MS-NLMP]: 4.2.2.2.2


def test_NTLMv1_with_extended_security():
    password = 'Password'
    server_challenge = '\x01\x23\x45\x67\x89\xab\xcd\xef'

    nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV1(password,
                                                                                                 server_challenge,
                                                                                                 has_extended_security = True,
                                                                                                 client_challenge = '\xAA'*8)

    assert binascii.hexlify(nt_challenge_response).lower() == '75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32'.replace(' ', '')  # [MS-NLMP]: 4.2.3.2.2
    assert binascii.hexlify(lm_challenge_response).lower() == 'aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'.replace(' ', '')  # [MS-NLMP]: 4.2.3.2.1


def test_NTLMv2():
    user = 'User'
    password = 'Password'
    domain = 'Domain'
    server_challenge = '\x01\x23\x45\x67\x89\xab\xcd\xef'

    server_avpair = binascii.unhexlify('01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00'.replace(' ', ''))
    domain_avpair = binascii.unhexlify('02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00'.replace(' ', ''))

    nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV2(password,
                                                                                                 user,
                                                                                                 server_challenge,
                                                                                                 server_avpair + domain_avpair + '\0'*4,
                                                                                                 domain,
                                                                                                 client_challenge = '\xAA'*8)

    assert binascii.hexlify(lm_challenge_response).lower() == '86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa'.replace(' ', '')  # [MS-NLMP]: 4.2.4.2.1
