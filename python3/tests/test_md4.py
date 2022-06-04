from smb.utils.md4 import MD4

_md4_test_data = [
    ("", 0x31d6cfe0d16ae931b73c59d7e0c089c0),
    ("a",   0xbde52cb31de33e46245e05fbdbd6fb24),
    ("abc",   0xa448017aaf21d8525fc10ae87aa6729d),
    ("message digest",   0xd9130a8164549fe818874806e1c7014b),
    ("abcdefghijklmnopqrstuvwxyz",   0xd79e1c308aa5bbcdeea8ed63df412da9),
    (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        0x043f8582f241db351ce627e153e7f0e4),
    (
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        0xe33b4ddc9c38f2199c3e7b164fcc0536),
    ("The quick brown fox jumps over the lazy dog", 0x1bee69a46ba811185c194762abaeae90),
    ("The quick brown fox jumps over the lazy cog", 0xb86e130ce7028da59e672d56ad0113df)
]


def test_md4():
    for input_data, expected_result in _md4_test_data:
        expected_digest = expected_result.to_bytes(16, byteorder="big", signed=False)
        md4 = MD4()
        md4.update(input_data)
        computed_digest = md4.digest()
        assert computed_digest == expected_digest
