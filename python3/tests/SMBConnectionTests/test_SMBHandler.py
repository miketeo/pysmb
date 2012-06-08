# -*- coding: utf-8 -*-

import os, urllib.request, urllib.parse, urllib.error, urllib.request, urllib.error, urllib.parse, time, random
from smb.SMBHandler import SMBHandler
from . import util


try:
    import hashlib
    def MD5(): return hashlib.md5()
except ImportError:
    import md5
    def MD5(): return md5.new()



def test_basic():
    # Basic test for smb URLs
    director = urllib.request.build_opener(SMBHandler)
    fh = director.open('smb://%(user)s:%(password)s@%(server_ip)s/smbtest/rfc1001.txt' % util.getConnectionInfo())

    s = fh.read()
    md = MD5()
    md.update(s)
    assert md.hexdigest() == '5367c2bbf97f521059c78eab65309ad3'
    assert len(s) == 158437

    fh.close()


def test_unicode():
    # Test smb URLs with unicode paths
    director = urllib.request.build_opener(SMBHandler)
    fh = director.open('smb://%(user)s:%(password)s@%(server_ip)s/smbtest/测试文件夹/垃圾文件.dat' % util.getConnectionInfo())

    s = fh.read()
    md = MD5()
    md.update(s)
    assert md.hexdigest() == '8a44c1e80d55e91c92350955cdf83442'
    assert len(s) == 256000

    fh.close()



TEST_FILENAME = os.path.join(os.path.dirname(__file__), os.pardir, 'SupportFiles', 'binary.dat')
TEST_FILESIZE = 256000
TEST_DIGEST = 'bb6303f76e29f354b6fdf6ef58587e48'

def test_upload():
    info = util.getConnectionInfo()
    info['filename'] = os.sep + 'StoreTest-%d-%d.dat' % ( time.time(), random.randint(0, 10000) )

    director = urllib.request.build_opener(SMBHandler)
    upload_fh = director.open('smb://%(user)s:%(password)s@%(server_ip)s/smbtest/%(filename)s' % info, data = open(TEST_FILENAME, 'rb'))

    retr_fh = director.open('smb://%(user)s:%(password)s@%(server_ip)s/smbtest/%(filename)s' % info)

    s = retr_fh.read()
    md = MD5()
    md.update(s)

    assert md.hexdigest() == TEST_DIGEST
    assert len(s) == TEST_FILESIZE
