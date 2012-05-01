
SMbHandler Class
================

The SMBHandler class provides support for "smb://" URLs in the `urllib2 <http://docs.python.org/library/urllib2.html>`_ python package.

Notes
-----
* Note that you need to pass in a valid hostname or IP address for the host component of the URL.
  Do not use the Windows/NetBIOS machine name for the host component.
* The first component of the path in the URL points to the name of the shared folder.
  Subsequent path components will point to the directory/folder of the file.
* You can retrieve and upload files, but you cannot delete files/folders or create folders.
  In uploads, if the parent folders do not exist, an *urllib2.URLError* will be raised.

Example
-------

The following code snippet illustrates file retrieval.::

    # -*- coding: utf-8 -*-
    import urllib2
    from smb.SMBHandler import SMBHandler

    director = urllib2.build_opener(SMBHandler)
    fh = director.open('smb://myuserID:mypassword@192.168.1.1/sharedfolder/rfc1001.txt')

    # Process fh like a file-like object and then close it.
    fh.close()

    # For paths/files with unicode characters, simply pass in the URL as an unicode string
    fh2 = director.open(u'smb://myuserID:mypassword@192.168.1.1/sharedfolder/测试文件夹/垃圾文件.dat')

    # Process fh2 like a file-like object and then close it.
    fh2.close()

The following code snippet illustrates file upload. You need to provide a file-like object for the *data* parameter in the *open()* method::

    import urllib2
    from smb.SMBHandler import SMBHandler

    file_fh = open('local_file.dat', 'rb')

    director = urllib2.build_opener(SMBHandler)
    fh = director.open('smb://myuserID:mypassword@192.168.1.1/sharedfolder/upload_file.dat', data = file_fh)

    # Reading from fh will only return an empty string
    fh.close()
