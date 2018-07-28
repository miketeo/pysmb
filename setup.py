import sys, os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

pkgdir = { '': 'python%s' % sys.version_info[0] }

setup(
    name = "pysmb",
    version = "1.1.25",
    author = "Michael Teo",
    author_email = "miketeo@miketeo.net",
    license = "zlib/libpng",
    description = "pysmb is an experimental SMB/CIFS library written in Python to support file sharing between Windows and Linux machines",
    keywords = "windows samba cifs sharing ftp smb linux",
    url = "https://miketeo.net/projects/pysmb",
    package_dir = pkgdir,
    packages = [ 'smb', 'smb.utils', 'nmb' ],
    install_requires = [ 'pyasn1' ],
    long_description="""pysmb is an experimental SMB/CIFS library written in Python. It implements the client-side SMB/CIFS protocol which allows your Python application to access and transfer files to/from SMB/CIFS shared folders like your Windows file sharing and Samba folders.""",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Win32 (MS Windows)",
        "Environment :: Console",
        "License :: OSI Approved :: zlib/libpng License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.4",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: File Sharing",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
    ],
)
