.. pysmb documentation master file, created by
   sphinx-quickstart on Sun Dec 18 15:54:40 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pysmb's documentation!
=================================

pysmb is a pure Python implementation of the client-side SMB/CIFS protocol which is the underlying protocol that facilitates file sharing and printing between Windows machines,
as well as with Linux machines via the Samba server application.
pysmb is developed in Python 2.4.6 (and Python 2.7.1) and has been tested against shared folders on Windows XP SP3, Windows Vista, Windows 7 and Samba 3.x.

License
-------
pysmb itself is licensed under an opensource license.
You are free to use pysmb in any applications, including for commercial purposes.
For more details on the terms of use, please read the LICENSE file that comes with your pysmb source.

pysmb depends on other 3rd-party modules whose terms of use are not covered by pysmb.
Use of these modules could possibly conflict with your licensing needs. Please exercise your own discretion to determine their suitabilities.
I have listed these modules in the following section.

Credits
-------
pysmb is not alone. It is made possible with support from other modules.

* **pyasn1** : Pure Python implementation of ASN.1 parsing and encoding (not included together with pysmb; needs to be installed separately)
* **md4** and **U32** : Pure Python implementation of MD4 hashing algorithm and 32-bit unsigned integer by Dmitry Rozmanov. Licensed under LGPL and included together with pysmb.
* **pyDes** : Pure python implementation of the DES encryption algorithm by Todd Whiteman. Free domain and included together with pysmb.

In various places, there are references to different specifications. Most of these referenced specifications
can be downloaded from Microsoft web site under Microsoft's "Open Specification Promise". If you need to download
a copy of these specifications, please google for it. For example, google for "MS-CIFS" to download the CIFS specification for NT LM dialect.

Package Contents and Description
================================

pysmb is organized into 2 main packages: smb and nmb.
The smb package contains all the functionalities related to Server Message Block (SMB) implementation.
As an application developer, you will be importing this module into your application.
Hence, please take some time to familiarize yourself with the smb package contents.

* **nmb/base.py** :
  Contains the NetBIOSSession and NBNS abstract class which implements NetBIOS session and NetBIOS Name Service communication
  without any network transport specifics.
* **nmb/NetBIOS.py**:
  Provides a NBNS implementation to query IP addresses for machine names. All operations are blocking I/O.
* **nmb/NetBIOSProtocol.py** :
  Provides the NBNS protocol implementation for use in Twisted framework.

* **smb/base.py** :
  Contains the SMB abstract class which implements the SMB communication without any network transport specifics.
* **smb/ntlm.py** :
  Contains the NTLMv1 and NTLMv2 authentication routines and the decoding/encoding of NTLM authentication messages within SMB messages.
* **smb/securityblob.py** :
  Provides routines to encode/decode the NTLMSSP security blob in the SMB messages.
* **smb/smb_constants.py** :
  All the constants used in the smb package
* **smb/smb_structs.py** :
  Contains the internal classes used in the SMB package. These classes are usually used to encode/decode the parameter and data blocks of specific SMB message.
* **smb/SMBConnection.py** :
  Contains a SMB protocol implementation. All operations are blocking I/O.
* **smb/SMBProtocol.py** :
  Contains the SMB protocol implementation for use in the Twisted framework.

Using pysmb
===========

As an application developer who is looking to use pysmb to translate NetBIOS names to IP addresses,
 * To use pysmb in applications where you want the file operations to return after they have completed (synchronous style), please read
   :doc:`nmb.NetBIOS.NetBIOS<api/nmb_NetBIOS>` documentation.
 * To use pysmb in Twisted, please read :doc:`nmb.NetBIOSProtocol.NBNSProtocol<api/nmb_NBNSProtocol>` documentation.

As an application developer who is looking to use pysmb to implement file transfer or authentication over SMB:
 * To use pysmb in applications where you want the file operations to return after they have completed (synchronous style), please read
   :doc:`smb.SMBConnection.SMBConnection<api/smb_SMBConnection>` documentation.
 * To use pysmb in Twisted, please read :doc:`smb.SMBProtocol.SMBProtocolFactory<api/smb_SMBProtocolFactory>` documentation.

As a software developer who is looking to modify pysmb so that you can integrate it to other network frameworks:
 * Read :doc:`extending`



Indices and tables
==================

.. toctree::
    :glob:
    :maxdepth: 1

    api/*
    extending

* :ref:`genindex`
* :ref:`search`
