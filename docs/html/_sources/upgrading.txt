Upgrading from older pysmb versions
====================================

This page documents the improvements and changes to the API that could be incompatible with previous releases.

pysmb 1.2.0
-----------
- Add new `delete_matching_folders` parameter to `deleteFiles()` method in SMBProtocolFactory and SMBConnection
  class to support deletion of sub-folders. If you are passing timeout parameter to the `deleteFiles()` method
  in your application, please switch to using named parameter for timeout.

pysmb 1.1.28
------------
- SharedFile instances returned from the `listPath()` method now has a new property
  `file_id` attribute which represents the file reference number given by the remote SMB server.

pysmb 1.1.26
------------
- SMBConnection class can now be used as a context manager

pysmb 1.1.25
------------
- SharedFile class has a new property `isNormal` which will be True if the file is a
  'normal' file. pysmb defines a 'normal' file as a file entry that is not
  read-only, not hidden, not system, not archive and not a directory;
  it ignores other attributes like compression, indexed, sparse, temporary and encryption.
- `listPath()` method in SMBProtocolFactory and SMBConnection class will now include
  'normal' files by default if you do not specify the `search` parameter.

pysmb 1.1.20
------------
- A new method `getSecurity()` was added to SMBConnection and SMBProtocolFactory class.

pysmb 1.1.15
------------
- Add new `truncate` parameter to `storeFileFromOffset()` in SMBProtocolFactory and SMBConnection
  class to support truncation of the file before writing. If you are passing timeout parameter
  to the `storeFileFromOffset()` method in your application, please switch to using named parameter for timeout.

pysmb 1.1.11
------------
- A new method `storeFileFromOffset()` was added to SMBConnection and SMBProtocolFactory class.

pysmb 1.1.10
------------
- A new method `getAttributes()` was added to SMBConnection and SMBProtocolFactory class
- SharedFile class has a new property `isReadOnly` to indicate the file is read-only on the remote filesystem.

pysmb 1.1.2
-----------
- `queryIPForName()` method in nmb.NetBIOS and nmb.NBNSProtocol class will now return only the server machine name and ignore workgroup names.

pysmb 1.0.3
-----------
- Two new methods were added to NBNSProtocol class: `queryIPForName()` and `NetBIOS.queryIPForName()`
  to support querying for a machine's NetBIOS name at the given IP address.
- A new method `retrieveFileFromOffset()` was added to SMBProtocolFactory and SMBConnection
  to support finer control of file retrieval operation.

pysmb 1.0.0
-----------
pysmb was completely rewritten in version 1.0.0.
If you are upgrading from pysmb 0.x, you most likely have to rewrite your application for the new 1.x API.
