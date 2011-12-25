
SMBConnection Class
===================

The SMBConnection is suitable for developers who wish to use pysmb to perform file operations with a remote SMB/CIFS server sequentially.

Each file operation method, when invoked, will block and return after it has completed or has encountered an error.

Caveats
-------

* It is not meant to be used asynchronously.
* A single *SMBConnection* instance should not be used to perform more than one operation concurrently at the same time.
* Do not keep a *SMBConnection* instance "idle" for too long, i.e. keeping a *SMBConnection* instance but not using it.
  Most SMB/CIFS servers have some sort of keepalive mechanism and impose a timeout limit.
  If the clients fail to respond within the timeout limit, the SMB/CIFS server may disconnect the client.

.. autoclass:: smb.SMBConnection.SMBConnection
    :members:
    :special-members:
