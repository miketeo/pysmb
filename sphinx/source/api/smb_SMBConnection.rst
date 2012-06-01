
SMBConnection Class
===================

The SMBConnection is suitable for developers who wish to use pysmb to perform file operations with a remote SMB/CIFS server sequentially.

Each file operation method, when invoked, will block and return after it has completed or has encountered an error.

Example
-------

The following illustrates a simple file retrieving implementation.::

    import tempfile
    from smb.SMBConnection import SMBConnection

    # There will be some mechanism to capture userID, password, client_machine_name, server_name and server_ip
    # client_machine_name can be an arbitary ASCII string
    # server_name should match the remote machine name, or else the connection will be rejected
    conn = SMBConnection(userID, password, client_machine_name, server_name, use_ntlm_v2 = True)
    assert conn.connect(server_ip, 139)

    file_obj = tempfile.NamedTemporaryFile()
    file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', file_obj)

    # Retrieved file contents are inside file_obj
    # Do what you need with the file_obj and then close it
    # Note that the file obj is positioned at the end-of-file,
    # so you might need to perform a file_obj.seek() if you need
    # to read from the beginning
    file_obj.close()

SMB2 Support
-------------

Starting from pysmb 1.1.0, pysmb will utilize SMB2 protocol for communication if the remote SMB/CIFS service supports SMB2.
Otherwise, it will fallback automatically back to using SMB1 protocol.

To disable SMB2 protocol in pysmb, set the *SUPPORT_SMB2* flag in the *smb_structs* module to *False* before creating the *SMBConnection* instance.::

    from smb import smb_structs
    smb_structs.SUPPORT_SMB2 = False

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
