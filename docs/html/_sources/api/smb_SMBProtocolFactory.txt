
SMBProtocolFactory Class
========================

For those who want to utilize pysmb in Twisted framework, pysmb has a *smb.SMBProtocol.SMBProtocol* implementation.
In most cases, you do not need to touch or import the *SMBProtocol* directly. All the SMB functionalities are exposed in the *SMBProtocolFactory*.

In your project,
 1. Create a new class and subclass *SMBProtocolFactory*.
 2. Override the *SMBProtocolFactory.onAuthOK* and *SMBProtocolFactory.onAuthFailed* instance methods to provide your own post-authenthentication handling.
    Once *SMBProtocolFactory.onAuthOK* has been called by pymsb internals, your application is ready to communicate with the remote SMB/CIFS service through
    the *SMBProtocolFactory* public methods such as *SMBProtocolFactory.storeFile*, *SMBProtocolFactory.retrieveFile*, etc.
 3. When you want to disconnect from the remote SMB/CIFS server, just call *SMBProtocolFactory.closeConnection* method.

All the *SMBProtocolFactory* public methods that provide file functionlities will return a *twisted.internet.defer.Deferred* instance.
A :doc:`NotReadyError<smb_exceptions>` exception is raised when the underlying SMB is not authenticated.
If the underlying SMB connection has been terminated, a :doc:`NotConnectedError<smb_exceptions>` exception is raised.

All the file operation methods in *SMBProtocolFactory* class accept a *timeout* parameter. This parameter specifies the time limit where pysmb will wait for the
entire file operation (except *storeFile* and *retrieveFile* methods) to complete. If the file operation fails to complete within the timeout period, the returned
*Deferred* instance's *errback* method will be called with a *SMBTimeout* exception.

If you are interested in learning the results of the operation or to know when the operation has completed, you should
add a handling method to the returned *Deferred* instance via *Deferred.addCallback*. If the file operation fails, the *Deferred.errback* function will be called
with an :doc:`OperationFailure<smb_exceptions>`; on timeout, it will be called with a :doc:`SMBTimeout<smb_exceptions>`.

Caveats
-------

* A new factory instance must be created for each SMB connection to the remote SMB/CIFS service. Avoid reusing the same factory instance for more than one SMB connection.
* The remote SMB/CIFS server usually imposes a limit of the number of concurrent file operations for each client. For example, to transfer a thousand files, you may need to setup a queue in your application and call *storeFile* or *retrieveFile* in batches.
* The *timeout* parameter in the file operation methods are not precise; it is accurate to within 1 second interval, i.e. with a timeout of 0.5 sec, pysmb might raise
  *SMBTimeout* exception after 1.5 sec.

.. autoclass:: smb.SMBProtocol.SMBProtocolFactory
    :members:
    :special-members:
