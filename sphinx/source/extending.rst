
Extending pysmb For Other Frameworks
====================================

This page briefly describes the steps involved in extending pysmb for other frameworks.

In general, you need to take care of the SMB TCP connection setup, i.e. finding the IP address of the remote server and connect to the SMB/CIFS service.
Then you need to read/write synchronously or asynchronously from and to the SMB socket. And you need to handle post-authentication callback methods, and from these methods,
initiate file operations with the remote SMB/CIFS server.

Now the above steps in more technical details:
 1. Create a new class which subclasses the *smb.base.SMB* class. Most often, the connection setup will be part of the *__init__* method.
 2. Override the *write(self, data)* method to provide an implementation which will write *data* to the socket.
 3. Write your own loop handling method to read data from the socket. Once data have been read, call *feedData* method with the parameter.
    The *feedData* method has its own internal buffer, so it can accept incomplete NetBIOS session packet data.
 4. Override
   * *onAuthOK* method to include your own operations to perform when authentication is successful. You can initiate file operations in this method.
   * *onAuthFailed* method to include your own processing on what to do when authentication fails. You can report this as an error, or to try a different NTLM authentication algorithm (*use_ntlm_v2* parameter in the constructor).
   * *onNMBSessionFailed* method to include your own processing on what to do when pysmb fails to setup the NetBIOS session with the remote server. Usually, this is due to a wrong *remote_name* parameter in the constructor.
