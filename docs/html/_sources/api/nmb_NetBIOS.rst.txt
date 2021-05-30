
NetBIOS class
=============

To use the NetBIOS class in your application,
 1. Create a new NetBIOS instance
 2. Call *queryName* method for each name you wish to query. The method will block until a reply is received from the remote SMB/CIFS service, or until timeout.
 3. When you are done, call *close* method to release the underlying resources.

.. autoclass:: nmb.NetBIOS.NetBIOS
    :members:
    :special-members:
