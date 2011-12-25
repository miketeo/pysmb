
NBNSProtocol Class
==================

pysmb has a *NBNSProtocol* implementation for Twisted framework.
This allows you to perform name query asynchronously without having your application to block and wait for the results.

In your project,
 1. Create a NBNSProtocol instance.
 2. Just call *queryName* method which will return a *Deferred* instance. Add your callback function to the *Deferred* instance via *addCallback* method to receive the results of the name query.
 3. When you are done with the NBNSProtocol instance, call its <NBNSProtocol instance>.transport.stopListening method to remove this instance from the reactor.

.. autoclass:: nmb.NetBIOSProtocol.NBNSProtocol
    :members:
    :special-members:

.. autoclass:: nmb.NetBIOSProtocol.NetBIOSTimeout
    :members:
