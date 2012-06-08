
Steps to Follow to Run the Unit Tests
=====================================

1a. Install Nose Testing Framework
All the unit tests here are designed to be conducted with the nose testing framework.
You can install the latest nose testing framework by running: easy_install nose
For more information on nose testing, please visit http://readthedocs.org/docs/nose/en/latest/

1b. Install the Twisted framework
If you need to test the SMB/NetBIOS protocol implementations for Twisted framework,
you should install the Twisted framework from http://twistedmatrix.com/
or by running: easy_install Twisted
Without the Twisted framework, the Twisted tests will fail.

2. Prepare a Shared Folder "smbtest" on a Remote Server
To run the unit tests here, besides installing the nose testing framework, you will
also need to prepare a shared folder on a remote server.
pysmb has been tested against Samba 3.x, Windows XP SP3 and Windows Vista.
The shared folder must be named "smbtest".

3. Unzip smbtest.zip in the Shared Folder
In the same folder where you are viewing this readme file, there should be a zip file
called "smbtest.zip". Unzip the contents of this zip file in the shared folder.

4. Update Connection Details in connection.ini
In the same folder where you are viewing this readme file, there should be an ini file
called "connection.ini". Edit this file's connection details to match the shared folder's
access information.

5. Run the Unit Tests
Just run: nosetests
