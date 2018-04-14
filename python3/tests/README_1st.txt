
Steps to Follow to Run the Unit Tests
=====================================

1. Install Nose Testing Framework
All the unit tests here are designed to be conducted with the nose testing framework.
You can install the latest nose testing framework by running: easy_install nose
For more information on nose testing, please visit http://readthedocs.org/docs/nose/en/latest/

2. Prepare a Shared Folder "smbtest" on a Remote Server
To run the unit tests here, besides installing the nose testing framework, you will
also need to prepare a shared folder on a remote server.
pysmb has been tested against Samba 3.x, Windows XP SP3 and Windows Vista.
The shared folder must be named "smbtest".

3. Download smbtest.zip from https://miketeo.net/files/Projects/pysmb/smbtest.zip
Unzip the contents of this zip file in the shared folder.

4. Update Connection Details in connection.ini
In the same folder where you are viewing this readme file, there should be an ini file
called "connection.ini". Edit this file's connection details to match the shared folder's
access information.

5. Run the Unit Tests in the python2 folder
Just run: nosetests3 -v tests
or selectively: nosetests3 -v tests/SMBConnectionTests
