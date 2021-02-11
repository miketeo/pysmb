
Steps to Follow to Run the Unit Tests
=====================================

## Step 1: Install system dependencies ##

If you are using Ubuntu 20.04 LTS, you can install the system dependencies with the following command
```
$> apt-get install virtualenv python-dev gcc g++ make automake autoconf
```
For other distributions, you can use their package managers and install the system dependencies (although the package names might differ slightly).

## Step 2: Setup python virtualenv ##

We will create a python2 virtualenv and install the python dependencies for testing in the "venv2" folder.

```
$> cd <pysmb-home>/python2
$> virtualenv -p /usr/bin/python2 venv2
$> source venv2/bin/activate
$venv2> pip install nose pyasn1 twisted
```

## Step 3: Setup shared folder on your remote SMB server ##

Prepare a shared folder called "smbtest" on your remote SMB server (Windows or Samba). 

Then, download [smbtest.zip](https://miketeo.net/files/Projects/pysmb/smbtest.zip) and unzip the contents of this zip file in the shared folder.

You should also configure a user on the SMB server with read-write access to the "smbtest" folder.

## Step 4: Update connection details in connection.ini ##

In the same folder where you are viewing this readme file, there should be an ini file called "connection.ini". Edit this file's connection details to match the shared folder's access information.

## Step 5: Run the unit tests in the python2 folder ##

Before running the tests, the venv2 virtualenv must be activated.
```
$> cd <pysmb-home>/python2
$> source venv2/bin/activate
```

To run all the tests:
```
    $venv2> nosetests -v tests
```

To selectively run some tests: 
```
    $venv2> nosetests -v tests/SMBConnectionTests
    $venv2> nosetests -v tests/SMBConnectionTests/test_rename.py
    $venv2> nosetests -v tests/SMBConnectionTests/test_rename.py:test_rename_english_file_SMB1
```

For more information, please consult the [documentation for nose](https://nose.readthedocs.io/).


