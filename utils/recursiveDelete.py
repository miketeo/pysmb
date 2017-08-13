#!/usr/bin/python2
#
# Simple script to demonstrate how to delete all files/sub-folders in the shared folder
#
from smb.SMBConnection import SMBConnection

dry_run = True  # Set to True to test if all files/folders can be "walked". Set to False to perform the deletion.
userID = 'myuser'
password = 'mypassword'
client_machine_name = 'testclient'   # Usually safe to use 'testclient'
server_name = 'MYSERVER'   # Must match the NetBIOS name of the remote server
server_ip = '192.168.1.10' # Must point to the correct IP address
domain_name = ''           # Safe to leave blank, or fill in the domain used for your remote server
shared_folder = 'smbtest'  # Set to the shared folder name

conn = SMBConnection(userID, password, client_machine_name, server_name, domain=domain_name, use_ntlm_v2=True, is_direct_tcp=True)
conn.connect(server_ip, 445)

def walk_path(path):
    print 'Walking path', path
    for p in conn.listPath(shared_folder, path):
        if p.filename!='.' and p.filename!='..':
            parentPath = path
            if not parentPath.endswith('/'):
                parentPath += '/'

            if p.isDirectory:
                walk_path(parentPath+p.filename)
                print 'Deleting folder (%s) in %s' % ( p.filename, path )
                if not dry_run:
                    conn.deleteDirectory(shared_folder, parentPath+p.filename)
            else:
                print 'Deleting file (%s) in %s' % ( p.filename, path )
                if not dry_run:
                    conn.deleteFiles(shared_folder, parentPath+p.filename)

# Start and delete everything at shared folder root
walk_path('/')
