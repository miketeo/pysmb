# -*- mode: python; tab-width: 4 -*-
# $Id: smb.py,v 1.3 2001-08-23 15:26:30 miketeo Exp $
#
# Copyright (C) 2001 Michael Teo <michaelteo@bigfoot.com>
# smb.py - SMB/CIFS library
#
# This software is provided 'as-is', without any express or implied warranty. 
# In no event will the author be held liable for any damages arising from the 
# use of this software.
#
# Permission is granted to anyone to use this software for any purpose, 
# including commercial applications, and to alter it and redistribute it 
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not 
#    claim that you wrote the original software. If you use this software 
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be 
#    misrepresented as being the original software.
#
# 3. This notice cannot be removed or altered from any source distribution.
#

import os, sys, socket, string, re, select, errno
import nmb
from random import randint
from struct import *



VERSION = '0.1.1'
CVS_REVISION = '$Revision: 1.3 $'

# Shared Device Type
SHARED_DISK = 0x00
SHARED_PRINT_QUEUE = 0x01
SHARED_DEVICE = 0x02
SHARED_IPC = 0x03

# Extended attributes mask
ATTR_ARCHIVE = 0x020
ATTR_COMPRESSED = 0x800
ATTR_NORMAL = 0x080
ATTR_HIDDEN = 0x002
ATTR_READONLY = 0x001
ATTR_TEMPORARY = 0x100
ATTR_DIRECTORY = 0x010
ATTR_SYSTEM = 0x004

# SMB Command Codes
SMB_COM_CREATE_DIR = 0x00
SMB_COM_DELETE_DIR = 0x01
SMB_COM_CLOSE = 0x04
SMB_COM_DELETE = 0x06
SMB_COM_RENAME = 0x07
SMB_COM_CHECK_DIR = 0x10
SMB_COM_READ_RAW = 0x1a
SMB_COM_WRITE_RAW = 0x1d
SMB_COM_TRANSACTION = 0x25
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_OPEN_ANDX = 0x2d
SMB_COM_READ_ANDX = 0x2e
SMB_COM_WRITE_ANDX = 0x2f
SMB_COM_TREE_DISCONNECT = 0x71
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75

# Service Type
SERVICE_DISK = 'A:'
SERVICE_PRINTER = 'LPT1:'
SERVICE_IPC = 'IPC'
SERVICE_COMM = 'COMM'
SERVICE_ANY = '?????'

# Options values for SMB.stor_file and SMB.retr_file
SMB_O_CREAT = 0x10   # Create the file if file does not exists. Otherwise, operation fails.
SMB_O_EXCL = 0x00    # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
SMB_O_OPEN = 0x01    # Open the file if the file exists
SMB_O_TRUNC = 0x02   # Truncate the file if the file exists

# Share Access Mode
SMB_SHARE_COMPAT = 0x00
SMB_SHARE_DENY_EXCL = 0x10
SMB_SHARE_DENY_WRITE = 0x20
SMB_SHARE_DENY_READEXEC = 0x30
SMB_SHARE_DENY_NONE = 0x40
SMB_ACCESS_READ = 0x00
SMB_ACCESS_WRITE = 0x01
SMB_ACCESS_READWRITE = 0x02
SMB_ACCESS_EXEC = 0x03



def strerror(errclass, errcode):
    if errclass == 0x01:
        return 'OS error', ERRDOS.get(errcode, 'Unknown error')
    elif errclass == 0x02:
        return 'Server error', ERRSRV.get(errcode, 'Unknown error')
    elif errclass == 0x03:
        return 'Hardware error', ERRHRD.get(errcode, 'Unknown error')
    elif errclass == 0xff:
        return 'Bad command', 'Bad command. Please file bug report'
    else:
        return 'Unknown error', 'Unknown error'

    

class SessionError(Exception): pass

# Contains information about a SMB shared device/service
class SharedDevice:

    def __init__(self, name, type, comment):
        self.__name = name
        self.__type = type
        self.__comment = comment

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def get_comment(self):
        return self.__comment

    def __repr__(self):
        return '<SharedDevice instance: name=' + self.__name + ', type=' + str(self.__type) + ', comment="' + self.__comment + '">'



# Contains information about the shared file/directory
class SharedFile:

    def __init__(self, ctime, atime, mtime, filesize, allocsize, attribs, shortname, longname):
        self.__ctime = ctime
        self.__atime = atime
        self.__mtime = mtime
        self.__filesize = filesize
        self.__allocsize = allocsize
        self.__attribs = attribs
        self.__shortname = shortname
        self.__longname = longname

    def get_ctime(self):
        return self.__ctime

    def get_mtime(self):
        return self.__mtime

    def get_atime(self):
        return self.__atime

    def get_filesize(self):
        return self.__filesize

    def get_allocsize(self):
        return self.__allocsize

    def get_attributes(self):
        return self.__attribs

    def is_archive(self):
        return self.__attribs & ATTR_ARCHIVE

    def is_compressed(self):
        return self.__attribs & ATTR_COMPRESSED

    def is_normal(self):
        return self.__attribs & ATTR_NORMAL

    def is_hidden(self):
        return self.__attribs & ATTR_HIDDEN

    def is_readonly(self):
        return self.__attribs & ATTR_READONLY

    def is_temporary(self):
        return self.__attribs & ATTR_TEMPORARY

    def is_directory(self):
        return self.__attribs & ATTR_DIRECTORY

    def is_system(self):
        return self.__attribs & ATTR_SYSTEM

    def get_shortname(self):
        return self.__shortname

    def get_longname(self):
        return self.__longname

    def __repr__(self):
        return '<SharedFile instance: shortname="' + self.__shortname + '", longname="' + self.__longname + '", filesize=' + str(self.__filesize) + '>'

    

# Represents a SMB session
class SMB:

    def __init__(self, remote_name, remote_host, my_name = None, sess_port = nmb.NETBIOS_SESSION_PORT):
        # The uid attribute will be set when the client calls the login() method
        self.__uid = 0
        self.__remote_name = remote_name
        
        if not my_name:
            my_name = 'PYSMB' + str(randint(1, 10000))
            
        self.__sess = nmb.NetBIOSSession(my_name, remote_name, remote_host, sess_port)
        _, self.__login_required, self.__max_transmit_size, rawmode = self.__neg_session()
        self.__can_read_raw = rawmode & 0x01
        self.__can_write_raw = rawmode & 0x02

    def __decode_smb(self, data):
        _, cmd, err_class, _, err_code, flags1, flags2, _, tid, pid, uid, mid, wcount = unpack('<4sBBBHBH12sHHHHB', data[:33])
        param_end = 33 + wcount * 2
        return cmd, err_class, err_code, flags1, flags2, tid, uid, mid, data[33:param_end], data[param_end + 2:]

    def __decode_trans(self, params, data):
        totparamcnt, totdatacnt, _, paramcnt, paramoffset, paramds, datacnt, dataoffset, datads, setupcnt = unpack('<HHHHHHHHHB', params[:19])
        if paramcnt + paramds < totparamcnt or datacnt + datads < totdatacnt:
            has_more = 1
        else:
            has_more = 0
        paramoffset = paramoffset - 55 - setupcnt * 2
        dataoffset = dataoffset - 55 - setupcnt * 2
        return has_more, params[20:20 + setupcnt * 2], data[paramoffset:paramoffset + paramcnt], data[dataoffset:dataoffset + datacnt]

    def __send_smb_packet(self, cmd, status, flags, flags2, tid, mid, params = '', data = ''):
        wordcount = len(params)
        assert wordcount & 0x1 == 0
        
        self.__sess.send_packet(pack('<4sBLBH12sHHHHB', '\xffSMB', cmd, status, flags, flags2, '\0' * 12, tid, os.getpid(), self.__uid, mid, wordcount / 2) + params + pack('<H', len(data)) + data)

    def __neg_session(self, timeout = None):
        self.__send_smb_packet(SMB_COM_NEGOTIATE, 0, 0, 0, 0, 0, data = '\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00')

        while 1:
            data = self.__sess.recv_packet(timeout)
            if data:
                cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                if cmd == SMB_COM_NEGOTIATE and flags1 | 0x80:
                    if err_class == 0x00 and err_code == 0x00:
                        sel_dialect, auth, max_buf_size, _, rawmode = unpack('<HHH4sH', params[:12])
                        return sel_dialect, auth, max_buf_size, rawmode
                    else:
                        raise SessionError, ( "Cannot neg dialect. (ErrClass: %d and ErrCode: %d)" % ( err_class, err_code ), err_class, err_code )
            
    def __connect_tree(self, path, service, timeout = None):
        self.__send_smb_packet(SMB_COM_TREE_CONNECT_ANDX, 0, 0, 0, 0, 0, pack('<BBHHH', 0xff, 0, 0, 0, 1), '\0' + path + '\0' + service + '\0')

        while 1:
            data = self.__sess.recv_packet(timeout)
            if data:
                cmd, err_class, err_code, flags1, flags2, tid, _, mid, params, d = self.__decode_smb(data)
                if cmd == SMB_COM_TREE_CONNECT_ANDX and flags1 | 0x80:
                    if err_class == 0x00 and err_code == 0x00:
                        return tid
                    else:
                        raise SessionError, ( "Cannot connect tree. (ErrClass: %d and ErrCode: %d)" % ( err_class, err_code ), err_class, err_code )

    def __disconnect_tree(self, tid):
        self.__send_smb_packet(SMB_COM_TREE_DISCONNECT, 0, 0, 0, tid, 0, '', '')

    def __open_file(self, tid, filename, open_mode, access_mode, timeout = None):
        self.__send_smb_packet(SMB_COM_OPEN_ANDX, 0, 0, 0, tid, 0, pack('<BBHHHHHLHLLL', 0xff, 0, 0, 0, access_mode, ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE, 0, 0, open_mode, 0, 0, 0), filename + '\x00')
        
        while 1:
            data = self.__sess.recv_packet(timeout)
            if data:
                cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                if cmd == SMB_COM_OPEN_ANDX:
                    if err_class == 0x00 and err_code == 0x00:
                        offset = unpack('<H', params[2:4])[0]
                        fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = unpack('<HHLLHHHHL', params[4+offset:28+offset])
                        return fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid
                    else:
                        raise SessionError, ( 'Open file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        
    def __close_file(self, tid, fid):
        self.__send_smb_packet(SMB_COM_CLOSE, 0, 0, 0, tid, 0, pack('<HL', fid, 0), '')

    def __trans(self, tid, setup, name, param, data, timeout = None):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB_COM_TRANSACTION, 0, 0, 0, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, 65504, 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name + param + data)

    def __trans2(self, tid, setup, name, param, data, timeout = None):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB_COM_TRANSACTION2, 0, 0, 0, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, 65504, 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name + param + data)

    def __nonraw_retr_file(self, tid, fid, offset, datasize, callback, timeout = None):
        max_buf_size = self.__max_transmit_size & ~0x3ff  # Read in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            self.__send_smb_packet(SMB_COM_READ_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_READ_ANDX:
                        if err_class == 0x00 and err_code == 0x00:
                            offset = unpack('<H', params[2:4])[0]
                            data_len, dataoffset = unpack('<HH', params[10+offset:14+offset])
                            if data_len == len(d):
                                callback(d)
                            else:
                                callback(d[dataoffset - 59:dataoffset - 59 + data_len])
                                read_offset = read_offset + data_len
                            break
                        else:
                            raise SessionError, ( 'Non-raw retr file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

    def __raw_retr_file(self, tid, fid, offset, datasize, callback, timeout = None):
        read_offset = offset
        while read_offset < datasize:
            self.__send_smb_packet(SMB_COM_READ_RAW, 0, 0, 0, tid, 0, pack('<HLHHLH', fid, read_offset, 0xffff, 0, 0, 0), '')
            data = self.__sess.recv_packet(timeout)
            if data:
                callback(data)
                read_offset = read_offset + len(data)
            else:
                # No data returned. Need to send SMB_COM_READ_ANDX to find out what is the error.
                self.__send_smb_packet(SMB_COM_READ_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    data = self.__sess.recv_packet(timeout)
                    if data:
                        cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                        if cmd == SMB_COM_READ_ANDX:
                            if err_class == 0x00 and err_code == 0x00:
                                offset = unpack('<H', params[2:4])[0]
                                data_len, dataoffset = unpack('<HH', params[10+offset:14+offset])
                                if data_len == 0:
                                    # Premature EOF!
                                    return
                                # By right we should not have data returned in the reply.
                                elif data_len == len(d):
                                    callback(d)
                                else:
                                    callback(d[dataoffset - 59:dataoffset - 59 + data_len])
                                read_offset = read_offset + data_len
                                break
                            else:
                                raise SessionError, ( 'Raw retr file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

    def __nonraw_stor_file(self, tid, fid, offset, datasize, callback, timeout = None):
        max_buf_size = self.__max_transmit_size & ~0x3ff  # Write in multiple KB blocks
        write_offset = offset
        while 1:
            data = callback(max_buf_size)
            if not data:
                break
            
            self.__send_smb_packet(SMB_COM_WRITE_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, fid, write_offset, 0, 0, 0, 0, len(data), 59), data)
            
            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_WRITE_ANDX:
                        if err_class == 0x00 and err_code == 0x00:
                            offset = unpack('<H', params[2:4])[0]
                            write_offset = write_offset + unpack('<H', params[4+offset:6+offset])[0]
                            break
                        else:
                            raise SessionError, ( 'Non-raw store file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

    def __raw_stor_file(self, tid, fid, offset, datasize, callback, timeout = None):
        write_offset = offset
        while 1:
            read_data = callback(65535)
            if not read_data:
                break

            read_len = len(read_data)
            self.__send_smb_packet(SMB_COM_WRITE_RAW, 0, 0, 0, tid, 0, pack('<HHHLLHLHH', fid, read_len, 0, write_offset, 0, 0, 0, 0, 59), '')
            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_WRITE_RAW:
                        if err_class == 0x00 and err_code == 0x00:
                            self.__sess.send_packet(read_data)
                            write_offset = write_offset + read_len
                            break
                        else:
                            raise SessionError, ( 'Raw store file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

        # We need to close fid to check whether the last raw packet is written successfully
        self.__send_smb_packet(SMB_COM_CLOSE, 0, 0, 0, tid, 0, pack('<HL', fid, 0), '')
        while 1:
            data = self.__sess.recv_packet(timeout)
            if data:
                cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                if cmd == SMB_COM_CLOSE:
                    if err_class == 0x00 and err_code == 0x00:
                        return
                    else:
                        raise SessionError, ( 'Raw store file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

    def is_login_required(self):
        return self.__login_required

    def login(self, name, password, domain = '', timeout = None):
        self.__send_smb_packet(SMB_COM_SESSION_SETUP_ANDX, 0, 0, 0, 0, 0, pack('<ccHHHHLHL', '\xff', '\0', 0, 65535, 2, 0, 0, len(password), 0), password + name + '\0' + domain + '\0' + os.name + '\0' + 'pysmb\0')

        while 1:
            data = self.__sess.recv_packet(timeout)
            if data:
                cmd, err_class, err_code, flags1, flags2, _, uid, mid, params, d = self.__decode_smb(data)
                if cmd == SMB_COM_SESSION_SETUP_ANDX:
                    if err_class == 0x00 and err_code == 0x00:
                        # We will need to use this uid field for all future requests/responses
                        self.__uid = uid
                        return 1
                    else:
                        raise SessionError, ( 'Authentication failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )

    def list_shared(self, timeout = None):
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\IPC$', SERVICE_ANY, timeout)
        self.__trans(tid, '', '\\PIPE\\LANMAN\0', '\x00\x00WrLeh\0B13BWz\0\x01\x00\xe0\xff', '')

        try:
            share_list = [ ]
            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_TRANSACTION:
                        if err_class == 0x00 and err_code == 0x00:
                            has_more, _, transparam, transdata = self.__decode_trans(params, d)
                            converter, numentries = unpack('<HH', transparam[2:6])
                            maxlength = len(transdata)
                            offset = 0
                            for i in range(0, numentries):
                                name = transdata[offset:string.find(transdata, '\0', offset)]
                                type, commentoffset = unpack('<HH', transdata[offset + 14:offset + 18])
                                if commentoffset > maxlength:
                                    comment = ''
                                else:
                                    comment = transdata[commentoffset:string.find(transdata, '\0', commentoffset)]
                                offset = offset + 20
                                share_list.append(SharedDevice(name, type, comment))
                            return share_list
                        else:
                            raise SessionError, ( 'List directory failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def list_path(self, service, path = '*', timeout = None):
        path = string.replace(path, '/', '\\')
            
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__trans2(tid, '\x01\x00', '\x00', '\x16\x00\x00\x02\x06\x00\x04\x01\x00\x00\x00\x00\x5c' + path + '\x00', '')
            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_TRANSACTION2:
                        if err_class == 0x00 and err_code == 0x00:
                            has_more, _, transparam, transdata = self.__decode_trans(params, d)
                            sid, searchcnt, eos, erroffset, lastnameoffset = unpack('<HHHHH', transparam)
                            files = [ ]
                            offset = 0
                            data_len = len(transdata)
                            while offset < data_len:
                                nextentry, fileindex, lowct, highct, lowat, highat, lowmt, highmt, lowcht, hightcht, loweof, higheof, lowsz, highsz, attrib, longnamelen, easz, shortnamelen = unpack('<lL12LLlLB', transdata[offset:offset + 69])
                                files.append(SharedFile(highct << 32 | lowct, highat << 32 | lowat, highmt << 32 | lowmt, higheof << 32 | loweof, highsz << 32 | lowsz, attrib, transdata[offset + 70:offset + 70 + shortnamelen], transdata[offset + 94:offset + 94 + longnamelen]))
                                offset = offset + nextentry
                            return files
                        else:
                            raise SessionError, ( 'List path failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def retr_file(self, service, filename, callback, mode = SMB_O_OPEN, offset = 0, timeout = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.__open_file(tid, filename, mode, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if self.__can_read_raw:
                self.__raw_retr_file(tid, fid, offset, datasize, callback)
            else:
                self.__nonraw_retr_file(tid, fid, offset, datasize, callback, timeout)
        finally:
            if fid >= 0:
                self.__close_file(tid, fid)
            self.__disconnect_tree(tid)

    def stor_file(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, timeout = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.__open_file(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)

            if self.__can_write_raw:
                # Once the __raw_write_file returns, fid is already closed
                self.__raw_stor_file(tid, fid, offset, datasize, callback, timeout)
                fid = -1
            else:
                self.__nonraw_stor_file(tid, fid, offset, datasize, callback, timeout)
        finally:
            if fid >= 0:
                self.__close_file(tid, fid)
            self.__disconnect_tree(tid)

    def copy(self, src_service, src_path, dest_service, dest_path, callback = None, write_mode = SMB_O_CREAT | SMB_O_TRUNC, timeout = None):
        dest_path = string.replace(dest_path, '/', '\\')
        src_path = string.replace(src_path, '/', '\\')
        src_tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + src_service, SERVICE_ANY, timeout)

        dest_tid = -1
        try:
            if src_service == dest_service:
                dest_tid = src_tid
            else:
                dest_tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + dest_service, SERVICE_ANY, timeout)
            
            dest_fid = self.__open_file(dest_tid, dest_path, write_mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)[0]
            src_fid, _, _, src_datasize, _, _, _, _, _ = self.__open_file(src_tid, src_path, SMB_O_OPEN, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if callback:
                callback(0, src_datasize)

            max_buf_size = (self.__max_transmit_size >> 10) << 10
            read_offset = 0
            write_offset = 0
            while read_offset < src_datasize:
                self.__send_smb_packet(SMB_COM_READ_ANDX, 0, 0, 0, src_tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, src_fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    data = self.__sess.recv_packet(timeout)
                    if data:
                        cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                        if cmd == SMB_COM_READ_ANDX:
                            if err_class == 0x00 and err_code == 0x00:
                                offset = unpack('<H', params[2:4])[0]
                                data_len, dataoffset = unpack('<HH', params[10+offset:14+offset])
                                if data_len == len(d):
                                    self.__send_smb_packet(SMB_COM_WRITE_ANDX, 0, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d)
                                else:
                                    self.__send_smb_packet(SMB_COM_WRITE_ANDX, 0, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d[dataoffset - 59:dataoffset - 59 + data_len])
                                while 1:
                                    data = self.__sess.recv_packet(timeout)
                                    if data:
                                        cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                                        if cmd == SMB_COM_WRITE_ANDX:
                                            if err_class == 0x00 and err_code == 0x00:
                                                offset = unpack('<H', params[2:4])[0]
                                                write_offset = write_offset + unpack('<H', params[4+offset:6+offset])[0]
                                                break
                                            else:
                                                raise SessionError, ( 'Copy (write) failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
                                read_offset = read_offset + data_len
                                if callback:
                                    callback(read_offset, src_datasize)
                                break
                            else:
                                raise SessionError, ( 'Copy (read) failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
                
        finally:
            self.__disconnect_tree(src_tid)
            if dest_tid > -1 and src_service != dest_service:
                self.__disconnect_tree(dest_tid)

    def check_dir(self, service, path, timeout = None):
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__send_smb_packet(SMB_COM_CHECK_DIR, 0, 0, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_CHECK_DIR:
                        if err_class == 0x00 and err_code == 0x00:
                            return
                        else:
                            raise SessionError, ( 'Check directory failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def remove(self, service, path, timeout = None):
        # Perform a list to ensure the path exists
        self.list_path(service, path, timeout)

        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__send_smb_packet(SMB_COM_DELETE, 0, 0, 0, tid, 0, pack('<H', ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCHIVE), '\x04' + path + '\x00')

            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_DELETE:
                        if err_class == 0x00 and err_code == 0x00:
                            return
                        else:
                            raise SessionError, ( 'Delete file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def rmdir(self, service, path, timeout = None):
        # Check that the directory exists
        self.check_dir(service, path, timeout)

        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__send_smb_packet(SMB_COM_DELETE_DIR, 0, 0, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_DELETE_DIR:
                        if err_class == 0x00 and err_code == 0x00:
                            return
                        else:
                            raise SessionError, ( 'Delete directory failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def mkdir(self, service, path, timeout = None):
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__send_smb_packet(SMB_COM_CREATE_DIR, 0, 0, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_CREATE_DIR:
                        if err_class == 0x00 and err_code == 0x00:
                            return
                        else:
                            raise SessionError, ( 'Create directory failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)

    def rename(self, service, old_path, new_path, timeout = None):
        tid = self.__connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, timeout)
        try:
            self.__send_smb_packet(SMB_COM_RENAME, 0, 0, 0, tid, 0, pack('<H', ATTR_SYSTEM | ATTR_HIDDEN | ATTR_DIRECTORY), '\x04' + old_path + '\x00\x04' + new_path + '\x00')

            while 1:
                data = self.__sess.recv_packet(timeout)
                if data:
                    cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                    if cmd == SMB_COM_RENAME:
                        if err_class == 0x00 and err_code == 0x00:
                            return 
                        else:
                            raise SessionError, ( 'Rename failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code ), err_class, err_code )
        finally:
            self.__disconnect_tree(tid)



ERRDOS = { 1: 'Invalid function',
           2: 'File not found',
           3: 'Invalid directory',
           4: 'Too many open files',
           5: 'Access denied',
           6: 'Invalid file handle. Please file a bug report.',
           7: 'Memory control blocks destroyed',
           8: 'Out of memory',
           9: 'Invalid memory block address',
           10: 'Invalid environment',
           11: 'Invalid format',
           12: 'Invalid open mode',
           13: 'Invalid data',
           15: 'Invalid drive',
           16: 'Attempt to remove server\'s current directory',
           17: 'Not the same device',
           18: 'No files found',
           32: 'Sharing mode conflicts detected',
           33: 'Lock request conflicts detected',
           80: 'File already exists'
           }

ERRSRV = { 1: 'Non-specific error',
           2: 'Bad password',
           4: 'Access denied',
           5: 'Invalid tid. Please file a bug report.',
           6: 'Invalid network name',
           7: 'Invalid device',
           49: 'Print queue full',
           50: 'Print queue full',
           51: 'EOF on print queue dump',
           52: 'Invalid print file handle',
           64: 'Command not recognized. Please file a bug report.',
           65: 'Internal server error',
           67: 'Invalid path',
           69: 'Invalid access permissions',
           71: 'Invalid attribute mode',
           81: 'Server is paused',
           82: 'Not receiving messages',
           83: 'No room to buffer messages',
           87: 'Too many remote user names',
           88: 'Operation timeout',
           89: 'Out of resources',
           91: 'Invalid user handle. Please file a bug report.',
           250: 'Temporarily unable to support raw mode for transfer',
           251: 'Temporarily unable to support raw mode for transfer',
           252: 'Continue in MPX mode',
           65535: 'Unsupported function'
           }

ERRHRD = { 19: 'Media is write-protected',
           20: 'Unknown unit',
           21: 'Drive not ready',
           22: 'Unknown command',
           23: 'CRC error',
           24: 'Bad request',
           25: 'Seek error',
           26: 'Unknown media type',
           27: 'Sector not found',
           28: 'Printer out of paper',
           29: 'Write fault',
           30: 'Read fault',
           31: 'General failure',
           32: 'Open conflicts with an existing open',
           33: 'Invalid lock request',
           34: 'Wrong disk in drive',
           35: 'FCBs not available',
           36: 'Sharing buffer exceeded'
           }
