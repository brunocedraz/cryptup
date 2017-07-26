#!/usr/bin/env python
# -*- coding: utf-8 -*-

import getpass
import struct
import sys
from Crypto.Cipher import AES

import cryptup


def decrypt_file(password, in_fd, out_fd, chunksize=4*1024):
    in_fd.seek(0)
    salt = in_fd.read(2)

    _, key = cryptup.generate_key(PASSWORD, salt)

    size_len = struct.calcsize('Q')
    in_fd.seek(-size_len, 2)
    in_eof = in_fd.tell()
    origsize = struct.unpack('<Q', in_fd.read(size_len))[0]
    in_fd.seek(2)
    iv = in_fd.read(AES.block_size)
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    in_pos = in_fd.tell()
    while True:
        read_size = chunksize
        in_pos += read_size
        if in_pos >= in_eof:
            read_size -= (in_pos - in_eof)
            in_pos -= (in_pos - in_eof)

        if read_size == 0:
            break
        chunk = in_fd.read(read_size)
        if len(chunk) == 0:
            break
        out_fd.write(decryptor.decrypt(chunk))
        if in_pos == in_eof:
            break

    out_fd.seek(0) 
    out_fd.truncate(origsize)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('USAGE: ' + sys.argv[0] + ' <filename>')
        exit(0)
    
    PASSWORD = getpass.getpass("Type encryption password: ")
    file_path = sys.argv[1]

    with open(file_path, 'rb') as f:
        decrypt_file(PASSWORD, f, sys.stdout)

