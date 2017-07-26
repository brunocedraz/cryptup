#!/usr/bin/env python
# -*- coding: utf-8 -*-

# pip install futures==3.0.5 pycrypto==2.6.1 tornado==4.3

import argparse
import concurrent.futures
import cgi
import getpass
import logging
import os
import shutil
import struct
import sys
import tempfile
from functools import wraps
from mimetools import Message
from StringIO import StringIO

import tornado
import tornado.options
import tornado.httpclient
import tornado.web
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from tornado import gen
from tornado.web import stream_request_body


TP = concurrent.futures.ThreadPoolExecutor(20)


def generate_key(password, salt=None):
    if not salt:
        salt = Random.get_random_bytes(2) 
    return salt, KDF.PBKDF2(password, salt, 32, 4092)


def disable_client_caching(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self.set_header("Cache-Control", "no-store, must-revalidate, no-cache, max-age=0")
        self.set_header("Expires", "Mon, 01 Jan 1990 00:00:00 GMT")
        self.set_header("Pragma", "no-cache")
        return func(self, *args, **kwargs)
    return wrapper


class UnauthorizedException(Exception):
    def __init__(self, message, cause):
        super(UnauthorizedException, self).__init__(message + u', caused by ' + repr(cause))
        self.cause = cause


class BaseHandler(tornado.web.RequestHandler):
    fail_redirect = '/'

    @disable_client_caching
    def write_error(self, status_code, **kwargs):
        if len(self.fail_redirect) > 0:
            self.redirect(self.fail_redirect) 
        else:
            self.set_status(200)
            if "exc_info" in kwargs:
                if kwargs["exc_info"][0] == UnauthorizedException:
                    self.write('{"status":"unauthorized","message":""}')
                else:
                    self.write('{"status":"failure","message":""}')
            else:
                logging.error("Error " + str(status_code) + ": " + str(kwargs))
                self.write('{"status":"failure","message":""}')

    def set_fail_redirect(self, redirect):
        self.fail_redirect = redirect


@stream_request_body
class UploadHandler(BaseHandler):
    def prepare(self):
        if self.request.method == 'POST':
            self.temp_file = tempfile.NamedTemporaryFile(suffix='.ec')
            self.boundary = ''
            self.fileinfo = ''
            self.status = 0
            self.last_data = ''
            self.boundary_length = 0
            self.boundary_text = ''
            self.enc_buffer = ''
            self.fsize = 0
            self.encrypted = True
            self.salt, self.key = generate_key(PASSWORD)
            self.original_size = 0
            if self.encrypted == True:
                iv = Random.new().read(AES.block_size)
                self.encryptor = AES.new(self.key, AES.MODE_CBC, iv)
                self.temp_file.write(self.salt)
                self.temp_file.write(iv)

    def data_received(self, chunk):
        if self.status == 0:
            self.boundary = self.boundary + chunk
            bpos = self.boundary.find('\r\n')
            if bpos != -1:
                self.boundary = self.boundary[:bpos]
                self.boundary_text = '\r\n' + self.boundary + '--\r\n'
                self.boundary_length = len(self.boundary_text)
                chunk = chunk[bpos + 2:]
                self.status = 1
        if self.status == 1:
            self.fileinfo = self.fileinfo + chunk
            ipos = self.fileinfo.find('\r\n\r\n')
            if ipos != -1:
                self.fileinfo = self.fileinfo[:ipos]
                chunk = chunk[ipos + 4:]
                self.status = 2
        if self.status == 2:
            if self.encrypted:
                self.fsize += len(chunk)
                self.enc_buffer = self.enc_buffer + chunk
                eb_length = len(self.enc_buffer)
                if eb_length >= 16:
                    blocks = eb_length / 16
                    current_buffer = self.enc_buffer[:16 * blocks]
                    self.enc_buffer = self.enc_buffer[16 * blocks:]
                    self.temp_file.write(self.encryptor.encrypt(current_buffer))
                self.last_data = (self.last_data + chunk)[-self.boundary_length:]
                if self.last_data == self.boundary_text:
                    self.original_size = self.fsize - self.boundary_length
                    if len(self.enc_buffer) > 0:
                        if len(self.enc_buffer) % 16 != 0:
                            self.enc_buffer += ' ' * (16 - len(self.enc_buffer) % 16)
                        self.temp_file.write(self.encryptor.encrypt(self.enc_buffer))
                    self.temp_file.write(struct.pack('<Q', self.original_size))
            else:
                self.fsize += len(chunk)
                self.temp_file.write(chunk)
                self.last_data = (self.last_data + chunk)[-self.boundary_length:]
                if self.last_data == self.boundary_text:
                    self.original_size = self.fsize - self.boundary_length
                    self.temp_file.truncate(self.original_size)

    @gen.coroutine
    def post(self):
        if self.original_size > 0:
            yield TP.submit(lambda: self.store_file())
        self.redirect('/') 

    def store_file(self):
        headers = Message(StringIO(self.fileinfo))
        filename = 'noname'
        if 'content-disposition' in headers:
            info = cgi.parse_header(headers['content-disposition'])
            if len(info) > 1 and info[0] == 'form-data':
                filename = info[1].get('filename', 'file')

        filename = os.path.basename(filename)

        basepath = STORAGE_PATH + '/'
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        self.temp_file.seek(0)
        with open(basepath + filename, 'wb') as fdst:
            shutil.copyfileobj(self.temp_file, fdst)
        self.temp_file.close()

        return filename

    def set_default_headers(self):
        r_format = self.get_argument('format', 'web')
        if r_format != 'web':
            origin = self.request.headers.get('Origin')
            if origin is not None:
                self.set_header("Access-Control-Allow-Headers", "Cache-Control, X-Requested-With")
                self.set_header('Access-Control-Allow-Methods', 'POST')

    def options(self):
        self.set_status(204)
        self.finish()


class FrontPageHandler(tornado.web.RequestHandler):
    @disable_client_caching
    def get(self):
        listdir = os.listdir(STORAGE_PATH)

        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write('''<!doctype html>
<html class="no-js" lang="">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title>CryptUp</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body>
    <h1>CryptUp</h1>
    <form enctype="multipart/form-data" action="upload" method="post">
      <input name="upload" id="upload" type="file"></input>
      <br/>
      <input type="submit" value="upload"></input>
    </form>
    <br/><br/><br/>
    ''' + ('<h3>Uploaded files</h3>' if len(listdir) > 0 else '') + '<br/><br/>'.join(listdir) + '''
  </body>
</html>''')

    def compute_etag(self):
        return None


class FaviconHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_status(404)

    def compute_etag(self):
        return None


class PingHandler(tornado.web.RequestHandler):
    @disable_client_caching
    def get(self):
        self.set_header("Content-Type", "application/json; charset=utf-8")
        self.write("pong")

    def compute_etag(self):
        return None


class ErrorHandler(tornado.web.ErrorHandler, BaseHandler):
    pass


def decrypt_file(password, in_fd, out_fd, chunksize=4*1024):
    in_fd.seek(0)
    salt = in_fd.read(2)

    _, key = generate_key(PASSWORD, salt)

    size_len = struct.calcsize('Q')
    in_fd.seek(-size_len, 2)
    in_eof = in_fd.tell()
    origsize = struct.unpack('<Q', in_fd.read(size_len))[0]
    in_fd.seek(2)
    iv = in_fd.read(AES.block_size)
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    in_pos = in_fd.tell()
    decrypted_size = 0
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
        output = decryptor.decrypt(chunk)
        output_size = len(output)
        decrypted_size += output_size
        if decrypted_size > origsize:
            out_fd.write(output[:output_size - (decrypted_size - origsize)])
            break

        out_fd.write(output)
        if in_pos == in_eof:
            break


if __name__ == "__main__":
    STORAGE_PATH = os.path.realpath('storage')
    SERVER_PORT = 8000


    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('encrypted_file',
                        nargs='?',
                        help='decrypt file instead of running server')
    parser.add_argument('-p',
                        '--port',
                        dest='SERVER_PORT',
                        default=SERVER_PORT,
                        type=int,
                        help='run server on the given port')

    parser.add_argument('-s',
                        '--storage',
                        dest='STORAGE_PATH',
                        default=STORAGE_PATH,
                        type=str,
                        help='directory to store uploaded files')

    args = parser.parse_args()

    if args.encrypted_file is not None:
        PASSWORD = getpass.getpass("Type encryption password: ")

        with open(args.encrypted_file, 'rb') as f:
            decrypt_file(PASSWORD, f, sys.stdout)

    else:
        while True:
            PASSWORD = getpass.getpass("Type encryption password: ")
            CONFIRM = getpass.getpass("Confirm password: ")
            if PASSWORD == CONFIRM:
                break
            print('Passwords do not match. Try again...')

        STORAGE_PATH = os.path.realpath(args.STORAGE_PATH)
        
        if not os.path.exists(STORAGE_PATH):
            os.makedirs(STORAGE_PATH)

        application = tornado.web.Application([
                (r"/upload", UploadHandler),  # POST
                (r"/", FrontPageHandler),  # GET
                (r"/favicon.ico", FaviconHandler),  # GET

                (r"/ping", PingHandler),  # GET
           ],
           default_handler_class=ErrorHandler,
           default_handler_args=dict(status_code=404),
           debug=False
        )

        application.listen(args.SERVER_PORT,
                           max_buffer_size=300 * (1024*1024))
        print("Starting server...")
        tornado.ioloop.IOLoop.instance().start()

