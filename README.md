CryptUp
=======

Upload server that encrypts files before reaching the disk.


## Usage

Start the upload server with

    ./cryptup.py

then type your password and you can start uploading files.

Decrypt files with

    ./cryptup.py <encrypted_filename> > <decrypted_filename>

then type the same password used when starting the server.


## Installation

Install dependencies with

    pip install futures==3.0.5 pycrypto==2.6.1 tornado==4.3
