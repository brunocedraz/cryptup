CryptUp
=======

Upload server that encrypts files before touching the disk.


## Usage

Start the upload server on port 8000 with

    ./cryptup

then type your password and you can start uploading files.

Decrypt files with

    ./cryptup <encrypted_filename> > <decrypted_filename>

then type the same password used when starting the server.


## Installation

Install dependencies with

    pip install futures==3.1.1 pycrypto==2.6.1 tornado==4.5.1
