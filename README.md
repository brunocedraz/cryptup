CryptUp
=======

Upload server that encrypts files before reaching the disk.


## Usage

Start the upload server with

    ./cryptup.py --port=8000

then type your password and you can start uploading files.

Decrypt files with

    ./decrypt.py <filename>

then type the same password used when starting the server.


## Installation

Install the dependencies by typing

    pip install futures==3.0.5 pycrypto==2.6.1 tornado==4.3
