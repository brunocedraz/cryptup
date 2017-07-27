CryptUp
=======

Upload server that encrypts files before touching the disk.


## Usage

Start the HTTP upload server on port 8000 with

    ./cryptup

then type your password and you can start uploading files.

Decrypt files with

    ./cryptup <encrypted_filename> > <decrypted_filename>

then type the same password used when starting the server.

Optionally start a HTTPS upload server on port 443 with

    ./cryptup -c fullchain.pem -k privkey.pem -p 443


## Installation

Install dependencies with

    pip install futures==3.1.1 pycrypto==2.6.1 tornado==4.5.1

Ubuntu 16.04 might require

    sudo apt install python-dev
