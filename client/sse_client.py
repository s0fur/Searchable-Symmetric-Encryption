# Copyright (c) Ian Van Houdt 2015

############
#
#  sse_client.py
#
#  Serves as SSE implementation for mail client. The routines 
#  for SSE are invoked by the client module via the API.
#
############

import socket
import os
import sys
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import bcrypt
from argparse import ArgumentParser

DEBUG = 1

########
#
# Client_SSE
#
########
class Client_SSE():

    def __init__(self):

        # need to either set up index, or load it in from file

        # placeholder for password. Will eventually take
        # as an arg of some sort
        self.password = b"password"
        self.salt = 42

        # Two keys, generated/Initialized by KDF
        (self.k, self.kPrime) = self.initKeys()

        # Pseudorandom func: HMAC.
        # default digestmod is Crypto.Hash.MD5 
        self.prf = HMAC.new(self.k)

        # Two K's: generated/initialized by PRF
        self.k1 = None
        self.k2 = None

        # client's cipher (AES w/ CBC)
        self.cipher = self.initCipher()

    def initKeys(self):
        # initialize keys k & kPrime
        # k used for PRF; kPrime used for Enc/Dec
        # return (k, kPrime)

        #password = b"password"

        hashed = bcrypt.hashpw(self.password, bcrypt.gensalt())

        if bcrypt.hashpw(self.password, hashed) == hashed:
            if (DEBUG): print "PW match!"
        else:
            if (DEBUG): print "No PW match!"
            exit(1)

        if(DEBUG): print("len of k = %d" % len(hashed))

        # Currently k and kPrime are ==
        # TODO: how to do the two keys?
        return (hashed, hashed)

    def initCipher(self):
        # initialize Cipher, using kPrime
        # return new Cipher object

        # TODO: fix key. Currently just a hack: AES keys must be
        # 16, 24 or 32 bytes long, but kPrime is 60
        key = self.kPrime[:16]
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        return cipher

    def encryptMail(self, infile, outfile):
        # python sse_client.py -e ../mail/message1.txt encM1.txt

        buf = infile.read()
        if buf == '': 
            print("[Enc] mail to encrypt is empty!\nExiting\n")
            exit(1)

        if (DEBUG): print("[Enc] mail to encrypt: %s\n" % (buf))

        #method = sse.cipher.encrypt

        while len(buf)%16 != 0:
            buf = buf + "\x08"

        #outfile.write(method(buf))
        outfile.write(self.cipher.encrypt(buf))
        outfile.close()        

    def decryptMail(self, mailName):

        pass

def debugEcho(msg):
    if (DEBUG):
        print ("[Client-BackEnd] Msg from client: %s" % (msg))


def main():

    # Set-up a command-line argument parser
    parser = ArgumentParser(description=__doc__, epilog="""Input is read from
        stdin and output is written to stdout. Use the stream redirection
        features of your shell to pass data through this program. If a key is
        not specified, it is generated and written to stderr.""")
    parser.add_argument('-s', '--search', action='store_true')
    parser.add_argument('-u', '--update', action='store_true')
    parser.add_argument('-e', '--encrypt', metavar='encrypt_file', 
                        dest='encrypt_file', nargs='*')
    parser.add_argument('-d', '--decrypt', action='store_true')
    parser.add_argument('-k', '--key', metavar='key')
    args = parser.parse_args()
    print args
 
    sse = Client_SSE()

    # Decode the key if it was supplied
    # key = base64.b64decode(args.key) if args.key else None


    if args.encrypt_file:
        infile = open(args.encrypt_file[0], "r")        
        outfile = open(args.encrypt_file[1], "w+")
        sse.encryptMail(infile, outfile)

    elif args.decrypt:
        pass

    else:
        print "Must specify encrypt or decrypt!"
        exit(1)


if __name__ == "__main__":
    main()
