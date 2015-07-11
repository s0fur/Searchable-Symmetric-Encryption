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
import binascii

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

        # TODO: need to sort out use of salt. Previously, salt was
        # randomly generated in initKeys, but the resulting pass-
        # words k & kPrime were different on each execution, and 
        # decryption was impossible. Hardcoding salt makes dectyption
        # possible but may be a bad short cut
        self.iv = None
        self.salt = "$2b$12$ddTuco8zWXF2.kTqtOZa9O"

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

        #hashed = bcrypt.hashpw(self.password, bcrypt.gensalt())
        hashed = bcrypt.hashpw(self.password, self.salt)

        if bcrypt.hashpw(self.password, hashed) == hashed:
            pass
        else:
            print "Password hash failed, exiting"
            exit(1)

        if(DEBUG > 1):
            print("len of k = %d" % len(hashed))
            print("k = %s" % hashed)

        # Currently k and kPrime are ==
        # TODO: how to do the two keys?
        return (hashed, hashed)

    def initCipher(self):
        # initialize Cipher, using kPrime
        # return new Cipher object

        # TODO: fix key. Currently just a hack: AES keys must be
        # 16, 24 or 32 bytes long, but kPrime is 60
        key = self.kPrime[:16]

        # generates 16 byte random iv
        self.iv = Random.new().read(AES.block_size)

        cipher = AES.new(key, AES.MODE_CBC, self.iv)

        return cipher

    def encryptMail(self, infile, outfile):
        # python sse_client.py -e ../mail/msg1.txt enc_msg1.txt

        buf = infile.read()
        if buf == '': 
            print("[Enc] mail to encrypt is empty!\nExiting\n")
            exit(1)

        if (DEBUG > 1): print("[Enc] mail to encrypt: %s\n" % (buf))

        while len(buf)%16 != 0:
            buf = buf + "\x08"

        outfile.write(self.iv + self.cipher.encrypt(buf))

    def decryptMail(self, infile, outfile):
        # python sse_client -d enc_msg1.txt dec_msg1.txt

        buf = infile.read()
        if buf == '': 
            print("[Dec] mail to decrypt is empty!\nExiting\n")
            exit(1)

        # self.kPrime[:16] == first 16 bytes of kPrime, ie: enc key
        # buf[:16] == iv of encrypted msg
        cipher = AES.new(self.kPrime[:16], AES.MODE_CBC, buf[:16])

        # decrypt all but first 16 bytes (iv)
        outfile.write(cipher.decrypt(buf[16:]))

def debugEcho(msg):
    if (DEBUG):
        print ("[Client-BackEnd] Msg from client: %s" % (msg))


def main():

    # Set-up a command-line argument parser
    parser = ArgumentParser()
    parser.add_argument('-s', '--search', action='store_true')
    parser.add_argument('-u', '--update', action='store_true')
    parser.add_argument('-e', '--encrypt', metavar='encrypt_file', 
                        dest='encrypt_file', nargs='*')
    parser.add_argument('-d', '--decrypt', metavar='decrypt_file',
                        dest='decrypt_file', nargs='*')
    parser.add_argument('-k', '--key', metavar='key')
    args = parser.parse_args()
 
    sse = Client_SSE()

    # Decode the key if it was supplied
    # key = base64.b64decode(args.key) if args.key else None

    if args.encrypt_file:
        if (DEBUG): 
            print("Encrypting %s\nOutput %s\n"
            % (args.encrypt_file[0], args.encrypt_file[1]))

        infile = open(args.encrypt_file[0], "r")        
        outfile = open(args.encrypt_file[1], "w+")

        sse.encryptMail(infile, outfile)

        infile.close()
        outfile.close()

    elif args.decrypt_file:
        if (DEBUG): 
            print("Decrypting %s\nOutput %s" 
            % (args.decrypt_file[0], args.decrypt_file[1]))

        infile = open(args.decrypt_file[0], "r")
        outfile = open(args.decrypt_file[1], "w+")

        sse.decryptMail(infile, outfile)

        infile.close()
        outfile.close()

    else:
        print "Must specify encrypt or decrypt!"
        exit(1)


if __name__ == "__main__":
    main()
