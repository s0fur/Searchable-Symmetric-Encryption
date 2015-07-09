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


def debugEcho(msg):
    if (DEBUG):
        print ("[Client-BackEnd] Msg from client: %s" % (msg))



sse = Client_SSE()
