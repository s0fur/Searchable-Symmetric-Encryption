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
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import bcrypt
from argparse import ArgumentParser
import binascii
import string
import anydbm
from client import Client

DEBUG = 1

########
#
# SSE_Client
#
########
class SSE_Client():

    def __init__(self):

        # interface for sending msgs to server
        self.client = Client()

        # need to either set up index, or load it in from file

        # placeholder for password. Will eventually take
        # as an arg of some sort
        self.password = b"password"

        # TODO: need to sort out use of salt. Previously, salt was
        # randomly generated in initKeys, but the resulting pass-
        # words k & kPrime were different on each execution, and 
        # decryption was impossible. Hardcoding salt makes dectyption
        # possible but may be a bad short cut
        self.iv = None
        self.salt = "$2b$12$ddTuco8zWXF2.kTqtOZa9O"

        # Two keys, generated/Initialized by KDF
        (self.k, self.kPrime) = self.initKeys()

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

    def update(self, document):

        infile = open(document, "r")
        word_list = self.parseDocument(infile)
        if (DEBUG > 1): print "[Update] Words from doc: " + word_list
        infile.close()

        index = self.encryptIndex(document, word_list)

        # test decryption and search of index
        # PASSES!
        # self.testSearch(index)

        # send updated index to server, as well as the encr messages
        self.client.send("update", index)

    def parseDocument(self, infile):

        word_list = None

        for line in infile:
            for word in line.split():
                try:
                    if word not in word_list and '\x08' not in word:
                        word_list.append(word)
                # except catches case of first word in doc, and an
                # empty list cannot be iterated over
                except:
                    word_list = [word]

        return word_list

    def encryptIndex(self, document, word_list):

        # This is where the SSE update routine is implemented

        if (DEBUG): print "Encrypting index of words in %s" % document

        L = []
        '''
        kPlus as described below (first) is used in the implementation
        of Dynamic SSE (specifically to allow updating, and requires
        mult dicts). For simplicity, I'm first using a basic version
        where I only maintain 1 dictionary on the server and on the 
        client.  
        Additionally, it seems the 2nd dict is just to manage updates
        that are added after the initial setup, but since I'm not 
        (yet) implementing setup(), two dictionaries is unecessary
        '''

        index = anydbm.open("index", "c")

        dynamic = 0 # 0 for 1 dict, 1 for 2 dicts (not implemented)

        if dynamic > 0:
            kPlus = self.prf.update(self.k + "3").digest()
            for w in word_list:
                print "kPlus = " + kPlus + " w = " + w
                k1Plus = self.prf.update(kPlus + ("1" + w))
                k2Plus = self.prf.update(kPlus + ("2" + w))
        
        else:
            for w in word_list:

                # Initialize K1 and K2
                k1 = self.PRF(self.k, ("1" + w))
                k2 = self.PRF(self.k, ("2" + w))

                if (DEBUG > 1): print("k1 = %s\nk2 = %s\n" % (k1, k2))

                # Set counter "c" (set as 0 if not in index)
                c = 0
                found = 0
                for k, v in index.iteritems():
                    if k == w:
                        if (DEBUG > 1): 
                            print("Found '%s' in db. C = %d" % (w, c))
                        found = 1
                        break
                    else:
                        c = c + 1

                if (DEBUG and not found):
                    print("'%s' not found in db" % w)

                l = self.PRF(k1, str(c))
                d = self.PRF(k2, document)

                if (DEBUG > 1):
                    print "w = " + w + "\tc = " + str(c)
                    print("l = %s\nd = %s\n" % (l, d))

                c = c + 1
                index[w] = str(c)
                L.append((l, d))

        index.close()
        return L

    def PRF(self, k, data):
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()

    def testSearch(self, index):
        '''
        Method for testing locally if the encryption in the update
        routine is actually accurate. 
        -create a static search term (ie: "the")
        -generate hashes with self.k (ie generate k1 and k2)
        -implement the backend get() and dec() methods to see if they
         return the correct data
        -try with search query that isn't in index
        '''

        # 'Client' activities
        query = "This"
        k1 = self.PRF(self.k, ("1" + query))
        k2 = self.PRF(self.k, ("3" + query))

        if (DEBUG > 1): 
            print("[testSearch]\nk1:%s\nk2:%s" % (k1, k2))

        # 'Server' activities
        c = 0
        found = 0
        while c < len(index):
            print "c = " + str(c)
            result = self.get(index, k1, c)
            if result: break
            c = c + 1

        if not result:
            print "NOT FOUND in INDEX"

        else:
            print "FOUND RESULT"

    def get(self, index, k, c):

        cc = 0
        while cc < len(index):
            F = self.PRF(k, str(c))
            if (DEBUG > 1):
                print "[Get] F: " + F
                print "[Get] Idx: " + index[cc][0] + "\n"
            if F == index[cc][0]:
                return F
            cc = cc + 1

def debugEcho(msg):
    if (DEBUG):
        print ("[Client-BackEnd] Msg from client: %s" % (msg))


def main():

    # Set-up a command-line argument parser
    parser = ArgumentParser()
    parser.add_argument('-s', '--search', action='store_true')
    parser.add_argument('-u', '--update', metavar='update', dest='update',
                        nargs=1)
    parser.add_argument('-e', '--encrypt', metavar='encrypt_file', 
                        dest='encrypt_file', nargs=2)
    parser.add_argument('-d', '--decrypt', metavar='decrypt_file',
                        dest='decrypt_file', nargs=2)
    parser.add_argument('-k', '--key', metavar='key')
    parser.add_argument('-i', '--inspect index', dest='inspect_index')
    args = parser.parse_args()
 
    sse = SSE_Client()

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

    elif args.update:
        if (DEBUG):
            print("Updating index with document %s" % args.update[0])

        sse.update(args.update[0])

    elif args.inspect_index:
        if (DEBUG): print("Inspecting the index")
        index = anydbm.open("index", "r")
        for k, v in index.iteritems():
            print "k:%s\tv:%s" % (k, v)

        index.close()

    else:
        print "Must specify encrypt or decrypt!"
        exit(1)


if __name__ == "__main__":
    main()
