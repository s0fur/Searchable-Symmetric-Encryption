# Copyright (c) Ian Van Houdt 2015

############
#
#  sse_client.py
#
#  Serves as SSE implementation for mail server. The routines 
#  for SSE are invoked by the server module via the API.
#
############

import socket
import os
import sys
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import unicodedata
import binascii
import database
import anydbm
from server import Server

DEBUG = 1

# CMD list
UPDATE = "update"
SEARCH = "search"

########
#
# SSE_Server
#
########
class SSE_Server():

    def __init__(self):

        self.server = Server()        

        # need to either set up index, or load it in from file
        #self.index = self.setupIndexList()
        self.index = None

    def update(self, new_index):

        index = anydbm.open("index", "c")

        for i in new_index:
            i0 = i[0].encode('ascii', 'ignore')
            i1 = i[1].encode('ascii', 'ignore')
            exists = 0
            for k, v in index.iteritems():
                if i0 == k and i1 == v:
                    exists = 1
                    break

            if not exists:
                index[i0] = i1

        if (DEBUG > 1): 
            print "\nUpdate Complete! Index contents:" 
            for k, v in index.iteritems():
                print "k:%s\nv:%s\n\n" % (k, v)

        index.close()

    def search(self, query):

        index = anydbm.open("index", "r")

        # TODO: crappy hack for now. Need to get size of index,
        # but I'm not sure what the best method is. So for now, 
        # just iterate through and grab the count.
        count = 0
        for k, v in index.iteritems():
            count = count + 1
            if (DEBUG > 1):
                print "K: " + k
                print "V: " + v
                print "\n"

        # query is a list of search terms, so each 'i' is a word
        # each word contains k1, to be used to find the correct hashed
        # document name, and k2 for unhashing the document name
        M = []
        for i in query:
            k1 = i[0].encode('ascii', 'ignore')
            k2 = i[1].encode('ascii', 'ignore')
            D = []
            for k, v in index.iteritems():
                d = self.get((k,v), k1, count)
                if d:
                    D.append(d)
                    if DEBUG > 1: 
                        print "[Server] Search found result!\n%s" % (k)

            if not D: continue

            # Go through list of docs in which the search query was found
            # dec() each and add to list of id
            # Send those messages are found to the client

            for d in D:
                m = self.dec(k2, d)
                M.append(m) 

        if not M:
            print "[Server]: Found no results for query"
            return 0

        if (DEBUG): 
            print "[Server] Found %d results for query" % len(M)
            for m in M:
                print "\t - %s" % m
            print "\n"

        # For each doc in M[], send file back to Client

    def get(self, index_n, k1, count):
       
        cc = 0
        while cc < count:
            F = self.PRF(k1, str(cc))
            if (DEBUG > 1): 
                print "index key = " + index_n[0]
                print "PRF of k1 and %d = %s\n" % (cc, F)
            if F == index_n[0]:
                return index_n[1]
            cc = cc + 1

        return 0

    def dec(self, k2, d):

        d_bin = binascii.unhexlify(d) 
        iv = d_bin[:16]
        cipher = AES.new(k2[:16], AES.MODE_CBC, iv)
        doc = cipher.decrypt(d_bin[16:])

        if (DEBUG): print "[Server]: Retrieved Doc = %s" % (doc)

        return doc

    def PRF(self, k, data):
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()

    def handle_msg(self, data):

        cmd = data[0]
        print("[Server] Cmd from client: %s" % cmd)

        if cmd == UPDATE:
            # New list of tuples mapping l & d
            new_index = data[1]
            self.update(new_index)

        if cmd == SEARCH:

            query = data[1]
            self.search(query)


def main():

    sse = SSE_Server()
    while 1:
        data = sse.server.listen()
        sse.handle_msg(data)


if __name__ == "__main__":
    main()
