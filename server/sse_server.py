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
import unicodedata
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

        # query is a list of search terms, so each 'i' is a word
        # each word contains k1, to be used to find the correct hashed
        # document name, and k2 for unhashing the document name
        L = []
        for i in query:
            k1 = i[0].encode('ascii', 'ignore')
            k2 = i[1].encode('ascii', 'ignore')
            print k1, k2
            print "\n\n"
            c = 0
            found = 0
            for k, v in index.iteritems():
                #print k, v
                result = self.get(k, k1, c, count)
                if result:
                    L.append(result)
                    break
                c = c + 1 


    def get(self, index_key, k1, c, count):
       
        L = []
        cc = 0
        while cc < count:
            F = self.PRF(k1, str(cc))
            if (DEBUG > 1): print F
            if F == index_key:
                L.append(F)

        return L

    def PRF(self, k, data):
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()

    def get1(self, index, k, c):
        # k1 is search query from client
        # c is counter from defined in search()

        # use HMAC to derive key
        #'F(k1, c) -- HMAC'

        pass

    def get_doc(self, key):
        # search db for key match
        # if match, return encryped doc

        pass

    def dec(self, d):
        # 'm = dec(k2, d)'
        pass

    def setupIndexList(self):
        pass
        # run computation to generate index elements

        # DEBUG:
        while i < 5:
            indexObj = database.Database()

            self.indexList.append(indexObj)
        print "indexList = " + self.indexList

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
