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

    def search(self, k1):
        # k1 is search query from client

        c = 0
        docIdList # append docIds that match search query and return list
        while 1:
            # key = get_key(k1, c)
            # d = get(key)
            # m = dec(d)
            # docIdList.append(m)
            c = c + 1

        pass

    def get_key(self, k1, c):
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

        # run computation to generate index elements

        # DEBUG:
        while i < 5:
            indexObj = database.Database()

            self.indexList.append(indexObj)
        print "indexList = " + self.indexList

        pass

    def handle_msg(self, data):

        cmd = data[0]
        print("[Server] Cmd from client: %s" % cmd)

        if cmd == UPDATE:
            # New list of tuples mapping l & d
            new_index = data[1]
            self.update(new_index)

        if cmd == SEARCH:

            pass

def debugEcho(msg):
    if (DEBUG):
        print ("[BackEnd] Msg from server: %s" % (msg))


def main():

    sse = SSE_Server()
    while 1:
        data = sse.server.listen()
        sse.handle_msg(data)


if __name__ == "__main__":
    main()
