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
import database
from server import Server

DEBUG = 1

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

def debugEcho(msg):
    if (DEBUG):
        print ("[BackEnd] Msg from server: %s" % (msg))


def main():

    print "Yo"
    sse = SSE_Server()
    sse.server.listen()


if __name__ == "__main__":
    main()
