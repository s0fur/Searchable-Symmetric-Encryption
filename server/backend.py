# Copyright (c) Ian Van Houdt 2015

############
#
#  backend.py
#
#  Serves as SSE implementation for mail server. The routines 
#  for SSE are invoked by the server module via the API.
#
############

import socket
import os
import sys
import database

DEBUG = 1

########
#
# SSE
#
########
class SSE():

    def __init__(self):

        # need to either set up index, or load it in from file

        # dictionary for index
        self.indexList = self.setupIndexList()

    # d = get(dict, Fk1(c))
    def get(self, index, c):

        # call Fk1(c)

        pass

    # m = decK2(d)
    def dec(self, d):
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


