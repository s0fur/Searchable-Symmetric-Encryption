# Copyright (c) Ian Van Houdt 2015

############
#
#  database.py
#
#  Manages all database routines, hopefully allowing for a sort of
#  plug-and-play between the SSE server and a different database
#  implementation
#
############

import os
import sys
import anydbm

########
#
# Database
#
# Database class used to store index. Actual encrypted mail on server
# is simply located inside local mail dir. All the tricky stuff is
# related only to the index.
#
# Index is made up of key-value pairs. There is a separate index for each
# word that is found in each document (dups removed). Therefore, the
# server's SSE backend will maintain a list of these indexes
#
# Key is some counter, unique and appearing once for each index. It point
# to a document in which the word in that index is found
#
# Value is the name of the encrypted document. By executing the algorithm
# to decrypt the counter, the SSE backend gets the counter, which can be
# used to get the document's name. With this, the client can see which
# files have the infomation in question, and can request those encrypted
# messages
#
########
class Database():

    def __init__(self):
        return "a"
        pass

    # helper function for init(). May not be necessary, but could be 
    # useful for offloading some of the setup required in creating the
    # indexes
    def setup(self):
        pass

    # method for returning key. *Temporary: May not remain in this module
    def getKey(self):
        pass

    # method for returning val. *Temporary: May not remain in this module
    def getValue(self):
        pass

