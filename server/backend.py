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

DEBUG = 1

########
#
# SSE
#
########
class SSE():

    def __init__(self):
        pass



def debugEcho(msg):
    if (DEBUG):
        print ("[BackEnd] Msg from server: %s" % (msg))


