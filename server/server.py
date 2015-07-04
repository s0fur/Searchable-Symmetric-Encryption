# Copyright (c) Ian Van Houdt 2015

############
#
#  server.py
#
#  Serves as mail server implementing SSE and speaking
#  an extended version of JMAP that understands SSE
#  
#
############

import socket
import os
import sys
import threading
import time

DEFAULT_TCP_IP = "127.0.0.1"
DEFAULT_TCP_PORT = 8000

DEBUG = 1

class Server():

    def __init__(self, IP = DEFAULT_TCP_PORT, PORT = DEFAULT_TCP_PORT):

        self.TCP_IP = IP
        self.TCP_PORT = PORT

        if (DEBUG): 
            print("SERVER\tIP: %s\tPORT: %d" % 
            (self.TCP_IP, int(self.TCP_PORT)))

    def receive(self):
        pass



def parse_args():

    if len(sys.argv) == 3: 
        TCP_IP = sys.argv[1]
        TCP_PORT = sys.argv[2]
    elif len(sys.argv) == 1:
        TCP_IP = DEFAULT_TCP_IP
        TCP_PORT = DEFAULT_TCP_PORT
    else:
        print("Error: Incorrect number of arguments.\nSpecify both " +
              "IP and PORT, or neither, using default IP and PORT:" +
              "\n%s:%d" % (DEFAULT_TCP_IP, DEFAULT_TCP_PORT))
        exit(1)

    return TCP_IP, TCP_PORT

# 'main'

(IP, PORT) = parse_args()

server = Server(IP, PORT)

exit(1)
while 1:
    server.receive()
