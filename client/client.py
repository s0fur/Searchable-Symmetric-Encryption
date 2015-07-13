# Copyright (c) Ian Van Houdt 2015

############
#
#  client.py
#
#  Serves as a simple mail client, forwarding encrypted
#  searches to a mail server who can service those types
#  of requests. Speaks an extended version of the JMAP
#  protocol for sending these msgs.
#
############

import socket
import os
import sys
import json

DEFAULT_TCP_IP = "127.0.0.1"
DEFAULT_TCP_PORT = 8000

DEBUG = 1

########
#
# Client
#
# basic client class for sending msgs
#
########
class Client():

    def __init__(self, IP = DEFAULT_TCP_IP, PORT = DEFAULT_TCP_PORT):

        self.TCP_IP = IP
        self.TCP_PORT = int(PORT)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #self.s.connect((self.TCP_IP, self.TCP_PORT))
        self.conn = None

    def send(self, msg, data = None):

        

        if (DEBUG):
            print("[Client] Sending Message to %s:%d\n" 
                   % (self.TCP_IP, self.TCP_PORT))

        if (msg == ""):
            print "[Client] No input message to send"
            exit(1)

        if (data):
            msg_list = []
            msg_list.append(msg)
            msg_list.append(data)
            serialized_data = json.dumps(msg_list)

        else: # Just a msg, no data
            serialized_data = json.dumps(msg)

        self.s.connect((self.TCP_IP, self.TCP_PORT))

        try:
            result = self.s.send(serialized_data)
        except socket.error:
            print "[Client] Error sending msg"


    def teardown(self):

        self.s.close()



########
#
# parse_args
#
########
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


########
#
# 'main'
#
# Need to bring up client to spin, but also need to take in cli search, 
# from which we generate K1 and K2 and send to server.
#
# Maybe just take args, then spin up client, send, wait for response,
# display result, return to cli
#
########

#client = Client()
#client.send()
