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
import string
import json
from flask import Flask
from flask import request
from flask import render_template
from flask import jsonify

app = Flask(__name__)

DEBUG = 1

# CMD list
UPDATE = "update"
SEARCH = "search"

########
#
# SSE_Server
#
########
@app.route('/update')
def update(new_index):

    index = anydbm.open("index", "c")

    for i in new_index:
        i0 = i[0].encode('ascii', 'ignore')
        i1 = i[1].encode('ascii', 'ignore')
        exists = 0
        for k, v in index.iteritems():
            if i0 == k and i1 == v:
                exists = 1
                break

        # TODO: I think this is the issue with overwriting the
        # previous entries, and only the latest filename was 
        # found upon queries
        if not exists:
            index[i0] = i1

    if (DEBUG > 1): 
        print "\nUpdate Complete! Index contents:" 
        for k, v in index.iteritems():
            print "k:%s\nv:%s\n\n" % (k, v)

    index.close()

@app.route('/search', methods=['POST'])
def search():

    if not request.json:
        return jsonify({'ret' : 'Error: not json'})

    query = request.get_json(force=True)
    if (DEBUG > 1): print query['query']
    query = query['query']

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
        print "k1: %s\nk2: %s\n" % (k1, k2)
        D = []
        for k, v in index.iteritems():
            d = get((k,v), k1, count)
            if d:
                D.append(d)
                if DEBUG > 1: 
                    print "[Server] Search found result!\n%s" % (k)

        if not D: continue

        # Go through list of docs in which the search query was found
        # dec() each and add to list of id
        # Send those messages are found to the client

        for d in D:
            m = dec(k2, d)
            m = filter(lambda x: x in string.printable, m)
            M.append(m) 

    if not M:
        print "[Server] Found no results for query"
        return 0

    if (DEBUG): 
        print "[Server] Found %d results for query" % len(M)
        for m in M:
            print "\t - %s" % repr(m)
        print "\n"

    # For each doc in M[], send file back to Client
    # buf is list of msgs so client can receive them all together 
    # and parse
    buf = []
    for m in M:
        fd = open(m, "rb")
        buf.append(binascii.hexlify(fd.read()))
        fd.close()

    #server.reply(buf)
    # TODO: how to return? JSONify here? Have a packing function?
    return jsonify(results=buf)

def get(index_n, k1, count):
       
    cc = 0
    while cc < count:
        F = PRF(k1, str(cc))
        if (DEBUG > 1): 
            print "index key = " + index_n[0]
            print "PRF of k1 and %d = %s\n" % (cc, F)
        if F == index_n[0]:
            return index_n[1]
        cc = cc + 1

    return 0

def dec(k2, d):

    d_bin = binascii.unhexlify(d) 
    iv = d_bin[:16]
    cipher = AES.new(k2[:16], AES.MODE_CBC, iv)
    doc = cipher.decrypt(d_bin[16:])

    if (DEBUG): print "[Server] Retrieved Doc = %s" % (doc)

    return doc

def PRF(k, data):
    hmac = HMAC.new(k, data, SHA256)
    return hmac.hexdigest()

def handle_msg(data):

    cmd = data[0]
    print("[Server] Cmd from client: %s" % cmd)

    if cmd == UPDATE:
        # New list of tuples mapping l & d
        new_index = data[1]
        update(new_index)

    if cmd == SEARCH:

        query = data[1]
        search(query)


if __name__ == '__main__':
    app.run(debug=True)

