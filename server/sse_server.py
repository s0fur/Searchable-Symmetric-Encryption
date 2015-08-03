# Copyright (c) Ian Van Houdt 2015

############
#
#  sse_server.py
#
#  Serves as SSE implementation for mail server. The routines 
#  for SSE are invoked by the server module via the API.
#
############

import socket
import os
import sys
sys.path.append(os.path.realpath('../jmap'))
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import unicodedata
import binascii
import anydbm
import string
import json
from flask import Flask
from flask import request
from flask import render_template
from flask import jsonify
from werkzeug import secure_filename
import jmap

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'mail'
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 
                                        'jpeg', 'gif'])
DEBUG = 1

# CMD list
UPDATE = "update"
SEARCH = "search"
ADD_FILE = "addmail"
SEARCH_METHOD = "getEncryptedMessages"
UPDATE_METHOD = "updateEncryptedIndex"
ADD_FILE_METHOD = "putEncryptedMessage"

########
#
# SSE_Server
#
########

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


@app.route('/addmail', methods=['POST'])
def add_mail():

    if not request.json:
        return jsonify(results='Error: not json')

    (method, file, filename, id_num) = jmap.unpack(ADD_FILE, request.get_json())

    if method != ADD_FILE_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    # return file to binary
    file = binascii.unhexlify(file)

    # open file and write to it locally
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    f = open(path, "w+")
    f.write(file)
    f.close()

    return jsonify(results="GOOD ADD FILE")


# TODO: Use this to request mail? Currently just sending them back after
# SEARCH routine
@app.route('/getmail', methods=['GET'])
def get_mail():
    pass


@app.route('/update', methods=['POST'])
def update():

    if not request.json:
        return jsonify(results='Error: not json')

    (method, new_index, id_num) = jmap.unpack(UPDATE, request.get_json())

    if method != UPDATE_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    index = anydbm.open("index", "c")

    for i in new_index:
        i0 = i[0].encode('ascii', 'ignore')
        i1 = i[1].encode('ascii', 'ignore')
        exists = 0
        for k, v in index.iteritems():
            if i0 == k and i1 == v:
                exists = 1
                print "EXISTS"
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
    return jsonify(results="GOOD UPDATE")


@app.route('/search', methods=['POST'])
def search():

    if not request.json:
        return jsonify(results='Error: not json')

    (method, query, id_num) = jmap.unpack(SEARCH, request.get_json())

    if method != SEARCH_METHOD:
        return jsonify(results='Error: Wrong Method for url')

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

    # query is a list of search terms, so each 'i' is a word/query
    # each word/query is a tuple containing k1, a hash of the search term,
    # and k2 for decrypting the document name.  Use k1 to match the key, 
    # and use k2 to decrypt each value (mail ID or name) that is associated
    # with that key.
    M = []
    for i in query:
        # Drop unicode
        k1 = i[0].encode('ascii', 'ignore')
        k2 = i[1].encode('ascii', 'ignore')
        if (DEBUG > 1): print "k1: %s\nk2: %s\n" % (k1, k2)
        D = []

        # Then, go through entire index, each key getting evaluated by the
        # get() routine, and any matches getting returned and appended to 
        # D. Don't break on a match, as the same word (k/k1) can have 
        # several entries, each for a single message.
        for k, v in index.iteritems():
            d = get((k,v), k1, count)
            if d:
                D.append(d)
                if DEBUG > 1: 
                    print "[Server] Search found result!\n%s" % (k)

        if not D: continue

        # 'd' represents an encrypted id number for a message (in the 
        # simple case, just the message's name).

        # Go through list of d's in which the search query was found and
        # dec() each and add to list of id's (M).
        # Send those messages are found to the client

        for d in D:
            m = dec(k2, d)
            m = filter(lambda x: x in string.printable, m)
            if m not in M:
                M.append(m) 

    if not M:
        buf = "Found no results for query"
        print "[Server] " +  buf
        return jsonify(results=buf)

    if (DEBUG): 
        print "[Server] Found %d results for query" % len(M)
        for m in M:
            print "\t - %s" % repr(m)
        print "\n"

    # TODO: Separate method for sending back files?  
    # Should it be whole files or just msg ids?
    # Currently sends msgs back in their entirety

    # TODO: Need to send back id_num and check at client side

    # For each doc in M[], send file back to Client
    # buf is list of msgs so client can receive them all together 
    # and parse
    buf = []
    for m in M:
        path = os.path.join(app.config['UPLOAD_FOLDER'], m)
        fd = open(path, "rb")
        buf.append(binascii.hexlify(fd.read()))
        fd.close()

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

    if (DEBUG > 1): print "[Server] Retrieved Doc = %s" % (doc)

    return doc


def PRF(k, data):
    hmac = HMAC.new(k, data, SHA256)
    return hmac.hexdigest()



if __name__ == '__main__':
    app.run(debug=True)

