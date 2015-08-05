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

SRCH_BODY = 0
SRCH_HEADERS = 1

HEADERS = ["from", "sent", "date", "to", "subject", "cc"]

DELIMETER = "++?"

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
    index_len = get_index_len(index)

    for i in new_index:
        i0 = i[0].encode('ascii', 'ignore')
        i1 = i[1].encode('ascii', 'ignore')
        match = i0

        if i[2]:
            i2 = i[2].encode('ascii', 'ignore')
            match = i2

        exists = 0
        for k, v in index.iteritems():
            if match == k: # and i1 == v:
                exists = 1
                del index[k]
                break

            '''
            # TODO: New index scheme. If exists, append. Current version
            # sends another query (i2) which is the search query OR'd with
            # the search term and count -1. That way, you can more easily
            # find the previous entry, delete it, and store the new one.

            # Shouldnt be exact matches anymore, but will leave in logic
            # of if stmt above for now, just in case.
            # else: for each element in index, find if the new element is
            # it's successor, ie new_index[i] is index[i+1]. Do this by 
            # using the K1 stored as the key of the index (k), and the 
            # count of the index (0..len) to see if the new_index term (i)
            # is already here, albeit under a lower number. get_update() 
            # should return the new length of the id list, as that should
            # be the c # of the PRF.
            else:
                continue
                x = get_update(i, k, index_len) 
                if x > 0:
                    break
                    pass
                else:
                    pass
            '''

        index[i0] = i1
        #if not exists:
        #    index[i0] = i1

    if (DEBUG > 1): 
        print "\nUpdate Complete! Index contents:" 
        for k, v in index.iteritems():
            print "k:%s\nv:%s\n\n" % (k, v)

    index.close()
    return jsonify(results="GOOD UPDATE")


def get_update(index_new, k1, count):

    cc = 0
    while cc < count:
        F = PRF(k1, str(cc))
        if (DEBUG > 1): 
            print "index key = " + index_new
            print "PRF of k1 and %d = %s\n" % (cc, F)
        if F == index_new:
            print "\n\nFound existing term in get_update\n\n"
            return cc
        cc = cc + 1
    return -1


@app.route('/search', methods=['POST'])
def search():

    TYPE = SRCH_BODY

    if not request.json:
        return jsonify(results='Error: not json')

    (method, query, id_num) = jmap.unpack(SEARCH, request.get_json())

    if method != SEARCH_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    # FIXME: This is a crap way to check for headers, and subsequently
    # searching for them. Need to fix this, as well as following FIXME's
    # in this method.
    if query[0] in HEADERS:
        header = query[0]
        TYPE = SRCH_HEADERS

    index = anydbm.open("index", "r")
    count = get_index_len(index)

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
        c = 0
        if i[2]:
            c = i[2].encode('ascii', 'ignore')
            print "C: %s " % c

        if (DEBUG > 1): print "k1: %s\nk2: %s\n" % (k1, k2)
        D = []

        d = new_get(index, k1, c)

        if not d:
            print "get() returned None!"
        else:
            D.append(d)
        '''
        
        # Then, go through entire index, each key getting evaluated by the
        # get() routine, and any matches getting returned and appended to 
        # D. Don't break on a match, as the same word (k/k1) can have 
        # several entries, each for a single message.
        for k, v in index.iteritems():
            # FIXME: continuation of header search. Find a better set-up.
            if TYPE == SRCH_HEADERS:
                d = get_header((k,v), k1, header)
            else:
                d = get((k,v), k1, count)
            if d:
                D.append(d)
                break
                if DEBUG > 1: 
                    print "[Server] Search found result!\n%s" % (k)
        ''' 
        if not D: continue

        # 'd' represents an encrypted id number for a message (in the 
        # simple case, just the message's name).

        # Go through list of d's in which the search query was found and
        # dec() each and add to list of id's (M).
        # Send those messages are found to the client

        print "D: "
        print D
        for d in D:
            m = dec(k2, d)
            m = filter(lambda x: x in string.printable, m)
            for msg in m.split(DELIMETER):
                print "-----\t" + msg
                if msg not in M:
                    M.append(msg) 

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
            print "C: " + str(cc)
            return index_n[1]
        cc = cc + 1
    return 0

def new_get(index, k1, c):
    F = PRF(k1, c)
    d = index[F]
    return d
    try:
        F = PRF(k1, str(c))
        d = index[F]
    except:
        d = None

    return d

# FIXME: But maybe not. This may be the only somewhat sane addition for the
# header search.  Could be joined with get(), but is distinct enough that
# it may be best to keep them separate.
def get_header(index_n, k1, header):

    F = PRF(k1, header)
    if (DEBUG > 1): 
        print "index key = " + index_n[0]
        print "PRF of k1 and %s = %s\n" % (header, F)
    if F == index_n[0]:
        return index_n[1]

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

def get_index_len(index):

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

    return count


if __name__ == '__main__':
    app.run(debug=True)

