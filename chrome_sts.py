#!/usr/bin/env python
# sts = json.loads(open('~/Library/Application Support/Google/Chrome/Default/TransportSecurity').read())
# sts[unicode(hashlib.sha256('\004neg9\003org\0').digest().encode('base64').strip())]

import os
import sys
import struct
import json
import hashlib

class chrome_sts():
    sts_state_file = os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/TransportSecurity')
    sts_state_json = None

    def hostToLabels(host):
        host = host.strip()

        labels = tuple(host.split('.'))

        # Remove any empty labels due to extraneous dots
        labels = filter(lambda x: len(x) > 0, labels)

        return labels

    def canonicalizeHost(host):
        labels = hostToLabels(host)

        canonicalized_host = ''
        for label in labels:
            label_len = len(label)
            canonicalized_host += struct.pack('b', label_len)
            canonicalized_host += label
            canonicalized_host += '\0'

        return canonicalized_host

    def loadSTS():
        sts_state_json = json.loads(open(sts_state_file, 'r').read())

    def lookup_host(host):
        canonicalized_host = canonicalizeHost(host)
        hashed_host = hashlib.sha256(canonicalized_host).digest().encode('base64')
        if sts_state_json.has_key(hashed_host):
            return sts_state_json[hashed_host]
        else:
            return None

if '__main__' == __name__:
    csts = chrome_sts()
    csts.loadSTS()
    print csts.lookup_host(sys.argv[1])
