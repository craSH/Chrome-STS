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

    def hostToLabels(self, host):
        host = host.strip()

        labels = tuple(host.split('.'))

        # Remove any empty labels due to extraneous dots
        labels = filter(lambda x: len(x) > 0, labels)

        return labels

    def canonicalizeHost(self, host):
        labels = self.hostToLabels(host)

        canonicalized_host = ''
        for label in labels:
            label_len = len(label)
            canonicalized_host += chr(label_len)
            canonicalized_host += label

        # Null-terminate
        canonicalized_host += '\0'

        return canonicalized_host

    def loadSTS(self):
        self.sts_state_json = json.loads(open(self.sts_state_file, 'r').read())

    def lookup_host(self, host):
        canonicalized_host = self.canonicalizeHost(host)
        hashed_host = hashlib.sha256(canonicalized_host).digest().encode('base64').strip()
        if self.sts_state_json.has_key(hashed_host):
            return self.sts_state_json[hashed_host]
        else:
            return None

if '__main__' == __name__:
    csts = chrome_sts()
    csts.loadSTS()
    result = csts.lookup_host(sys.argv[1])
    if result:
        print result
    else:
        print "No entry for %s" % sys.argv[1]
