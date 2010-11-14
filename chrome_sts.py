#!/usr/bin/env python
# sts = json.loads(open('~/Library/Application Support/Google/Chrome/Default/TransportSecurity').read())
# sts[unicode(hashlib.sha256('\004neg9\003org\0').digest().encode('base64').strip())]

import os
import sys
import struct
import json
import hashlib
import time

debug_levels = {0: 'ERROR',
                1: 'WARNING',
                2: 'INFO',
                3: 'DEBUG'}

DEBUG = 2

class chrome_sts():
    def __init__(self, sts_state_file=None):
        # Load the json file into memory
        sts_state_json = dict()
        self.sts_entries = dict()
        
        try:
            sts_state_json = json.loads(open(sts_state_file, 'r').read())
        except Exception, ex:
            debug(0, "Failed to load STS State file %s (%s)" % (sts_state_file, ex))
            sys.exit(1)
            
        for k, v in sts_state_json.items():
            entry = sts_entry(k,
                              created = v['created'],
                              expiry = v['expiry'],
                              include_subdomains = v['include_subdomains'],
                              mode = v['mode']
                              )
            self.sts_entries.update(entry.getDict())

    def get(self, host):
        hashed_host = hashHost(host)
        debug(3, "Host hash: %s" % hashed_host)
        if self.sts_entries.has_key(hashed_host):
            return self.sts_entries[hashed_host]
        else:
            return None

    def add(self, host, max_age=365*24*60*60, include_subdomains=False, mode='strict'):
        """Add a new entry to the sts object"""
        hashed_hostname = hashHost(host)
        cur_time = time.time()
        cur_time_s = "%.6f" % (cur_time)
        expiration = "%.6f" % (cur_time + max_age)
        new_entry = sts_entry(hashed_hostname,
                              created=cur_time_s,
                              expiry=expiration,
                              include_subdomains=include_subdomains,
                              mode=mode)

        self.sts_entries.update(new_entry)
        debug(2, "Added/updated STS Entry for %s: %s" % (repr(host), json.dumps(new_entry.getDict())))

class sts_entry(dict):
    """
    Class that represents a single entry in the Chrome STS list
    Example from file:
        "j6md0fxp6QYNP8B0wy4GhW10q925k2nmAkN+LQsMG6U=": {
           "created": 1288843191.608916,
           "expiry": 1320710325.353056,
           "include_subdomains": false,
           "mode": "strict"
        }
    """
    def __init__(self, hash, created=None, expiry=None, include_subdomains=False, mode="Strict"):
        super(sts_entry, self).__init__()
        self.hash = hash
        self.created = created
        self.expiry = expiry
        self.include_subdomains = include_subdomains
        self.mode = mode

        # Attributes which will be the key for our hash
        attributes = {
            'created': self.created,
            'expiry': self.expiry,
            'include_subdomains': self.include_subdomains,
            'mode': self.mode
        }
        
        # Set ourselves
        self.__setitem__(hash, attributes)

def canonicalizeHost(host):
    """Return an RFC3490 compatible canonicalized DNS hostname. Adapated from Scapy source."""
    temp = [label[:63] for label in host.split(".")] # Truncate labels that cannont be encoded (more than 63 bytes..)
    temp = map(lambda x: chr(len(x)) + x, temp)
    temp = ''.join(temp)
    if temp[-1] != "\x00":
        temp += "\x00"

    debug(3, "Canonicalized hostname: %s" % repr(temp))
    return temp
    
def hashHost(host):
    """Generate a hash suitable for use in Chrome STS cache based on a human-readable hostname"""
    canonicalized_host = canonicalizeHost(host)
    hashed_host = hashlib.sha256(canonicalized_host).digest()
    hashed_host = hashed_host.encode('base64').strip()
    
    return hashed_host
    
def debug(level, msg):
    """Print message based on debug level"""
    if DEBUG >= level:
        print >>sys.stderr, "%s" % debug_levels[level] + ':', msg


if '__main__' == __name__:
    path = os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/TransportSecurity')
    csts = chrome_sts(sts_state_file=path)

    result = csts.get(sys.argv[1])
    if result:
        print result
    else:
        print "No entry for %s" % sys.argv[1]
