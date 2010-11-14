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

class chrome_sts(dict):
    def __init__(self, sts_state_file=None, autocommit=False):
        
        self._sts_state_file = sts_state_file
        
        # Shall we write to disk immediately after any modifications?
        self._autocommit = autocommit
        
        # Load the json file into memory
        sts_state_json = dict()
                
        try:
            sts_state_json = json.loads(open(self._sts_state_file, 'r').read())
        except Exception, ex:
            debug(0, "Failed to load STS State file %s (%s)" % (sts_state_file, ex))
            raise
            
        for k, v in sts_state_json.items():
            entry = sts_entry(k,
                              created = v['created'],
                              expiry = v['expiry'],
                              include_subdomains = v['include_subdomains'],
                              mode = v['mode']
                              )
            self.update(entry)

    def get(self, host):
        hashed_host = hashHost(host)
        debug(3, "Host hash: %s" % hashed_host)
        if self.has_key(hashed_host):
            return self[hashed_host]
        else:
            return None

    def stsAddEntry(self, host, max_age=365*24*60*60, include_subdomains=False, mode='strict'):
        """Add a new entry to the STS object"""
        hashed_hostname = hashHost(host)
        cur_time = time.time()
        cur_time_s = "%.6f" % (cur_time)
        expiration = "%.6f" % (cur_time + max_age)
        new_entry = sts_entry(hashed_hostname,
                              created=cur_time_s,
                              expiry=expiration,
                              include_subdomains=include_subdomains,
                              mode=mode)

        self.update(new_entry)
        debug(2, "Added/updated STS Entry for %s: %s" % (repr(host), json.dumps(new_entry)))
        
        if self._autocommit:
            debug(2, "Executing autocommit of STS state file")
            self.writeStateFile()

    def writeStateFile(self):
        """Write out the contents of this STS object to the STS state file"""
        sts_state_file_text = json.dumps(self, indent=3)
        fh = None
        try:
            fh = open(self._sts_state_file, 'w')
            fh.write(sts_state_file_text)
            fh.flush()
            debug(2, "Sucessfully wrote STS state to file %s" % repr(self._sts_state_file))
        except Exception, ex:
            debug(0, "Failed to write STS State file: %s" % ex)
            raise
        finally:
            fh.close()

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

    csts = None
    try:
        csts = chrome_sts(sts_state_file=path)
    except Exception, ex:
        # Should already be displaying error messages anywhere something is thrown up here
        sys.exit(1)

    result = csts.get(sys.argv[1])
    if result:
        print result
    else:
        print "No entry for %s" % sys.argv[1]
