#!/usr/bin/env python
#
# A little tool to add/delete/query entries from Chrome's STS cache
# Handy for adding hosts to it like Facebook, twitter, etc.
# Requires a restart of Chrome to load the updated file.
# 
# Copyleft 2010 Ian Gallagher <crash@neg9.org>

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

class ChromeSTS(dict):
    def __init__(self, sts_state_file=None, autocommit=True):
        """
        This class represents the StrictTransportSecurity file contents,
        which is a list of STS entries. It's a JSON dictionary of entries (also dictionaries)
        on disk, so this just extends Python's dictionary class
        """
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
            entry = StsEntry(k,
                              created = v['created'],
                              expiry = v['expiry'],
                              include_subdomains = v['include_subdomains'],
                              mode = v['mode']
                              )
            self.update(entry)

    def get(self, host):
        """Get a given entry out of the STS object"""
        hashed_host = hash_host(host)
        debug(3, "Host hash: %s" % hashed_host)
        if self.has_key(hashed_host):
            return self[hashed_host]
        else:
            return None

    def sts_add_entry(self, host, max_age=365*24*60*60, include_subdomains=False, mode='strict'):
        """Add a new entry to the STS object"""
        hashed_hostname = hash_host(host)
        cur_time = time.time()
        expiration = cur_time + max_age
        new_entry = StsEntry(hashed_hostname,
                              created=cur_time,
                              expiry=expiration,
                              include_subdomains=include_subdomains,
                              mode=mode)

        self.update(new_entry)
        debug(2, "Added/updated STS Entry for %s: %s" % (repr(host), json.dumps(new_entry)))
        
        if self._autocommit:
            debug(2, "Executing autocommit of STS state file")
            self.write_state_file()
            
    def sts_delete_entry(self, host):
        """Delete a given host from the STS cache"""
        hashed_hostname = hash_host(host)
        try:
            result = self.pop(hashed_hostname)
            debug(2, "Deleted STS cache entry for %s (%s): %s" % (repr(hostname), hashed_hostname, result))
        except KeyError, ex:
            debug(0, "Unable to find entry in STS cache for %s (%s)" % (repr(hostname), hashed_hostname))
            return
            
        if self._autocommit:
            debug(2, "Executing autocommit of STS state file")
            self.write_state_file()

    def write_state_file(self):
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

class StsEntry(dict):
    """
    Class that represents a single entry in the Chrome STS list. Again, this class extends
    Python's dictionary class.
    Example from file:
        "j6md0fxp6QYNP8B0wy4GhW10q925k2nmAkN+LQsMG6U=": {
           "created": 1288843191.608916,
           "expiry": 1320710325.353056,
           "include_subdomains": false,
           "mode": "strict"
        }
    """
    def __init__(self, hash, created=None, expiry=None, include_subdomains=False, mode="Strict"):
        super(StsEntry, self).__init__()

        # Attributes which will be the key for our hash
        attributes = {
            'created': created,
            'expiry': expiry,
            'include_subdomains': include_subdomains,
            'mode': mode
        }
        
        # Set ourselves
        self.__setitem__(hash, attributes)

def canonicalize_host(host):
    """Return an RFC3490 compatible canonicalized DNS hostname. Adapated from Scapy source."""
    temp = [label[:63] for label in host.split(".")] # Truncate labels that cannont be encoded (more than 63 bytes..)
    temp = map(lambda x: chr(len(x)) + x, temp)
    temp = ''.join(temp)
    if temp[-1] != "\x00":
        temp += "\x00"

    debug(3, "Canonicalized hostname: %s" % repr(temp))
    return temp
    
def hash_host(host):
    """Generate a hash suitable for use in Chrome STS cache based on a human-readable hostname"""
    canonicalized_host = canonicalize_host(host)
    hashed_host = hashlib.sha256(canonicalized_host).digest()
    hashed_host = hashed_host.encode('base64').strip()
    
    return hashed_host
    
def debug(level, msg):
    """Print message based on debug level"""
    if DEBUG >= level:
        print >>sys.stderr, "%s" % debug_levels[level] + ':', msg


if '__main__' == __name__:
    import optparse
    usage = "usage: %prog [options] domain/hostname"
    parser = optparse.OptionParser(usage=usage)

    parser.add_option( '-a','--add', dest='add_host', action='store_true', help='Add/update a host to the STS cache')
    parser.add_option( '-s','--include-subdomains', dest='include_subdomains',default=False, help='Include subdomains')
    parser.add_option( '-m','--max-age', dest='max_age', default=365*24*60*60, help='Maximum age entry will be cached (seconds)')
    parser.add_option( '-d','--delete', dest='delete_host', action='store_true', help='Delete a given host from the STS cache')
    parser.add_option( '-p','--sts-cache-path', dest='path_override', default=None, help="Manually specify the path to Chrome/Chromium's TransportSecurity file")
    parser.add_option( '-v','--verbose', dest='verbosity',  default=2, help='Verbosity/debug level. 0 (errors only) - 3 (debug)')
    
    (options, args) = parser.parse_args()

    if not len(args) > 0:
        parser.print_help()
        sys.exit(1)

    hostname = args[0]
    DEBUG = int(options.verbosity)
    
    if options.add_host and options.delete_host:
        debug(0, "You can not simultaneously add and delete the same host!")
        sys.exit(1)

    # Set the path to the user provided one if given, else try and find the file automagically
    sts_cache_path = None
    if options.path_override:
        sts_cache_path = options.path_override
    else:
        sts_path_possibilities = [
            os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/TransportSecurity'),
            os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/StrictTransportSecurity'),
            os.path.join(os.environ['HOME'], '.config/chromium/Default/TransportSecurity'),
        ]
        # Iterate over the path possibilities until we find one that appears to be a file.
        for path in sts_path_possibilities:
            if os.path.isfile(path):
                sts_cache_path = path
                break

    # Create the Chrome STS Object that will hold all the STS entries from disk, and ones we add/delete
    csts = None
    try:
        csts = ChromeSTS(sts_state_file=sts_cache_path, autocommit=True)
    except Exception, ex:
        # Should already be displaying error messages anywhere something is thrown up here
        sys.exit(1)

    # Figure out what to do
    if options.add_host:
        csts.sts_add_entry(hostname, max_age=options.max_age, include_subdomains=options.include_subdomains)
    elif options.delete_host:
        csts.sts_delete_entry(hostname)
    else:
        # No add or delete, just query the cache for any domain given, if any
        query_result = json.dumps(csts.get(hostname), indent=3)
        if query_result and 'null' != query_result.lower():
            display = "Query: %s\n\n" % repr(hostname)
            display += '"%s": ' % hash_host(hostname)
            display += query_result
            print display
        else:
            print "No entry for %s" % repr(hostname)
