#!/usr/bin/env python
# Stupid script to reverse STS host entries in Chrome STS cache based on your browsing history and alexa top 1million domains
# Requires that you download + unzip this file in thw CWD: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
# It computes SHA256 hashes of those million domains each run right now, so it's silly slow. Could cache, but this is just a lame
# proof-of-concept.
#
# Copyleft 2010 Ian Gallagher <crash@neg9.org>

import os
import sys
import tempfile
import shutil
from pprint import pprint
from sqlite3 import dbapi2 as sqlite

from chrome_sts_manager import ChromeSTS, hash_host

print "# Chrome/Chromium STS Privacy Leak PoC"
print "# Look up STS hosts based on precomputed hashes of your own browsing history + Alexa Top 1,000,000 domains"

hist_db = os.path.join(os.environ['HOME'], 'Library/Application Support/Chromium/Default/History')

# Copy DB to a temp file so we can work on it while Chrome is running (and the db is locked)
temp = tempfile.mktemp('.sqlite')
shutil.copy(hist_db, temp)

history_domains = []
alexa_domains = []
host_list = set()
host_dict = {}

matched_entries = []
unmatched_entries = []

# Pull all hosts out of Chrome's browsing history (obviously juicy data we already have..)
try:
    con = sqlite.connect(temp)
    cursor = con.cursor()
    cursor.execute('SELECT url FROM urls')
    result = cursor.fetchall()
    url_list = map(lambda x: x[0], result)
    history_domains = map(lambda x: x.split('/')[2], url_list)
    history_domains = map(lambda x: x.split(':')[0], history_domains)

except Exception, ex:
    raise

finally:
    os.unlink(temp)

# Add in Alexa top 1million domains for completeness
alexa_1m_file = open('top-1m.csv', 'r')
alexa_domains = map(lambda x: x.split(',', 1)[1].strip(), alexa_1m_file.readlines())

host_list = set(history_domains + alexa_domains)

# Build a dictionary of hashed_host: hostname so we can easily lookup hosts based on their hash
for host in host_list:
    hashed_hostname = hash_host(host)
    host_dict[hashed_hostname] = host

# Load up STS data
sts_cache_path = None
sts_path_possibilities = [
    os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/TransportSecurity'),
    os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/StrictTransportSecurity'),
    os.path.join(os.environ['HOME'], '.config/chromium/Default/TransportSecurity'),
    os.path.join(os.environ['HOME'], '.config/google-chrome/Default/TransportSecurity'),
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
    raise

for hashed_host, infodict in csts.items():
    if host_dict.has_key(hashed_host):
        matched_entries.append((host_dict[hashed_host], infodict['created']))
    else:
        unmatched_entries.append((hashed_host, infodict['created']))

print "Matched STS host entries:"

for match in matched_entries:
    print "    %s, Last Accessed: %f" % match

print ""
print "Unmatched STS host hashes:"

for unknown in unmatched_entries:
    print "    %s, Last Accessed: %f" % unknown
