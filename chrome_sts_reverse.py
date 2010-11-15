#!/usr/bin/env python
# Stupid script to reverse STS host entries in Chrome STS cache based on your browsing history and alexa top 1million domains
# Requires that you download + unzip this file in thw CWD: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
# It computes SHA256 hashes of those million domains each run right now, so it's silly slow. Could cache, but this is just a lame
# proof-of-concept.
#
# Copyleft 2010 Ian Gallagher <crash@neg9.org>

import os
import sys
import time
import tempfile
import shutil
from pprint import pprint
from sqlite3 import dbapi2 as sqlite

from chrome_sts_manager import ChromeSTS, hash_host

print "# Chrome/Chromium STS Privacy Leak PoC"
print "# Look up STS hosts based on precomputed hashes of your own browsing history + Alexa Top 1,000,000 domains"

hist_db = os.path.join(os.environ['HOME'], 'Library/Application Support/Chromium/Default/History')
alexa_file = 'top-1m.csv'
alexa_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

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
try:
    alexa_1m_file = open(alexa_file, 'r')
    alexa_domains = map(lambda x: x.split(',', 1)[1].strip().split('/', 1)[0], alexa_1m_file.readlines())
except IOError, ex:
    print >>sys.stderr, "You do not have the Alexa top 1,000,000 sites file (%s) - download and unzip here for better results: %s" % (alexa_file, alexa_url)
    print >>sys.stderr, "Continuing with data collected only from Chrome browsing history, expect a potentially smaller set of results..."

host_list = set(history_domains + alexa_domains)

# Build a dictionary of hashed_host: hostname so we can easily lookup hosts based on their hash
for host in host_list:
    hashed_hostname = hash_host(host)
    host_dict[hashed_hostname] = host

# Create the Chrome STS Object that will hold all the STS entries from disk, and ones we add/delete
csts = None
try:
    csts = ChromeSTS(autocommit=True)
except Exception, ex:
    raise

for hashed_host, infodict in csts.items():
    # Convert seconds since epoch to human readable string
    created = time.ctime(infodict['created'])

    if host_dict.has_key(hashed_host):
        matched_entries.append((created, host_dict[hashed_host]))
    else:
        unmatched_entries.append((created, hashed_host))

print "Matched STS host entries:"

for match in matched_entries:
    print "    Accessed: %s - %s" % match

print ""
print "Unmatched STS host hashes:"

for unknown in unmatched_entries:
    print "    Accessed: %s - %s" % unknown
