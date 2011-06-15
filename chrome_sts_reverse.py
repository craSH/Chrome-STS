#!/usr/bin/env python
# Stupid script to reverse STS host entries in Chrome STS cache based on your browsing history and alexa top 1million domains
# Requires that you download + unzip this file in thw CWD: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
# It computes SHA256 hashes of those million domains each run right now, so it's silly slow. Could cache, but this is just a lame
# proof-of-concept.
#
# Copyleft 2010 Ian Gallagher <crash@neg9.org>

import os, sys, time, tempfile, shutil, cPickle, urllib
from cStringIO import StringIO
from zipfile import ZipFile

# Try importing sqlite module, different on Linux/OSX/who knows..
try:
    from sqlite3 import dbapi2 as sqlite
except ImportError, ex:
    from pysqlite import dbapi2 as sqlite
except ImportError, ex:
    # Arr, I give up! You can fix this as appropriate for your system ;)
    raise

from chrome_sts_manager import ChromeSTS, hash_host

hist_path_possibilities = [
    os.path.join(os.environ['HOME'], 'Library/Application Support/Google/Chrome/Default/History'),      # OS X Chrome official
    os.path.join(os.environ['HOME'], 'Library/Application Support/Chromium/Default/History'),           # OS X Chromium
    os.path.join(os.environ['HOME'], '.config/chromium/Default/History'),                               # *nix Chromium
    os.path.join(os.environ['HOME'], '.config/google-chrome/Default/History'),                          # *nix Chrome official
]
alexa_file = 'top-1m.csv'
alexa_file_pickle = 'top-1m_hashed.pickle'
alexa_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

def pre_hash_alexa():
    alexa_dict = {}
    alexa_stringio = StringIO()

    print "Downloading %s ..." % alexa_url
    alexa_stringio.write(urllib.urlopen(alexa_url).read())
    alexa_zip = ZipFile(alexa_stringio)

    print "Hashing + caching Alexa top 1,000,000 domain hashes, this may take about a minute..."
    alexa_domains = map(lambda x: x.split(',', 1)[1].strip().split('/', 1)[0], alexa_zip.read(alexa_file).split('\n')[:-1])

    for host in alexa_domains:
        hashed_hostname = hash_host(host)
        alexa_dict[hashed_hostname] = host

    cPickle.dump(alexa_dict, open('top-1m_hashed.pickle', 'wb'), protocol=cPickle.HIGHEST_PROTOCOL)

    # Take advantage of the fact that python will return this by reference, so you can use it immediately without
    # reading it back from disk.
    return alexa_dict

if '__main__' == __name__:
    print "# Chrome/Chromium STS Privacy Leak PoC"
    print "# Look up STS hosts based on precomputed hashes of your own browsing history + Alexa Top 1,000,000 domains"

    # Copy DB to a temp file so we can work on it while Chrome is running (and the db is locked)
    temp = tempfile.mktemp('.sqlite')
    found_history = False
    for choice in hist_path_possibilities:
        try:
            shutil.copy(choice, temp)
            found_history = True
            continue
        except IOError, ex:
            pass

    if not found_history:
        print >>sys.stderr, "Unable to locate Chrome/Chromium History file..."
        sys.exit(1)

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
        url_list = filter(lambda x: x.count('/') > 1 and x.count(':') > 0, url_list)
        history_domains = map(lambda x: x.split('/')[2], url_list)
        history_domains = map(lambda x: x.split(':')[0], history_domains)
        history_domains = filter(lambda x: len(x) > 0, history_domains)

    except Exception, ex:
        raise

    finally:
        os.unlink(temp)

    # Build a dictionary of hashed_host: hostname so we can easily lookup hosts based on their hash (from history)
    for host in history_domains:
        hashed_hostname = hash_host(host)
        host_dict[hashed_hostname] = host

    # Add hashes for Alexa top 1m sites to the dictionary
    if not os.path.isfile(alexa_file_pickle):
        # Perhaps our first time running, generate them and load them.
        host_dict.update(pre_hash_alexa())
    else:
        # We already have the Alexa hashes, yay! Load them (much quicker than generating them)
        host_dict.update(cPickle.load(open(alexa_file_pickle, 'rb')))

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

    if matched_entries:
        for match in matched_entries:
            print "    Accessed: %s - %s" % match
    else:
        print "    No matched STS host entries found."

    print "\nUnmatched STS host hashes:"

    if unmatched_entries:
        for unknown in unmatched_entries:
            print "    Accessed: %s - %s" % unknown
    else:
        print "    No unmatched STS host entries found."
