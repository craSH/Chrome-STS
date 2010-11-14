# chrome_sts_manager.py
## A little tool to add/delete/query entries from Chrome's STS cache
Handy for adding hosts to it like Facebook, twitter, etc.
Do not add hosts to the STS cache that don't support HTTPS. They will break.
Do not use this unless you are very familiar with HSTS!

Requires a restart of Chrome to load the updated file.

Copyleft 2010 Ian Gallagher <crash@neg9.org>


 Usage: chrome_sts_manager.py [options] domain/hostname

 Options:
   -h, --help            show this help message and exit
   -a, --add             Add/update a host to the STS cache
   -d, --delete          Delete a given host from the STS cache
   -s INCLUDE_SUBDOMAINS, --include-subdomains=INCLUDE_SUBDOMAINS
                         Include subdomains
   -m MAX_AGE, --max-age=MAX_AGE
                         Maximum age entry will be cached (seconds)
   -p PATH_OVERRIDE, --sts-cache-path=PATH_OVERRIDE
                         Manually specify the path to Chrome/Chromium's
                         TransportSecurity file
   -v VERBOSITY, --verbose=VERBOSITY
                         Verbosity/debug level. 0 (errors only) - 3 (debug)
 

### Example usage (Adding www.facebook.com)
This adds facebook.com and all subdomains to Chrome's STS cache for one year. This breaks Facebook chat and probably apps, if you care about those things:

 $ ./chrome_sts_manager.py -a facebook.com -s
 INFO: Added/updated STS Entry for 'facebook.com': {"7QzmF0xxCtHTEKYxqWspZY5pl1F0B90+PraFnPulnH8=": {"expiry": 1321272174.509285, "include_subdomains": true, "mode": "strict", "created": 1289736174.509285}}
 INFO: Executing autocommit of STS state file
 INFO: Sucessfully wrote STS state to file '/Users/crash/Library/Application Support/Google/Chrome/Default/TransportSecurity'
 
