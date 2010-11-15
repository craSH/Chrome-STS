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
 

### Example usage (Adding facebook.com and all subdomains)
This adds facebook.com and all subdomains to Chrome's STS cache for one year. This breaks Facebook chat and probably apps, if you care about those things:

    $ ./chrome_sts_manager.py -a facebook.com -s
    INFO: Added/updated STS Entry for 'facebook.com': {"7QzmF0xxCtHTEKYxqWspZY5pl1F0B90+PraFnPulnH8=": {"expiry": 1321272174.509285, "include_subdomains": true, "mode": "strict", "created": 1289736174.509285}}
    INFO: Executing autocommit of STS state file
    INFO: Sucessfully wrote STS state to file '/Users/crash/Library/Application Support/Google/Chrome/Default/TransportSecurity'
    
# chrome_sts_reverse.py
## A little proof of concept script to reveal hosts stored in STS cache (which are SHA256 hashed)
The hashing of hostnames in Chrome's STS cache is not useful from a security perspective, it's trivial to look these up based on your own browsing history and the Alexa top 1,000,000 sites list. That is what this script does.
This is not amazing by any means, most users will have all their STS entries present in the normal browser history, so I don't see that there's much of a leak here. It's really just an annoyance when trying to deal with the STS cache :)

### Example usage (You must have the Alexa top 1m sites file downloaded + unzipped)
    $ python chrome_sts_reverse.py
    # Chrome/Chromium STS Privacy Leak PoC
    # Look up STS hosts based on precomputed hashes of your own browsing history + Alexa Top 1,000,000 domains
    Matched STS host entries:
        calomel.org, Last Accessed: 1289002307.810874
        neg9.org, Last Accessed: 1289003617.943210
        www.noisebridge.net, Last Accessed: 1289731341.660200
    
    Unmatched STS host hashes:
        vnGyNm8Ca0otQ0Xeju02z1ytnWf4cDxFBqUcQJ77lpg=, Last Accessed: 1289777331.593507
        rKLF0Hae9LVGc224j1/caNj/mw10uyYWv7QkStDh9gU=, Last Accessed: 1288843191.608916
