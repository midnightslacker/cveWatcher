CVE Watcher queries the National Vulnerability Database (NVD) for CVEs related to specific vendor and/or product


Example:

python cveWatcher.py -v Microsoft -s 0 -S 2015 -e 0 -E 2015 -c HIGH 		( This grabs all Microsoft CVEs in Jan. 2015 with a CVSS rating of HIGH )

python cveWatcher.py -v Adobe -s 0 -S 2015 -e 0 -E 2015 -c MEDIUM_HIGH		( This grabs all Adobe CVEs in Jan. 2015 with a CVSS rating of MEDIUM OR HIGH )

python cveWatcher.py -v Google -p chrome -s 4 -S 2014 -e 11 -E 2014 -c HIGH ( This grabs all CVEs for Chrome from May 2014 to December 2014 witha  CVSS rating of HIGH)
