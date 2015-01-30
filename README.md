CVE Watcher queries the National Vulnerability Database (NVD) for CVEs related to specific vendor and/or product and prints the results to STD OUT.

  -h, --help            show this help message and exit
  -v VENDOR, --vendor VENDOR
                        Name of vendor to search NVD for
  -p PRODUCT, --product PRODUCT
                        Specific product made by a vendor [OPTIONAL]
  -s START_MONTH, --start_month START_MONTH
                        Integer value 0 through 11 for start month
  -S START_YEAR, --start_year START_YEAR
                        Integer value for start year
  -e END_MONTH, --end_month END_MONTH
                        Integer value 0 through 11 for end month
  -E END_YEAR, --end_year END_YEAR
                        Integer value for end year
  -c CVSS_SCORE, --cvss_score CVSS_SCORE
                        HIGH, MEDIUM_HIGH, MEDIUM, or LOW [OPTIONAL]

Example:
python cveWatcher.py -v Microsoft -s 0 -S 2015 -e 0 -E 2015 -c HIGH 		( This grabs all Microsoft CVEs in Jan. 2015 with a CVSS rating of HIGH )
python cveWatcher.py -v Adobe -s 0 -S 2015 -e 0 -E 2015 -c MEDIUM_HIGH		( This grabs all Adobe CVEs in Jan. 2015 with a CVSS rating of MEDIUM OR HIGH )
python cveWatcher.py -v Google -p chrome -s 4 -S 2014 -e 11 -E 2014 -c HIGH ( This grabs all CVEs for Chrome from May 2014 to December 2014 witha  CVSS rating of HIGH)