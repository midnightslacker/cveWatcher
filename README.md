CVE Watcher queries the National Vulnerability Database (NVD) for CVEs related to specific vendor and/or product


Example:

python cveWatcher.py -v Microsoft -s 0 -S 2015 -e 0 -E 2015 -c HIGH

python cveWatcher.py -v Adobe -s 0 -S 2015 -e 0 -E 2015 -c MEDIUM_HIGH

python cveWatcher.py -v Google -p chrome -s 4 -S 2014 -e 11 -E 2014 -c HIGH

