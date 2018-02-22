TODO:
Fix -p flag
-c flag is deprecated

CVE Watcher queries the National Vulnerability Database (NVD) for CVEs related to specific vendor and/or product


Example(s):

python CVEWatcher.py -v Microsoft -s 0 -S 2015 -e 0 -E 2015

python CVEWatcher.py -v Adobe -s 0 -S 2015 -e 0 -E 2015

python CVEWatcher.py -v Google -p chrome -s 4 -S 2014 -e 11 -E 2014


Example Output:

Microsoft,7.8,HIGH,CVE-2017-3762,January  25  2018

Microsoft,8.8,HIGH,CVE-2018-0862,January  24  2018

Microsoft,8.8,HIGH,CVE-2018-0849,January  22  2018

Microsoft,8.8,HIGH,CVE-2018-0848,January  22  2018

Microsoft,8.8,HIGH,CVE-2018-0845,January  22  2018

Microsoft,7.8,HIGH,CVE-2016-0215,January  22  2018

Microsoft,6.5,MEDIUM,CVE-2018-0819,January  16  2018

Microsoft,6.5,MEDIUM,CVE-2018-0818,January  09  2018

Microsoft,7.5,HIGH,CVE-2018-0812,January  09  2018

Microsoft,7.8,HIGH,CVE-2018-0807,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0806,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0805,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0807,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0804,January  09  2018

Microsoft,7.8,HIGH,CVE-2018-0802,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0801,January  09  2018

Microsoft,6.1,MEDIUM,CVE-2018-0799,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0798,January  09  2018

Microsoft,7.8,HIGH,CVE-2018-0797,January  09  2018

Microsoft,8.8,HIGH,CVE-2018-0796,January  09  2018
