"""
[+] CVEWatcher module makes a web request to the National Vulnerability Database (NVD).
[+} This web request can be configured to include vendor, product, CVSS score and a time line for when to search for vulnerabilities.

"""


import requests
import re
import argparse
import sys
from bs4 import BeautifulSoup


CVSS_REGEX = re.compile(r"(V3: [0-9].[0-9])\s(CRITICAL|HIGH|MEDIUM|LOW)")
CVE_REGEX = re.compile(r"(CVE-20[0-9]{2}-\d{4})\n")
PUBLISHED_REGEX = re.compile(r"(January|February|March|April|May|June|July|August|Sepetember|October|November|Decemeber)(\s[0-9]{2}\, 20[0-9]{2})")
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'


def get_cve(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: CVE Numbers
    """
    vulnerability = re.findall(pattern, str(content))
    return list(vulnerability)


def get_published(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: Publish Dates of CVEs
    """
    pubdate = re.findall(pattern, str(content))
    return list(pubdate)


def get_cvss(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: CVSS Score
    """
    score = re.findall(pattern, str(content))
    return list(score)


def urlgrab2(host):
    """
    :rtype : String
    :param host: url
    :param pattern: regex
    :return: Test for web page grab
    """
    headers = {'User-Agent' : USER_AGENT}

    try:    
        response = requests.get(host, headers=headers)  
    except requests.exceptions.HTTPError as error:
        print error
        sys.exit(1)

    cve_list = response.text
    soup = BeautifulSoup(str(cve_list), "lxml")
    text_only = soup.getText().encode("utf-8")
    return text_only


def main():
    """
    :return: None
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vendor", help="Name of vendor to search NVD for", type=str)
    parser.add_argument("-p", "--product", help="Specific product made by a vendor \t [OPTIONAL]")
    parser.add_argument("-s", "--start_month", help="Integer value 0 through 11 for start month", type=int)
    parser.add_argument("-S", "--start_year", help="Integer value for start year", type=int)
    parser.add_argument("-e", "--end_month", help="Integer value 0 through 11 for end month", type=int)
    parser.add_argument("-E", "--end_year", help="Integer value for end year", type=int)
    parser.add_argument("-c", "--cvss_score", help="HIGH, MEDIUM_HIGH, MEDIUM, or LOW \t [OPTIONAL]", type=str)

    args = parser.parse_args()

    if args.product is not None:
        url = "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cpe_vendor=cpe%3a%2f%{0}" \
              "&cpe_product=cpe%3a%2f%3a%3a{1}" \
              "&pub_date_start_month={2}" \
              "&pub_date_start_year={3}" \
              "&pub_date_end_month={4}" \
              "&pub_date_end_year={5}" \
              "&cvss_sev_base={6}&cve_id=".format(str(args.vendor),
                                                str(args.product),
                                                str(args.start_month),
                                                str(args.start_year),
                                                str(args.end_month),
                                                str(args.end_year),
                                                str(args.cvss_score))
    else:
        url = "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cpe_vendor=cpe%3a%2f%3a{0}" \
            "&pub_date_start_month={1}" \
            "&pub_date_start_year={2}" \
            "&pub_date_end_month={3}" \
            "&pub_date_end_year={4}" \
            "&cvss_sev_base={5}&cve_id=".format(str(args.vendor),
                                                str(args.start_month),
                                                str(args.start_year),
                                                str(args.end_month),
                                                str(args.end_year),
                                                str(args.cvss_score))

    all_text = urlgrab2(url)
    cve_list = get_cve(all_text, CVE_REGEX)
    cvss_list = get_cvss(all_text, CVSS_REGEX)
    pub_list = get_published(all_text, PUBLISHED_REGEX)


    for element in range(len(cvss_list)):
        print str(args.vendor) + "," + str(','.join(cvss_list[element]).replace("V3: ", "")) + ',' + str(cve_list[element]) + "," + str(' '.join(pub_list[element]).replace(","," "))


if __name__ == "__main__":
    main()
