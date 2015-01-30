import urllib2
import re
import argparse
from bs4 import BeautifulSoup


cve_regex = re.compile("CVE-\d*-\d*\\\\r")
cvss_regex = re.compile("CVSS Severity: \d+.\d HIGH|MEDIUM_HIGH|MEDIUM|LOW")
published_regex = re.compile("Published: \d+\/\d+\/\d+")


def get_cve(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: CVE Numbers
    """
    vulnerability = re.findall(pattern, str(content))
    vulnerability = [v.replace('\\r', '') for v in vulnerability]
    return list(vulnerability)


def get_published(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: Publish Dates of CVEs
    """
    pubdate = re.findall(pattern, str(content))
    pubdate = [p.replace('Published: ', '') for p in pubdate]
    return list(pubdate)


def get_cvss(content, pattern):
    """
    :rtype : List
    :param content: website text
    :param pattern: regex
    :return: CVSS Score
    """
    score = re.findall(pattern, str(content))
    score = [s.replace('CVSS Severity: ', '') for s in score]
    return list(score)


def urlgrab2(host):
    """
    :rtype : String
    :param host: url
    :param pattern: regex
    :return: Test for web page grab
    """

    try:
        response = urllib2.urlopen(host)
    except urllib2.URLError as e:
        if hasattr(e, 'reason'):
            print "\t [-] Failed to reach " + str(host) + "\n\t [-] Reason: ", e.reason + "\n"
            sys.exit()
        elif hasattr(e, 'code'):
            print "\t [-] The server (%s) couldn't fulfill the requst.\n\t [-] Reason: %s" % (host, e.code)
            sys.exit()

    cve_list = response.readlines()
    soup = BeautifulSoup(str(cve_list))
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
    cve_list = get_cve(all_text, cve_regex)
    cvss_list = get_cvss(all_text, cvss_regex)
    pub_list = get_published(all_text, published_regex)

    for element in range(len(cvss_list)):
        print str(args.vendor) + "," + str(cve_list[element]) + "," + str(cvss_list[element]) + "," + str(pub_list[element])


if __name__ == "__main__":
    main()
