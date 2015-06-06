# nm-dispatcher-dnspod

NetworkManager dispatcher to update IPv4 (A) and IPv6 (AAAA) records on DNSPod.cn (using Python 3 and Requests library)

It may or may not support DNSPod International (DNSPod.com). Please refer to the [API Docs](https://www.dnspod.com/Support/api). At least the API endpoint should be changed.

## Usage

1. Make sure NetworkManager, Python 3 and [Requests](http://python-requests.org) are installed.
2. Create an account at [DNSPod China](https://www.dnspod.cn), import your domain, and create A and/or AAAA records as needed. This script will not create the records for you.
3. Update the config parameters at the beginning of the script.
4. Copy it to `/etc/NetworkManager/dispatcher.d/` and `chmod +x FILENAME`.
