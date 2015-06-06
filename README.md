# nm-dispatcher-dnspod
NetworkManager dispatcher to update IPv4 (A) and IPv6 (AAAA) records on DNSPod.cn (using Python 3 and Requests library)

## Usage

1. Make sure NetworkManager, python 3 and [Requests](http://python-requests.org) are installed.
2. Create an account at http://dnspod.cn, import your domain, and create A and/or AAAA records as needed.
3. Update the configure parameters at the beginning of the script.
4. Copy it to `/etc/NetworkManager/dispatcher.d/` and `chmod +x FILENAME`.
