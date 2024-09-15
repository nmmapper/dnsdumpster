# dnsdumpster
A tool to perform DNS reconnaissance on target networks. The results include a variety of information that are useful for users performing network reconnaissance.
Some of the information return include
 * [Host subdomains](https://www.nmmapper.com/sys/tools/subdomainfinder/)
 * Different dns informat(MX, A record)
 * Geo information
 * [Email](https://www.nmmapper.com/kalitools/theharvester/email-harvester-tool/online/)

# Dependencies 
 * requests
 * dnspython
 * simplejson
 * ip2geotools
 * ipwhois

```sh
$ pip3 install -r requirements.txt
```

# How to
```sh
$ python3 dnsdumpster.py -d nmmapper.com

Starting dns dump against nmmapper.com
Searching using engine Netcraft
Searching using engine Virustotal
Searching using engine ThreatCrowd
Searching using engine SSL Certificates
[
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "173.212.192.0/19",
            "asn_country_code": "DE",
            "asn_date": "2009-10-26",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "173.212.208.249",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "www.nmmapper.com",
        "subdomain_ip": "173.212.208.249"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "207.180.222.0/23",
            "asn_country_code": "DE",
            "asn_date": "1996-08-21",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "207.180.222.55",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "analytics.nmmapper.com",
        "subdomain_ip": "207.180.222.55"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "173.212.192.0/19",
            "asn_country_code": "DE",
            "asn_date": "2009-10-26",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "173.212.208.249",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "celery.nmmapper.com",
        "subdomain_ip": "173.212.208.249"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "clk.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "d1.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "173.212.192.0/19",
            "asn_country_code": "DE",
            "asn_date": "2009-10-26",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "173.212.208.249",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "goaccess.nmmapper.com",
        "subdomain_ip": "173.212.208.249"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "mail.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "p0-cdn.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "p352931.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "p352931-cdn.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": {
            "asn": "51167",
            "asn_cidr": "167.86.88.0/23",
            "asn_country_code": "DE",
            "asn_date": "1993-05-14",
            "asn_description": "CONTABO, DE",
            "asn_registry": "ripencc"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Munich (Ramersdorf-Perlach)",
            "country": "DE",
            "ip_address": "167.86.88.139",
            "latitude": null,
            "longitude": null,
            "region": "Bavaria"
        },
        "subdomain": "upstream.nmmapper.com",
        "subdomain_ip": "167.86.88.139"
    },
    {
        "asn": null,
        "domain": "nmmapper.com",
        "geo": null,
        "subdomain": "webook.nmmapper.com",
        "subdomain_ip": ""
    },
    {
        "asn": {
            "asn": "15169",
            "asn_cidr": "34.64.0.0/14",
            "asn_country_code": "US",
            "asn_date": "2018-09-28",
            "asn_description": "GOOGLE - Google LLC, US",
            "asn_registry": "arin"
        },
        "domain": "nmmapper.com",
        "geo": {
            "city": "Ashburn",
            "country": "US",
            "ip_address": "34.67.67.41",
            "latitude": 39.0437192,
            "longitude": -77.4874899,
            "region": "Virginia"
        },
        "subdomain": "wss.nmmapper.com",
        "subdomain_ip": "34.67.67.41"
    },
    {
        "asn": null,
        "domain": "nmmapper.com",
        "geo": null,
        "subdomain": "wss1.nmmapper.com",
        "subdomain_ip": ""
    }
]
```

There is support for web application firewall detection. When all subdomains have been enumerated we detect if each of the subdomain is behind a web application firewall. To detect web application firewalls we use [WAFW00F](https://github.com/EnableSecurity/wafw00f) by [Enable Security](http://enablesecurity.com/)
```py
from wafw00f.main import WafW00F
detector = WafW00F(host)
waf = detector.identwaf()
if(waf):
    return waf[0]
else:
    return ""
```
```sh
{
            "asn": {
                "asn": "13335",
                "asn_cidr": "104.27.160.0/20",
                "asn_country_code": "US",
                "asn_date": "2014-03-28",
                "asn_description": "CLOUDFLARENET - Cloudflare, Inc., US",
                "asn_registry": "arin"
            },
            "geo": {
                "city": "Ashburn",
                "country": "US",
                "ip_address": "104.27.171.116",
                "latitude": 39.0437192,
                "longitude": -77.4874899,
                "region": "Virginia"
            },
            "server": "cloudflare",
            "subdomain": "mail.mp3hunter.net",
            "subdomain_ip": "104.27.171.116",
            "waf": "Cloudflare (Cloudflare Inc.)"
        },

```
Web server detection, the tool also supports web server detection on both the main domain and the subdomains that have been enumerated. Here is a piece of code that does the detection
```py
def get_server_type(host):
    """
    :param host: the server we want to get it's server
    @return str
    """
    try:
        ua = get_user_agent()
        headers = {
            'User-Agent': ua,
            'From': 'info@nmmapper.com' 
        }
        res  = requests.get(add_protocol(host), headers=headers)
        if(res.headers):
            return res.headers.get("Server")
        else:
            return ""
            
    except Exception as e:
        return ""
```

## Stargazers over time
[![Stargazers over time](https://starchart.cc/nmmapper/dnsdumpster.svg?variant=adaptive)](https://starchart.cc/nmmapper/dnsdumpster)
