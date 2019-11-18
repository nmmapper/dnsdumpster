# dnsdumpster
A tool to perform DNS reconnaissance on target networks. The results include a variety of information that are useful for users performing network reconnaissance.
Some of the information return include
 * Host subdomains
 * Different dns informat(MX, A record)
 * Geo information
 * Email

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
