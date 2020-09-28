.. meta::
    :description lang=en:
        A tool to perform DNS reconnaissance on target networks. Among the DNS information 
        got from include subdomains, mx records, web application firewall can let you 
        customize the look and feel of your docs or add additional 


Dnsdumpster a tool to perform DNS, MX, NS Lookup
=================================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Home page
=========
* `https://www.nmmapper.com <https://www.nmmapper.com>`_

Repository and source code
==========================
* `https://github.com/wangoloj/dnsdumpster <https://github.com/wangoloj/dnsdumpster>`_

Rationale
=========
There are many projects out there that both in github and online that offer dns manage and dumping of dns data. But we at `https://www.nmmapper.com <https://www.nmmapper.com>`_ wanted to unify lot of python tools out there that perform dns recon so that we can host it online. Like we did unify and host `8 subdomain finder tools <https://www.nmmapper.com/sys/tools/subdomainfinder/>`_.

Our approach to this tool is to dump as match information about a given host as possible. The tool is still in development and we continue to add more features on it.


Dnsdumpster setups
=================
.. code-block:: bash
   :linenos:
 
   git clone https://github.com/wangoloj/dnsdumpster.git
   pip3 install -r requirements.txt
   #
   # This should be done inside python virtualenv

Dnsdumpster will dump
=================================

The following are the kind of information that dnsdumpster will be able to dump given a domain.

* Subdomains
* MX
* TXT
* Server Detection
* Web application firewall(WAF)
* Geo locate physical location of IP
* ASN Detection


We are doing what ever we can to dump more information.

Dumping subdomains
==================
After cloning into your virtualenv and installing the required

.. code-block:: bash
   :linenos:

   (www.dnsdumpster.net) $python3 dnsdumpster.py -d nmmapper.com
   Starting dns dump against nmmapper.com
   Searching using engine DNSdumpster
   Searching using engine Netcraft
   Searching using engine Virustotal
   Searching using engine ThreatCrowd
   Searching using engine SSL Certificates
   Could not initialize connection to a1.nmmapper.com
   Could not initialize connection to a1.nmmapper.com
   Could not initialize connection to a2.nmmapper.com
   Could not initialize connection to a2.nmmapper.com
   Could not initialize connection to clk.nmmapper.com
   Could not initialize connection to clk.nmmapper.com
   Could not initialize connection to upstream.d.nmmapper.com
   Could not initialize connection to upstream.d.nmmapper.com
   .....
   {
    "asn": null,
    "host": "nmmapper.com",
    "mx": "mx1.privateemail.com.",
    "ns": [
        {
            "ip": "173.245.59.170",
            "ns": "gordon.ns.cloudflare.com."
        },
        {
            "ip": "173.245.58.56",
            "ns": "adi.ns.cloudflare.com."
        }
    ],
    "server": "cloudflare",
    "subdomains": [
        {
            "asn": {
                "asn": "13335",
                "asn_cidr": "104.24.96.0/20",
                "asn_country_code": "US",
                "asn_date": "2014-03-28",
                "asn_description": "CLOUDFLARENET - Cloudflare, Inc., US",
                "asn_registry": "arin"
            },
            "geo": {
                "city": "Ashburn",
                "country": "US",
                "ip_address": "104.24.103.134",
                "latitude": 39.0437192,
                "longitude": -77.4874899,
                "region": "Virginia"
            },
        },
    "txt": [],
    "waf": "Cloudflare (Cloudflare Inc.)"
    }


Domain dnsmapping
================
**TODO**

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
