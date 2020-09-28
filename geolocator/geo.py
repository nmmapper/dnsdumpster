#  geo.py
#  
#  Copyright 2019 Wangolo Joel <wangolo@ldap.testlumiotic.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
from ip2geotools.databases.noncommercial import DbIpCity
from ipwhois.net import Net
from ipwhois.asn import IPASN
from ipwhois.asn import ASNOrigin
from dns import resolver
from dns.resolver import NXDOMAIN
try:
    import simplejson as json
except ImportError:
    import json
import dns

def query_A_records(hostname, query_type="A"):
    """
    @
    """
    try:
        resol = resolver.Resolver()
        query = resol.query(hostname, query_type)
        return query
    except NXDOMAIN as e:
        return None
    except dns.exception.Timeout:
        return ""
    except dns.resolver.NoAnswer:
        return ""
        
def geo_locate_ip(ip):
    """
    @IP: 147.229.2.90
    """
    try:
        response = DbIpCity.get(ip, api_key='free')
    except Exception:
        return None
    else:
        return json.loads(response.to_json())
        
def locate_asn_info(ip):
    """
    @IP: 147.229.2.90
    """
    try:
        net = Net(ip)
        ipasn = IPASN(net)
        results = ipasn.lookup()
    except Exception:
        return None
    else:
        return results
        
