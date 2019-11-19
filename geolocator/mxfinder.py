#  mxfinder.py
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
import dns
from dns.resolver import Resolver
from dns.resolver import NXDOMAIN
try:
    import simplejson as json
except ImportError:
    import json
from .geo import query_A_records

def query_host_mx(hostname, rt="MX"):
    try:
        resolver  = Resolver()
        mx = resolver.query(hostname, rt)
        
    except NXDOMAIN as e:
        return None
    else:
        mx = mx[0]
        return str(mx.exchange)
        
def query_host_ns(hostname, rt="NS"):
    try:
        resolver  = Resolver()
        ns = resolver.query(hostname, rt)
    except NXDOMAIN as e:
        return None
    else:
        ns_list = []
        
        if(ns.rrset is not None):
            for r in ns.rrset:
                a_record = query_A_records(r.to_text())
                
                if(a_record):
                    a_record = a_record[0]
                    
                    ns_list.append(
                        {"ns":r.to_text(),
                         "ip":a_record.address
                        }
                    )
                else:
                    ns_list.append(
                        {"ns":r.to_text(),
                         "ip":""
                        }
                    )
                
        return ns_list
        
