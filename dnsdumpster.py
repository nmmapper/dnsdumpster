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

import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
import dns.resolver
import requests

import urllib.parse as urlparse
import urllib.parse as urllib
import requests.packages.urllib3
from dns import resolver
from dns.resolver import NXDOMAIN
try:
    import simplejson as json
except ImportError:
    import json 
from geolocator.geo import (query_A_records, geo_locate_ip, locate_asn_info
)
from geolocator.mxfinder import (query_host_mx, query_host_ns, query_host_txt
)
from geolocator.utils import get_server_type
import searchparser
import searchutils

def subdomain_sorting_key(hostname):
    """Sorting key for subdomains

    This sorting key orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:

    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]

    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

class EnumratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.headers = {
              'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.8',
              'Accept-Encoding': 'gzip',
          }
        self.print_banner()

    def print_(self, text):
        return

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        print("Searching using engine {0}".format(self.engine_name))
        return

    def send_req(self, query, page_no=1):
        
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    # override
    def extract_domains(self, resp):
        """ chlid class should override this function """
        return

    # override
    def check_response_errors(self, resp):
        """ chlid class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumrators require sleeping to avoid bot detections like Google enumerator"""
        return

    def generate_query(self):
        """ chlid class should override this function """
        return

    def get_page(self, num):
        """ chlid class that user different pagnation counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            if(query):
                count = query.count(self.domain)  # finding the number of subdomains found so far
            else:
                count = 0
                
            # if they we reached the maximum number of subdomains in search query
            # then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):  # maximum pages for Google to avoid getting blocked
                return self.subdomains
            resp = self.send_req(query, page_no)

            # check if there is any error occured
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            # if the previous page hyperlinks was the similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

        # make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains

class EnumratorBaseThreaded(multiprocessing.Process, EnumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        EnumratorBase.__init__(self, base_url, engine_name, domain, subdomains)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)

class GoogleEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0}: {1}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str and 'Our systems have detected unusual traffic' in resp):
            print("[!] Error: Google probably now is blocking our requests" )
            print("[~] Finished now the Google Enumeration ...")
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

class YahooEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub("<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    print("%s%s: %s%s".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query


class AskEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0}: {0}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)

        return query


class BingEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        EnumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2

            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0} {1}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query


class BaiduEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        EnumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        links = list()
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        print("{0} : {1}" % (self.engine_name, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query


class NetcraftEnum(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        self.lock = threading.Lock()
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            print(e)
            resp = None
        return resp

    def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub('host=.*?%s' % self.domain, 'host=%s' % self.domain, link[0])
        url = 'http://searchdns.netcraft.com' + link
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # hashlib.sha1 requires utf-8 encoded str
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        if(resp):
            cookies = self.get_cookies(resp.headers)
            url = self.base_url.format(domain=self.domain)
            while True:
                resp = self.get_response(self.req(url, cookies))
                self.extract_domains(resp)
                if(isinstance(resp, int)):
                    break
                if 'Next page' not in resp:
                    return self.subdomains
                    break
                url = self.get_next(resp)

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0} : {1}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

class DNSdumpster(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        
        self.live_subdomains = []
        self.engine_name = "DNSdumpster"
        self.threads = 70
                
        self.domain = domain.replace(' ', '%20')
        
        self.results = ""
        self.totalresults = ""
        self.server = 'dnsdumpster.com'
        self.base_url = self.server

        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.q = q
        super(DNSdumpster, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q)
        
        self.targetdomain = domain
        
        return

    def do_search(self):
        try:
            agent = searchutils.Core.get_user_agent()
            headers = {'User-Agent': agent}
            session = requests.session()
            # create a session to properly verify
            url = f'https://{self.server}'
            request = session.get(url, headers=headers)
            cookies = str(request.cookies)
            # extract csrftoken from cookies
            csrftoken = ''
            for ch in cookies.split("=")[1]:
                if ch == ' ':
                    break
                csrftoken += ch
            data = {
                'Cookie': f'csfrtoken={csrftoken}', 'csrfmiddlewaretoken': csrftoken, 'targetip': self.targetdomain}
            headers['Referer'] = url
            post_req = session.post(url, headers=headers, data=data)
            self.results = post_req.text
            
        except Exception as e:
            print(f'An exception occured: {e}')
        self.totalresults += self.results

    def extract_domains(self):
        rawres = searchparser.Parser(self.totalresults, self.targetdomain)  
        self.live_subdomains =  rawres.hostnames()
        for sub in self.live_subdomains:
            self.subdomains.append(sub)
        
    def enumerate(self):
        self.do_search()  # Only need to do it once.
        self.extract_domains() 
        return self.subdomains 
        
    def get_people(self):
        return []
    
    def get_ipaddresses(self):
        return [] 

class Virustotal(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://www.virustotal.com/gui/domain/{domain}/details"
        self.apiurl = 'https://www.virustotal.com/vtapi/v2/domain/report'
        self.API_KEY="efdf4846c4464ed7d07d432774add91f848931f0214c54660177a20cb1003f84"
        self.params =  {'apikey':self.API_KEY,'domain':domain}
        self.engine_name = "Virustotal"
        self.lock = threading.Lock()
        self.q = q
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        return

    # the main send_req need to be rewritten
    def send_req(self, url):
        try:
            resp = self.session.get(self.apiurl, headers=self.headers, params=self.params)
        except Exception as e:
            print(e)
            resp = None
        else:
            return resp.json()

    # once the send_req is rewritten we don't need to call this function, the stock one should be ok
    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.send_req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = resp.get('subdomains')
            for subdomain in subdomains:
                self.subdomains.append(subdomain.strip())
        except Exception as e:
            print(e)
            pass

class ThreatCrowd(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.domain = domain 
        self.queryurl = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}'.format(self.domain)
        self.engine_name = "ThreatCrowd"
        self.lock = threading.Lock()
        self.q = q
        super(ThreatCrowd, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        return

    def req(self, url):
        try:
            resp = self.session.get(self.queryurl, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            print("ERROR ", e)
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0} : {1}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

class CrtSearch(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://crt.sh/?q={domain}'
        self.domain = domain
        self.queryurl = 'https://crt.sh/?q={0}&output=json'.format(self.domain)
        self.engine_name = "SSL Certificates"
        self.lock = threading.Lock()
        self.q = q
        super(CrtSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        return

    def req(self, url):
        try:
            resp = self.session.get(self.queryurl, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<TD>(.*?)</TD>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                
                #print("SUBDOMAINS ", subdomain)
                if(self.domain in subdomain and "</A>" not in subdomain):
                    if not subdomain.endswith(self.domain) or '*' in subdomain:
                        continue

                    if '@' in subdomain:
                        subdomain = subdomain[subdomain.find('@')+1:]

                    if subdomain not in self.subdomains and subdomain != self.domain:
                        print("{0} : {1}".format(self.engine_name, subdomain))
                        self.subdomains.append(subdomain.strip())
                        
        except Exception as e:
            pass

class PassiveDNS(EnumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://api.sublist3r.com/search.php?domain={domain}'
        self.engine_name = "PassiveDNS"
        self.lock = threading.Lock()
        self.q = q
        super(PassiveDNS, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if not resp:
            return self.subdomains

        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = json.loads(resp)
            for subdomain in subdomains:
                if subdomain not in self.subdomains and subdomain != self.domain:
                    print("{0} : {1}".format(self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

def clean_domains(domain):
    validator = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    domain_list = []
    
    for d in domain:
        match = validator.match(d)
        
        if(match):
            domain_list.append(match.string)
    return domain_list
    
def main(domain):
    bruteforce_list = set()
    search_list = set()

    subdomains_queue = multiprocessing.Manager().list()
    enable_bruteforce = True

    # Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        raise ValueError("Invalid domain entered")

    parsed_domain = urlparse.urlparse(domain)
    print("Starting dns dump against {0}".format(domain))

    supported_engines = {
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    engines = [
        #BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
        DNSdumpster,
        NetcraftEnum,  Virustotal, ThreatCrowd, CrtSearch
    ]

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue) for enum in engines]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if subdomains:
        subdomains = clean_domains(sorted(subdomains, key=subdomain_sorting_key))
    
    # Dict data
    subdomain_list = []
    dnsrecords = dict()
    
    for sub in subdomains:
        a_record = query_A_records(sub)
        if(a_record):
            A = a_record[0]
            d = {
                "subdomain":sub,
                "subdomain_ip":A.address,
                "asn":locate_asn_info(A.address),
                "server":get_server_type(sub),
            }
            subdomain_list.append(d)
        else:
            d = {
                "subdomain":sub,
                "subdomain_ip":"",
                "server":get_server_type(sub),
            }
            subdomain_list.append(d)
    
    dnsrecords["host"]=domain
    dnsrecords["server"]=get_server_type(domain)
    dnsrecords["mx"]=query_host_mx(domain)
    dnsrecords["ns"]=query_host_ns(domain)
    dnsrecords["asn"]=locate_asn_info(domain)
    dnsrecords["subdomains"]=subdomain_list
    dnsrecords["txt"]=query_host_txt(domain)
    return dnsrecords

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="Module to dump all dns records of a given domain")
    parser.add_argument('-d', '--d', help='Help', required=True)
    args = parser.parse_args()
    
    subs = main(args.d)
    print(json.dumps(subs, indent=4, sort_keys=True))
