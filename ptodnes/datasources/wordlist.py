import asyncio
import aiofiles
import re

from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator
from ptodnes.DNS.odnesdns import OdnesDNS

from ptodnes.DNS.dns_record_dict import DNSRecordDict

import punycode


class Wordlist(Datasource):

    def __init__(self, api_key: str = ''):
        super().__init__()
        wordlists_cfg = self.config.get("wordlists", [])
        self._enabled = self.config.get('enabled', True)
        if type(wordlists_cfg) is type(''):
            self.__wordlists = [wordlists_cfg]
        else:
            self.__wordlists = wordlists_cfg

    async def check_api_key(self):
        pass

    def add_api_key(self, api_key: str = None):
        pass

    async def search(self, domain: str):
        if not self._enabled:
            return []
        if self._wordlists:
            self.__wordlists = self._wordlists
        self.print_info("Started wordlist search")
        loop = asyncio.get_event_loop()
        dns = OdnesDNS(loop)
        datasource_objects = []
        rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
        async for sub in self.read_wordlist():
            subdomain = sub + '.' + domain if sub else domain
            d = ''
            try:
                d = subdomain
                subdomain = punycode.convert(subdomain, True)
            except:
                continue
            if rgx.match(subdomain):
                datasource_object = DatasourceObject(domain=subdomain, DNSData=[
                    DNSRecordGenerator(source=self.__class__.__name__, type='<NONE>', verified=False, value="<EMPTY>",
                                       ttl=None,
                                       record_last_seen=None)])
                datasource_objects.append(datasource_object)
        res = DNSRecordDict()
        res.extend(datasource_objects)

        qtypes: list
        if self._qtype:
            qtypes = self._qtype
        else:
            qtypes = ['A', 'AAAA', 'CNAME']

        qtasks = []
        for qtype in qtypes:
            task = loop.create_task(dns.query(res, qtype=qtype, print_func=self.print_info))
            qtasks.append(task)
        await asyncio.gather(*qtasks)
        if self._verbose:
            print()
        res.filter_untrusted()

        return res.as_list()

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        self.print_warning("IP address lookup is not supported.")
        return []

    async def read_wordlist(self):
        for wordlist in self.__wordlists:
            self.print_info(f"Reading wordlist {wordlist}")
            async with aiofiles.open(wordlist, 'r') as wordlist_file:
                async for line in wordlist_file:
                    if line.endswith('\n'):
                        line = line[:-1]
                    yield line