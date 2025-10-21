import asyncio
import aiofiles
import re

from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator, date_from_utc
from ptodnes.DNS.odnesdns import OdnesDNS

from ptodnes.DNS.dns_record_dict import DNSRecordDict


class Wordlist(Datasource):

    def __init__(self, api_key: str = '', *, wordlists: list = None):
        super().__init__()
        if wordlists:
            self.__wordlists = wordlists
            return
        if self._wordlists:
            self.__wordlists = self._wordlists
            return
        wordlists_cfg = self.config.get("wordlists", [])
        if type(wordlists_cfg) is type(''):
            self.__wordlists = [wordlists_cfg]
        else:
            self.__wordlists = wordlists_cfg



    async def search(self, domain: str):
        self.print_info("Started wordlist search")
        loop = asyncio.get_event_loop()
        dns = OdnesDNS(loop)
        datasource_objects = []
        rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
        async for sub in self.read_wordlist():
            subdomain = sub + '.' + domain
            if rgx.match(subdomain):
                datasource_object = DatasourceObject(domain=subdomain, DNSData=[
                    DNSRecordGenerator(source=self.__class__.__name__, type='<NONE>', verified=False, value="<EMPTY>",
                                       ttl=None,
                                       record_last_seen=None)])
                datasource_objects.append(datasource_object)
        res = DNSRecordDict()
        res.extend(datasource_objects)

        qtypes = ['A', 'AAAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', ]

        qtasks = []
        for qtype in qtypes:
            task = loop.create_task(dns.query(res, qtype=qtype))
            qtasks.append(task)
        await asyncio.gather(*qtasks)

        res.filter_untrusted()

        return res.as_list()

    async def read_wordlist(self):
        for wordlist in self.__wordlists:
            self.print_info(f"Reading wordlist {wordlist}")
            async with aiofiles.open(wordlist, 'r') as wordlist_file:
                async for line in wordlist_file:
                    if line.endswith('\n'):
                        line = line[:-1]
                    yield line