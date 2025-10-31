import asyncio
import re
from datetime import datetime, timezone
import aiodns
from ptodnes.DNS.record import  DNSRecord
from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptodnes.datasources.datasource import DNSRecordGenerator, DatasourceObject
from ptodnes.metaclasses import Singleton

class OdnesDNS(metaclass=Singleton):
    """
    Class to provide DNS queries
    """
    def __init__(self, loop):
        self.__resolver = aiodns.DNSResolver(loop=loop)
        self.__rev4 = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
        self.__rev6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))', re.IGNORECASE)

    async def reverse(self, ip: str) -> list[str]:
        if self.__rev4.match(ip) or self.__rev6.match(ip):
            try:
                res = await self.__resolver.gethostbyaddr(ip)
                return res.aliases
            except aiodns.error.DNSError:
                return []
        return []

    async def query_one(self, domain: str, domain_data: list[DNSRecord], qtype='ANY', *, print_func=None):
        """
        Query one domain with selected record type, update domain_data with results.
        :param domain: domain to query.
        :param domain_data: domain data to update.
        :param qtype: query type.
        :param print_func: output function.
        """
        try:
            if print_func:
                print_func(f"querying {domain}", clear_to_eol=True, end='\r')
            data = await self.__resolver.query(domain, qtype) #ANY not working on all servers
            preprocessed = []
            if type(data) is not type([]):
                preprocessed.append(data)
            else:
                preprocessed = data
            results = {}
            for response in preprocessed:
                record: DNSRecord
                if response.type in ['A', 'AAAA', 'NS']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.host, ttl=response.ttl,
                                                verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['CNAME']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.cname,
                                                ttl=response.ttl, verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['MX']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.host, ttl=response.ttl,
                                                priority=response.priority, verified=True,
                                                record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['PTR']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.name, ttl=response.ttl,
                                                verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['SOA']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.nsname, ttl=response.ttl,
                                                verified=True, rname=response.hostmaster, retry=response.retry,
                                                expire=response.expires, refresh=response.refresh,
                                                serial=response.serial, minimum=response.minttl,
                                                record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['SRV']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.host, ttl=response.ttl,
                                                verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                elif response.type in ['TXT']:
                    record = DNSRecordGenerator(type=response.type, source="DNS", value=response.text, ttl=response.ttl,
                                                verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                else:
                    continue
                sources = set()
                if DNSRecord('<NONE>',0,'<EMPTY>',False, {''}, None) in domain_data:
                    for empty in domain_data:
                        sources.update(empty.source)
                record.source.update(sources)

                if record not in domain_data:
                    domain_data.append(record)
                else:
                    for i in range(len(domain_data)):
                        if domain_data[i] == record:
                            record.source.update(domain_data[i].source)
                            domain_data[i] = record
        except aiodns.error.DNSError:
            pass

    async def query(self, domain_list: DNSRecordDict, qtype='ANY', *, print_func=None):
        """
        Query provided domain list with selected record type, update its data with results.
        :param domain_list: domain list to query.
        :param qtype: query type.
        """
        tasks = []
        for domain, info in domain_list.items():
            task = asyncio.create_task(self.query_one(domain, info, qtype, print_func=print_func))
            tasks.append(task)
        await asyncio.gather(*tasks)

