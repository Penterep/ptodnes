import asyncio
import re
from datetime import datetime, timezone
import aiodns
from ptodnes.DNS.record import  DNSRecord
from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptodnes.datasources.datasource import DNSRecordGenerator, DatasourceObject
from ptodnes.metaclasses import Singleton
import pycares

class OdnesDNS(metaclass=Singleton):
    """
    Class to provide DNS queries
    """
    def __init__(self):
        self.__loop = None
        self.__resolver = None
        self.__rev4 = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
        self.__rev6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))', re.IGNORECASE)

    def set_loop(self,loop):
        self.__loop = loop
        self.__resolver = aiodns.DNSResolver(loop=loop)

    def get_loop(self):
        return self.__loop

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
            data = await self.__resolver.query_dns(domain, qtype) #ANY not working on all servers
            preprocessed = []
            if type(data.answer) is not type([]):
                preprocessed.append(data.answer)
            else:
                preprocessed = data.answer
            results = {}
            for response in preprocessed:
                record: DNSRecord
                match response.type:
                    case pycares.QUERY_TYPE_A:
                        record = DNSRecordGenerator(type='A', source="DNS", value=response.data.addr, ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_AAAA:
                        record = DNSRecordGenerator(type='AAAA', source="DNS", value=response.data.addr, ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_NS:
                        record = DNSRecordGenerator(type='NS', source="DNS", value=response.data.nsdname, ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_CNAME:
                        record = DNSRecordGenerator(type='CNAME', source="DNS", value=response.data.cname,
                                                    ttl=response.ttl, verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_MX:
                        record = DNSRecordGenerator(type='MX', source="DNS", value=response.data.exchange, ttl=response.ttl,
                                                    priority=response.data.priority, verified=True,
                                                    record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_PTR:
                        record = DNSRecordGenerator(type='PTR', source="DNS", value=response.data.dname, ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_SOA:
                        record = DNSRecordGenerator(type='SOA', source="DNS", value=response.data.mname, ttl=response.ttl,
                                                    verified=True, rname=response.data.rname, retry=response.data.retry,
                                                    expire=response.data.expire, refresh=response.data.refresh,
                                                    serial=response.data.serial, minimum=response.data.minimum,
                                                    record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_SRV:
                        record = DNSRecordGenerator(type='SRV', source="DNS", value=response.data.target, ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case pycares.QUERY_TYPE_TXT:
                        record = DNSRecordGenerator(type='TXT', source="DNS", value=response.data.data.decode('utf-8'), ttl=response.ttl,
                                                    verified=True, record_last_seen = datetime.now(tz=timezone.utc))
                    case _:
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
            task = asyncio.create_task(self.query_one(domain, info.records, qtype, print_func=print_func))
            tasks.append(task)
        await asyncio.gather(*tasks)

